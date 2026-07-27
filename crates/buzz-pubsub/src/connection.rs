//! One Redis/Valkey connection boundary for local development and Snowman AWS.
//!
//! Snowman production uses ElastiCache IAM tokens instead of a password-bearing
//! URL. redis-rs consumes a streaming credential provider, reauthenticates live
//! connections, reconnects, and restores RESP3 subscriptions. This wrapper
//! keeps existing local/test deadpool pools working while making dynamic
//! identity the production path.

use std::pin::Pin;
use std::sync::Arc;

use futures_util::Stream;
use redis::aio::{ConnectionLike, ConnectionManager, ConnectionManagerConfig};
use redis::{IntoConnectionInfo, ProtocolVersion, PushInfo, RedisFuture, RedisResult};
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Clone)]
struct SharedCredentialsProvider(Arc<dyn redis::auth::StreamingCredentialsProvider>);

impl redis::auth::StreamingCredentialsProvider for SharedCredentialsProvider {
    fn subscribe(
        &self,
    ) -> Pin<Box<dyn Stream<Item = RedisResult<redis::auth::BasicAuth>> + Send + 'static>> {
        self.0.subscribe()
    }
}

/// Reusable connection factory. It never exposes credentials or puts them in a URL.
#[derive(Clone)]
pub struct RedisConnector {
    client: redis::Client,
    credentials: Option<SharedCredentialsProvider>,
}

impl std::fmt::Debug for RedisConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisConnector")
            .field("dynamic_credentials", &self.credentials.is_some())
            .finish_non_exhaustive()
    }
}

impl RedisConnector {
    /// Build a connector from a URL after forcing RESP3, which is required for
    /// reconnect-safe pub/sub push delivery.
    pub fn from_url(redis_url: &str) -> RedisResult<Self> {
        let info = redis_url.into_connection_info()?;
        let redis = info
            .redis_settings()
            .clone()
            .set_protocol(ProtocolVersion::RESP3);
        let client = redis::Client::open(info.set_redis_settings(redis))?;
        Ok(Self {
            client,
            credentials: None,
        })
    }

    /// Attach a streaming provider used for initial AUTH, refresh, reconnect,
    /// and every independently managed subscriber connection.
    pub fn with_credentials<P>(mut self, provider: P) -> Self
    where
        P: redis::auth::StreamingCredentialsProvider + 'static,
    {
        self.credentials = Some(SharedCredentialsProvider(Arc::new(provider)));
        self
    }

    fn manager_config(
        &self,
        push_sender: Option<mpsc::UnboundedSender<PushInfo>>,
    ) -> ConnectionManagerConfig {
        let mut config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(std::time::Duration::from_secs(3)))
            .set_response_timeout(Some(std::time::Duration::from_secs(3)))
            .set_concurrency_limit(1024);
        if let Some(provider) = self.credentials.clone() {
            config = config.set_credentials_provider(provider);
        }
        if let Some(sender) = push_sender {
            config = config
                .set_push_sender(sender)
                .set_automatic_resubscription();
        }
        config
    }

    async fn connect(
        &self,
        push_sender: Option<mpsc::UnboundedSender<PushInfo>>,
    ) -> RedisResult<ConnectionManager> {
        self.client
            .get_connection_manager_with_config(self.manager_config(push_sender))
            .await
    }

    /// Create a dedicated reconnecting subscriber connection and push receiver.
    pub async fn subscriber(
        &self,
    ) -> RedisResult<(ConnectionManager, mpsc::UnboundedReceiver<PushInfo>)> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let connection = self.connect(Some(sender)).await?;
        Ok((connection, receiver))
    }
}

/// Errors acquiring a command connection.
#[derive(Debug, Error)]
pub enum RedisPoolError {
    /// A legacy local/test deadpool checkout failed.
    #[error("Redis pool checkout failed: {0}")]
    Deadpool(#[from] deadpool_redis::PoolError),
}

/// A command connection for either compatibility or IAM-managed operation.
pub enum RedisConnection {
    /// Local/test deadpool connection.
    Deadpool(deadpool_redis::Connection),
    /// Reconnecting connection with streaming credentials.
    Managed(ConnectionManager),
}

impl ConnectionLike for RedisConnection {
    fn req_packed_command<'a>(
        &'a mut self,
        command: &'a redis::Cmd,
    ) -> RedisFuture<'a, redis::Value> {
        match self {
            Self::Deadpool(connection) => connection.req_packed_command(command),
            Self::Managed(connection) => connection.req_packed_command(command),
        }
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        pipeline: &'a redis::Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<redis::Value>> {
        match self {
            Self::Deadpool(connection) => connection.req_packed_commands(pipeline, offset, count),
            Self::Managed(connection) => connection.req_packed_commands(pipeline, offset, count),
        }
    }

    fn get_db(&self) -> i64 {
        match self {
            Self::Deadpool(connection) => connection.get_db(),
            Self::Managed(connection) => connection.get_db(),
        }
    }
}

/// Metrics-compatible connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedisPoolStatus {
    /// Immediately available logical command handles.
    pub available: usize,
    /// Current physical connection count (one multiplexed connection in IAM mode).
    pub size: usize,
    /// Configured command-capacity compatibility value.
    pub max_size: usize,
    /// Callers waiting for a legacy pool checkout.
    pub waiting: usize,
}

#[derive(Clone)]
enum RedisPoolInner {
    Deadpool(deadpool_redis::Pool),
    Managed(ConnectionManager),
}

/// Redis command and subscriber access with one authentication policy.
#[derive(Clone)]
pub struct RedisPool {
    inner: RedisPoolInner,
    connector: RedisConnector,
    configured_capacity: usize,
}

/// Converts either the governed pool or a legacy local/test pool at an explicit URL.
pub trait IntoRedisPool {
    /// Perform the conversion without guessing an endpoint.
    fn into_redis_pool(self, redis_url: &str) -> RedisResult<RedisPool>;
}

impl IntoRedisPool for RedisPool {
    fn into_redis_pool(self, _redis_url: &str) -> RedisResult<RedisPool> {
        Ok(self)
    }
}

impl IntoRedisPool for deadpool_redis::Pool {
    fn into_redis_pool(self, redis_url: &str) -> RedisResult<RedisPool> {
        RedisPool::from_deadpool(redis_url, self)
    }
}

impl RedisPool {
    /// Compatibility constructor for local/test password or unauthenticated Redis.
    pub fn from_deadpool(redis_url: &str, pool: deadpool_redis::Pool) -> RedisResult<Self> {
        let configured_capacity = pool.status().max_size;
        Ok(Self {
            inner: RedisPoolInner::Deadpool(pool),
            connector: RedisConnector::from_url(redis_url)?,
            configured_capacity,
        })
    }

    /// Production constructor. The first dynamically authenticated connection
    /// must succeed before startup can continue.
    pub async fn managed<P>(
        redis_url: &str,
        configured_capacity: usize,
        provider: P,
    ) -> RedisResult<Self>
    where
        P: redis::auth::StreamingCredentialsProvider + 'static,
    {
        let connector = RedisConnector::from_url(redis_url)?.with_credentials(provider);
        let manager = connector.connect(None).await?;
        Ok(Self {
            inner: RedisPoolInner::Managed(manager),
            connector,
            configured_capacity,
        })
    }

    /// Acquire an independently usable command handle.
    pub async fn get(&self) -> Result<RedisConnection, RedisPoolError> {
        match &self.inner {
            RedisPoolInner::Deadpool(pool) => Ok(RedisConnection::Deadpool(pool.get().await?)),
            RedisPoolInner::Managed(connection) => Ok(RedisConnection::Managed(connection.clone())),
        }
    }

    /// Create a dedicated reconnecting subscriber governed by the same credentials.
    pub async fn subscriber(
        &self,
    ) -> RedisResult<(ConnectionManager, mpsc::UnboundedReceiver<PushInfo>)> {
        self.connector.subscriber().await
    }

    /// Return compatible operational metrics without exposing endpoint details.
    pub fn status(&self) -> RedisPoolStatus {
        match &self.inner {
            RedisPoolInner::Deadpool(pool) => {
                let status = pool.status();
                RedisPoolStatus {
                    available: status.available,
                    size: status.size,
                    max_size: status.max_size,
                    waiting: status.waiting,
                }
            }
            RedisPoolInner::Managed(_) => RedisPoolStatus {
                available: 1,
                size: 1,
                max_size: self.configured_capacity,
                waiting: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_debug_redacts_endpoint_details() {
        let connector = RedisConnector::from_url("redis://secret-host.internal:6379").unwrap();
        let debug = format!("{connector:?}");
        assert!(!debug.contains("secret-host"));
        assert_eq!(debug, "RedisConnector { dynamic_credentials: false, .. }");
    }
}
