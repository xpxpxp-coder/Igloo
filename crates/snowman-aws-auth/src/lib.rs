#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Short-lived AWS service credentials for Snowman-controlled runtimes.

use std::pin::Pin;
use std::time::{Duration, SystemTime};

use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_sigv4::http_request::{
    sign, SignableBody, SignableRequest, SignatureLocation, SigningParams, SigningSettings,
};
use aws_sigv4::sign::v4;
use futures_util::{stream, Stream};
use redis::auth::{BasicAuth, StreamingCredentialsProvider};
use redis::{ErrorKind, RedisError, RedisResult};

const TOKEN_VALIDITY: Duration = Duration::from_secs(15 * 60);
const TOKEN_REFRESH: Duration = Duration::from_secs(10 * 60);

/// Short-lived AWS IAM authentication configuration for managed Valkey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElastiCacheIamConfig {
    /// ElastiCache IAM user name sent in Redis AUTH.
    pub user_id: String,
    /// Replication-group identifier used as the SigV4 token authority.
    pub cache_name: String,
    /// AWS region used for the ElastiCache SigV4 scope.
    pub region: String,
}

/// Generates SigV4 AUTH tokens from the workload task role and refreshes them
/// before the ElastiCache 15-minute connection-token validity expires.
#[derive(Clone)]
pub struct ElastiCacheIamCredentials {
    config: ElastiCacheIamConfig,
    credentials: SharedCredentialsProvider,
}

impl ElastiCacheIamCredentials {
    /// Resolve the standard AWS workload credential chain once. The SDK's
    /// shared provider refreshes underlying role credentials as needed.
    pub async fn load(config: ElastiCacheIamConfig) -> anyhow::Result<Self> {
        let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let credentials = sdk.credentials_provider().ok_or_else(|| {
            anyhow::anyhow!("AWS task-role credential provider is unavailable for Valkey IAM")
        })?;
        Ok(Self {
            config,
            credentials,
        })
    }

    async fn issue_at(&self, now: SystemTime) -> Result<BasicAuth, String> {
        let credentials = self
            .credentials
            .provide_credentials()
            .await
            .map_err(|error| format!("AWS task-role credentials unavailable: {error}"))?;
        let identity: aws_smithy_runtime_api::client::identity::Identity = credentials.into();

        let mut token_url = url::Url::parse(&format!("http://{}/", self.config.cache_name))
            .map_err(|error| format!("invalid cache name: {error}"))?;
        token_url
            .query_pairs_mut()
            .append_pair("Action", "connect")
            .append_pair("User", &self.config.user_id);

        let mut settings = SigningSettings::default();
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(TOKEN_VALIDITY);
        let params: SigningParams<'_> = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.config.region)
            .name("elasticache")
            .time(now)
            .settings(settings)
            .build()
            .map_err(|error| format!("could not build ElastiCache signing scope: {error}"))?
            .into();
        let request = SignableRequest::new(
            "GET",
            token_url.as_str(),
            std::iter::empty::<(&str, &str)>(),
            SignableBody::empty(),
        )
        .map_err(|error| format!("could not create ElastiCache signable request: {error}"))?;
        let signed = sign(request, &params)
            .map_err(|error| format!("could not sign ElastiCache IAM token: {error}"))?;
        let signed_params: Vec<(String, String)> = signed
            .output()
            .params()
            .iter()
            .map(|(name, value)| ((*name).to_string(), value.to_string()))
            .collect();
        for (name, value) in signed_params {
            token_url.query_pairs_mut().append_pair(&name, &value);
        }

        let token = token_url
            .as_str()
            .strip_prefix("http://")
            .ok_or_else(|| "ElastiCache IAM token used an unexpected scheme".to_string())?
            .to_string();
        Ok(BasicAuth::new(self.config.user_id.clone(), token))
    }

    fn redis_error(detail: String) -> RedisError {
        RedisError::from((
            ErrorKind::AuthenticationFailed,
            "Snowman Valkey IAM credential generation failed",
            detail,
        ))
    }
}

impl StreamingCredentialsProvider for ElastiCacheIamCredentials {
    fn subscribe(&self) -> Pin<Box<dyn Stream<Item = RedisResult<BasicAuth>> + Send + 'static>> {
        let provider = self.clone();
        Box::pin(stream::unfold(
            (provider, true),
            |(provider, first)| async move {
                if !first {
                    tokio::time::sleep(TOKEN_REFRESH).await;
                }
                let item = provider
                    .issue_at(SystemTime::now())
                    .await
                    .map_err(Self::redis_error);
                Some((item, (provider, false)))
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_credential_types::Credentials;

    #[tokio::test]
    async fn token_is_scoped_encoded_and_never_contains_secret() {
        let credentials = Credentials::new(
            "AKIDEXAMPLE",
            "super-secret-signing-material",
            Some("session-token".to_string()),
            None,
            "snowman-test",
        );
        let provider = ElastiCacheIamCredentials {
            config: ElastiCacheIamConfig {
                user_id: "snowman-relay".to_string(),
                cache_name: "snowman-staging-valkey".to_string(),
                region: "us-east-1".to_string(),
            },
            credentials: SharedCredentialsProvider::new(credentials),
        };
        let auth = provider
            .issue_at(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000))
            .await
            .unwrap();

        assert_eq!(auth.username(), "snowman-relay");
        assert!(auth
            .password()
            .starts_with("snowman-staging-valkey/?Action=connect&User=snowman-relay"));
        assert!(auth.password().contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(auth.password().contains("X-Amz-Expires=900"));
        assert!(auth.password().contains("X-Amz-Signature="));
        assert!(!auth.password().contains("super-secret-signing-material"));
    }
}
