//! Private NIP-98 authenticated coordinator service.

use std::{collections::BTreeMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration as ChronoDuration, Utc};
use nostr::TagKind;
use serde::Serialize;
use sha2::{Digest, Sha256};
use snowman_agent_contract::JobSnapshot;
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;
use uuid::Uuid;

use crate::{
    AwsEcsControl, Coordinator, CoordinatorConfig, CoordinatorError, KmsTokenDeriver,
    RuntimeProfile, VerifiedLaunchRequest, COORDINATOR_SCHEMA,
};

const MAX_REQUEST_BYTES: usize = 786_432;
const AUTH_EVIDENCE_SECONDS: i64 = 120;

type ProductionCoordinator = Coordinator<KmsTokenDeriver, AwsEcsControl>;

/// Exact service configuration loaded from a dedicated secret and static ECS policy.
pub struct Config {
    bind_addr: SocketAddr,
    database_url: String,
    database_role: String,
    max_connections: u32,
    public_origin: Url,
    coordinator: CoordinatorConfig,
    token_hmac_key_arn: String,
}

/// Non-sensitive startup failure classes.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required static or secret-backed setting is missing or invalid.
    #[error("Snowman agent coordinator configuration is invalid: {0}")]
    Invalid(&'static str),
    /// The dedicated database identity could not be initialized.
    #[error("Snowman agent coordinator database initialization failed")]
    Database,
    /// AWS clients could not be bound to the exact coordinator policy.
    #[error("Snowman agent coordinator AWS initialization failed")]
    Aws,
}

impl Config {
    /// Load and fail closed on every production service boundary.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = env_value("SNOWMAN_AGENT_COORDINATOR_BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()
            .map_err(|_| ConfigError::Invalid("bind address is invalid"))?;
        let database_url = required("SNOWMAN_AGENT_COORDINATOR_DATABASE_URL")?;
        let database_role = required("SNOWMAN_AGENT_COORDINATOR_DATABASE_ROLE")?;
        buzz_db::runtime_security::validate_role_name(&database_role)
            .map_err(|_| ConfigError::Invalid("database role is invalid"))?;
        let max_connections = env_value("SNOWMAN_AGENT_COORDINATOR_MAX_CONNECTIONS")
            .unwrap_or_else(|| "8".into())
            .parse::<u32>()
            .map_err(|_| ConfigError::Invalid("connection limit is invalid"))?;
        let public_origin =
            parse_private_origin(&required("SNOWMAN_AGENT_COORDINATOR_PUBLIC_ORIGIN")?)?;
        let cluster_arn = required("SNOWMAN_AGENT_COORDINATOR_ECS_CLUSTER_ARN")?;
        let private_subnet_ids: Vec<String> = serde_json::from_str(&required(
            "SNOWMAN_AGENT_COORDINATOR_PRIVATE_SUBNET_IDS_JSON",
        )?)
        .map_err(|_| ConfigError::Invalid("private subnet JSON is invalid"))?;
        let executor_security_group_id =
            required("SNOWMAN_AGENT_COORDINATOR_EXECUTOR_SECURITY_GROUP_ID")?;
        let profiles: Vec<RuntimeProfile> = serde_json::from_str(&required(
            "SNOWMAN_AGENT_COORDINATOR_RUNTIME_PROFILES_JSON",
        )?)
        .map_err(|_| ConfigError::Invalid("runtime profile JSON is invalid"))?;
        let mut runtime_profiles = BTreeMap::new();
        for profile in profiles {
            let key = profile.runtime_id.clone();
            if runtime_profiles.insert(key, profile).is_some() {
                return Err(ConfigError::Invalid("runtime profile IDs must be unique"));
            }
        }
        let coordinator = CoordinatorConfig {
            cluster_arn,
            private_subnet_ids,
            executor_security_group_id,
            runtime_profiles,
        };
        coordinator
            .validate()
            .map_err(|_| ConfigError::Invalid("coordinator placement policy is invalid"))?;
        let token_hmac_key_arn = required("SNOWMAN_AGENT_COORDINATOR_TOKEN_HMAC_KEY_ARN")?;
        if max_connections == 0
            || max_connections > 16
            || !valid_database_url(&database_url)
            || env_value("SNOWMAN_AGENT_COORDINATOR_NETWORK_POLICY").as_deref()
                != Some("private-snowman-only")
        {
            return Err(ConfigError::Invalid(
                "database or private-network control is invalid",
            ));
        }
        Ok(Self {
            bind_addr,
            database_url,
            database_role,
            max_connections,
            public_origin,
            coordinator,
            token_hmac_key_arn,
        })
    }
}

/// Shared private-service state.
#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    coordinator: Arc<ProductionCoordinator>,
    bind_addr: SocketAddr,
    public_origin: Url,
}

impl AppState {
    /// Initialize the dedicated database identity and exact AWS clients.
    pub async fn new(config: Config) -> Result<Self, ConfigError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&config.database_url)
            .await
            .map_err(|_| ConfigError::Database)?;
        buzz_db::runtime_security::verify_agent_coordinator_role(&pool, &config.database_role)
            .await
            .map_err(|_| ConfigError::Database)?;
        let aws = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let token_deriver =
            KmsTokenDeriver::new(aws_sdk_kms::Client::new(&aws), config.token_hmac_key_arn)
                .map_err(|_| ConfigError::Aws)?;
        let coordinator = Coordinator::new(
            pool.clone(),
            config.coordinator,
            token_deriver,
            AwsEcsControl::new(aws_sdk_ecs::Client::new(&aws)),
        )
        .map_err(|_| ConfigError::Aws)?;
        Ok(Self {
            pool,
            coordinator: Arc::new(coordinator),
            bind_addr: config.bind_addr,
            public_origin: config.public_origin,
        })
    }

    /// Address on which the private task listens behind internal TLS.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Continuously reconcile crash-interrupted and deadline-expired launches.
    /// Database claims make this safe when production later runs two tasks.
    pub async fn run_reconciler(self) {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match self.coordinator.reconcile_due_launches(25).await {
                Ok(count) if count > 0 => {
                    tracing::info!(reconciled_launches = count, "agent launches reconciled");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(%error, "agent launch reconciliation failed");
                }
            }
            match self.coordinator.reconcile_running_tasks(25).await {
                Ok(count) if count > 0 => {
                    tracing::info!(reconciled_tasks = count, "agent tasks reconciled");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(%error, "agent task reconciliation failed");
                }
            }
        }
    }
}

/// Build the private launch-only router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/_liveness", get(liveness))
        .route("/_readiness", get(readiness))
        .route("/v1/tenants/{tenant_id}/launches", post(post_launch))
        .route(
            "/v1/tenants/{tenant_id}/launches/{launch_id}/bootstrap",
            post(post_bootstrap),
        )
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .with_state(state)
}

async fn liveness() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn readiness(State(state): State<AppState>) -> StatusCode {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(1) => StatusCode::NO_CONTENT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[derive(Serialize)]
struct LaunchResponse {
    schema_version: String,
    launch_id: Uuid,
    job_id: Uuid,
    ecs_task_arn: String,
    launched: bool,
}

async fn post_launch(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<LaunchResponse>, ApiError> {
    if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
        return Err(ApiError::Invalid);
    }
    let expected_url = state
        .public_origin
        .join(&format!("v1/tenants/{tenant_id}/launches"))
        .map_err(|_| ApiError::Internal)?;
    let auth = verify_auth(&headers, expected_url.as_str(), &body)?;
    let snapshot: JobSnapshot = serde_json::from_slice(&body).map_err(|_| ApiError::Invalid)?;
    if snapshot.tenant_id != tenant_id.to_string() || snapshot.workspace_id != tenant_id {
        return Err(ApiError::Invalid);
    }
    let now = Utc::now();
    let receipt = state
        .coordinator
        .submit(VerifiedLaunchRequest {
            snapshot,
            request_sha256: Sha256::digest(&body).into(),
            requester_pubkey: auth.pubkey,
            auth_event_id: auth.event_id,
            auth_observed_at: now,
            auth_expires_at: now + ChronoDuration::seconds(AUTH_EVIDENCE_SECONDS),
        })
        .await
        .map_err(ApiError::from)?;
    Ok(Json(LaunchResponse {
        schema_version: COORDINATOR_SCHEMA.into(),
        launch_id: receipt.launch_id,
        job_id: receipt.job_id,
        ecs_task_arn: receipt.ecs_task_arn,
        launched: receipt.launched,
    }))
}

async fn post_bootstrap(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((tenant_id, launch_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    if !body.is_empty()
        || headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key("forwarded")
        || headers.contains_key("x-forwarded-for")
        || headers.contains_key("x-real-ip")
    {
        return Err(ApiError::Invalid);
    }
    let credentials = state
        .coordinator
        .redeem_bootstrap(tenant_id, launch_id, peer.ip())
        .await
        .map_err(ApiError::from)?;
    let mut response = Json(credentials).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store, private, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    Ok(response)
}

struct VerifiedAuth {
    pubkey: [u8; 32],
    event_id: [u8; 32],
}

fn verify_auth(headers: &HeaderMap, url: &str, body: &[u8]) -> Result<VerifiedAuth, ApiError> {
    let encoded = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Nostr "))
        .ok_or(ApiError::Unauthorized)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| ApiError::Unauthorized)?;
    if bytes.len() > 32 * 1024 {
        return Err(ApiError::Unauthorized);
    }
    let event_json = String::from_utf8(bytes).map_err(|_| ApiError::Unauthorized)?;
    let event: nostr::Event =
        serde_json::from_str(&event_json).map_err(|_| ApiError::Unauthorized)?;
    if !event.tags.iter().any(|tag| tag.kind() == TagKind::Payload) {
        return Err(ApiError::Unauthorized);
    }
    let pubkey = buzz_auth::verify_nip98_event(&event_json, url, "POST", Some(body))
        .map_err(|_| ApiError::Unauthorized)?;
    Ok(VerifiedAuth {
        pubkey: pubkey.to_bytes(),
        event_id: event.id.to_bytes(),
    })
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Invalid,
    Conflict,
    Busy,
    Unavailable,
    Internal,
}

impl From<CoordinatorError> for ApiError {
    fn from(value: CoordinatorError) -> Self {
        match value {
            CoordinatorError::InvalidConfiguration | CoordinatorError::Database => Self::Internal,
            CoordinatorError::InvalidRequest => Self::Unauthorized,
            CoordinatorError::AuthenticationConflict | CoordinatorError::Conflict => Self::Conflict,
            CoordinatorError::Busy => Self::Busy,
            CoordinatorError::TokenDerivation | CoordinatorError::Issue | CoordinatorError::Ecs => {
                Self::Unavailable
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::Busy => (StatusCode::CONFLICT, "busy"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (
            status,
            Json(serde_json::json!({
                "schema_version": "snowman.agent.coordinator.error.v1",
                "error": code,
            })),
        )
            .into_response()
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env_value(name).ok_or(ConfigError::Invalid(name))
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn parse_private_origin(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("public origin is invalid"))?;
    let host = url.host_str().unwrap_or("");
    if value != value.to_ascii_lowercase()
        || url.scheme() != "https"
        || !(host == "internal.snowmanai.org" || host.ends_with(".internal.snowmanai.org"))
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ConfigError::Invalid(
            "public origin must be an exact private Snowman HTTPS origin",
        ));
    }
    Ok(url)
}

fn valid_database_url(value: &str) -> bool {
    if sqlx::postgres::PgConnectOptions::from_str(value).is_err() {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let ssl_modes = url
        .query_pairs()
        .filter_map(|(name, value)| (name == "sslmode").then_some(value.into_owned()))
        .collect::<Vec<_>>();
    url.scheme() == "postgresql"
        && url.host_str().is_some_and(|host| {
            host.ends_with(".rds.amazonaws.com") || host.ends_with(".rds.amazonaws.com.cn")
        })
        && url.port_or_known_default() == Some(5432)
        && !url.username().is_empty()
        && url.password().is_some_and(|value| value.len() >= 32)
        && ssl_modes.len() == 1
        && ssl_modes[0] == "verify-full"
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag};

    fn auth_header(keys: &Keys, url: &str, body: &[u8]) -> HeaderMap {
        let digest = hex::encode(Sha256::digest(body));
        let event = EventBuilder::new(Kind::Custom(27235), "")
            .tags([
                Tag::parse(["u", url]).unwrap(),
                Tag::parse(["method", "POST"]).unwrap(),
                Tag::parse(["payload", &digest]).unwrap(),
            ])
            .sign_with_keys(keys)
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Nostr {}", STANDARD.encode(event.as_json()))).unwrap(),
        );
        headers
    }

    #[test]
    fn coordinator_origin_is_private_snowman_only() {
        assert!(
            parse_private_origin("https://coordinator.staging.internal.snowmanai.org/").is_ok()
        );
        for denied in [
            "https://api.openai.com/",
            "https://internal.snowmanai.org.attacker.test/",
            "http://coordinator.internal.snowmanai.org/",
            "https://coordinator.internal.snowmanai.org/path",
        ] {
            assert!(parse_private_origin(denied).is_err(), "{denied}");
        }
    }

    #[test]
    fn database_route_is_snowman_aws_tls_only() {
        let password = "p".repeat(32);
        assert!(valid_database_url(&format!(
            "postgresql://coordinator:{password}@snowman.cluster.us-west-2.rds.amazonaws.com:5432/snowman?sslmode=verify-full"
        )));
        assert!(!valid_database_url(&format!(
            "postgresql://coordinator:{password}@database.attacker.test:5432/snowman?sslmode=verify-full"
        )));
        assert!(!valid_database_url(&format!(
            "postgresql://coordinator:{password}@snowman.cluster.us-west-2.rds.amazonaws.com:5432/snowman?sslmode=require"
        )));
    }

    #[test]
    fn launch_auth_binds_signature_url_method_and_exact_payload() {
        let keys = Keys::generate();
        let url = "https://coordinator.staging.internal.snowmanai.org/v1/tenants/20000000-0000-4000-8000-000000000001/launches";
        let body = br#"{"schema_version":"snowman.agent.job.snapshot.v1"}"#;
        let headers = auth_header(&keys, url, body);
        let verified = verify_auth(&headers, url, body).unwrap();
        assert_eq!(verified.pubkey, keys.public_key().to_bytes());
        assert!(verify_auth(&headers, url, b"changed").is_err());
        assert!(verify_auth(
            &headers,
            "https://coordinator.staging.internal.snowmanai.org/v1/tenants/another/launches",
            body,
        )
        .is_err());
    }
}
