#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Private, deny-by-default inference boundary for Snowman workforce agents.
//!
//! The gateway authenticates exact KMS-signed Analyst 360 requests, consumes
//! nonces in Redis, re-evaluates tenant/model/capability/classification and
//! budget policy, and calls only a configured private Snowman inference
//! backend. It never accepts an endpoint, credential, or arbitrary tool from a
//! caller and it does not persist prompts or model output.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use aws_sdk_kms::{
    primitives::Blob,
    types::{MacAlgorithmSpec, MessageType, SigningAlgorithmSpec},
};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::StreamExt;
use reqwest::{redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use snowman_agent_contract::{ModelGrantClaims, MODEL_GRANT_SCHEMA};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;
use uuid::Uuid;

/// Exact generation route exposed behind the private Snowman load balancer.
pub const GENERATION_PATH: &str = "/internal/snowman/v1/model-generations";
/// Versioned generation contract.
pub const GENERATION_SCHEMA_VERSION: &str = "snowman.model-generation.v1";
const ASSERTION_VERSION: &str = "snowman.service-request.v1";
const OPERATION: &str = "models.generate";
const MODEL_TOKEN_DOMAIN: &[u8] = b"snowman.agent.model-token.v1\0";
const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_ASSERTION_AGE_SECONDS: i64 = 90;
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;
const AGENT_GRANT_HEADER: &str = "x-snowman-agent-model-grant";

/// Static service principal policy. Private keys remain in the calling
/// workload's KMS key and are never present in this configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalPolicy {
    /// Stable workload identity.
    pub principal_id: String,
    /// Exact asymmetric KMS public-key ARN allowed for this identity.
    pub key_id: String,
    /// Tenant boundary.
    pub tenant_id: String,
    /// Client boundary.
    pub client_id: String,
    /// Project boundary.
    pub project_id: String,
    /// Exact model identifiers this workload may invoke.
    pub model_ids: Vec<String>,
    /// Specialist roles this workload may execute.
    pub specialist_roles: Vec<String>,
    /// Capabilities this workload may execute.
    pub capabilities: Vec<String>,
    /// Data classifications this workload may process.
    pub classifications: Vec<String>,
}

/// Operations-owned route to a Snowman-hosted inference runtime.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRoute {
    /// Public catalog identifier bound into workforce tasks.
    pub model_id: String,
    /// Operations-owned runtime kind: `private_openai` or `sagemaker`.
    pub backend_kind: String,
    /// Private Snowman inference origin; required only for `private_openai`.
    pub backend_origin: Option<String>,
    /// Exact same-account endpoint; required only for `sagemaker`.
    pub sagemaker_endpoint_name: Option<String>,
    /// Exact inference component hosted by the endpoint; required only for `sagemaker`.
    pub sagemaker_inference_component_name: Option<String>,
    /// Model identifier understood by the private runtime.
    pub backend_model: String,
    /// Route input-token ceiling.
    pub max_input_tokens: u64,
    /// Route output-token ceiling.
    pub max_output_tokens: u64,
    /// Route cost ceiling in millionths of a US dollar.
    pub max_cost_microusd: u64,
    /// Input price in micro-USD per million tokens.
    pub input_microusd_per_million_tokens: u64,
    /// Output price in micro-USD per million tokens.
    pub output_microusd_per_million_tokens: u64,
}

/// Complete process configuration.
#[derive(Clone)]
pub struct Config {
    /// Bind address, normally the task's private interface.
    pub bind_addr: String,
    /// Redis URL used only for replay protection.
    pub redis_url: String,
    /// IAM-authenticated Valkey user dedicated to gateway nonce keys.
    pub valkey_iam_user_id: String,
    /// Exact ElastiCache replication group used for SigV4 tokens.
    pub valkey_cache_name: String,
    /// AWS region shared by KMS and ElastiCache.
    pub aws_region: String,
    /// Exact HMAC KMS key used only to verify coordinator-issued agent grants.
    pub agent_grant_key_arn: String,
    /// Dedicated least-privilege model-authority database URL.
    pub database_url: String,
    /// Exact PostgreSQL role expected in the database URL.
    pub database_role: String,
    /// Small bounded connection pool used for authorization transactions.
    pub database_max_connections: u32,
    /// Principal policies keyed by principal ID.
    pub principals: BTreeMap<String, PrincipalPolicy>,
    /// Model routes keyed by catalog model ID.
    pub routes: BTreeMap<String, ModelRoute>,
    /// Backend request timeout.
    pub timeout: Duration,
}

/// Configuration errors contain no secret or client content.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required environment variable is missing or malformed.
    #[error("Snowman model gateway configuration is invalid: {0}")]
    Invalid(&'static str),
}

/// Fail-closed model-grant verification failures. No token or client content
/// is included in either the value or its display form.
#[derive(Debug, thiserror::Error)]
pub enum AgentModelGrantError {
    /// The compact token or its claims violate the Snowman contract.
    #[error("Snowman agent model grant is invalid")]
    Invalid,
    /// KMS could not validate the exact domain-separated MAC.
    #[error("Snowman agent model grant authentication failed")]
    Authentication,
}

/// Verify one coordinator-issued model grant with the exact HMAC KMS key.
///
/// This proves token integrity only. A caller must additionally recheck the
/// token digest and live `issued`/`started` job state before inference so that
/// cancellation, deadline expiry, and lease loss revoke model authority.
pub async fn verify_agent_model_grant(
    kms: &aws_sdk_kms::Client,
    key_id: &str,
    token: &str,
) -> Result<ModelGrantClaims, AgentModelGrantError> {
    if !valid_hmac_key_arn(key_id) {
        return Err(AgentModelGrantError::Invalid);
    }
    let (payload, mac, claims) = decode_agent_model_grant(token)?;
    let mut message = Vec::with_capacity(MODEL_TOKEN_DOMAIN.len() + payload.len());
    message.extend_from_slice(MODEL_TOKEN_DOMAIN);
    message.extend_from_slice(&payload);
    let verified = kms
        .verify_mac()
        .key_id(key_id)
        .mac_algorithm(MacAlgorithmSpec::HmacSha256)
        .message(Blob::new(message))
        .mac(Blob::new(mac))
        .send()
        .await
        .map_err(|_| AgentModelGrantError::Authentication)?
        .mac_valid();
    if !verified {
        return Err(AgentModelGrantError::Authentication);
    }
    Ok(claims)
}

fn decode_agent_model_grant(
    token: &str,
) -> Result<(Vec<u8>, Vec<u8>, ModelGrantClaims), AgentModelGrantError> {
    if !(64..=32_768).contains(&token.len()) || !token.starts_with("smg1_") {
        return Err(AgentModelGrantError::Invalid);
    }
    let (payload_text, mac_text) = token[5..]
        .split_once('.')
        .ok_or(AgentModelGrantError::Invalid)?;
    if payload_text.contains('.') || mac_text.contains('.') {
        return Err(AgentModelGrantError::Invalid);
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_text)
        .map_err(|_| AgentModelGrantError::Invalid)?;
    let mac = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(mac_text)
        .map_err(|_| AgentModelGrantError::Invalid)?;
    if payload.is_empty() || payload.len() > 16 * 1024 || mac.len() != 32 {
        return Err(AgentModelGrantError::Invalid);
    }
    let claims: ModelGrantClaims =
        serde_json::from_slice(&payload).map_err(|_| AgentModelGrantError::Invalid)?;
    if serde_json::to_vec(&claims).map_err(|_| AgentModelGrantError::Invalid)? != payload
        || !valid_model_grant_claims(&claims)
    {
        return Err(AgentModelGrantError::Invalid);
    }
    Ok((payload, mac, claims))
}

fn valid_model_grant_claims(claims: &ModelGrantClaims) -> bool {
    let capabilities = claims.capability_grants.iter().collect::<BTreeSet<_>>();
    claims.schema_version == MODEL_GRANT_SCHEMA
        && !claims.tenant_id.is_nil()
        && !claims.job_id.is_nil()
        && !claims.task_id.is_nil()
        && claims.generation > 0
        && valid_identifier(&claims.model_id)
        && !claims.model_id.contains("://")
        && valid_identifier(&claims.specialist_role)
        && !claims.capability_grants.is_empty()
        && claims.capability_grants.len() <= 64
        && capabilities.len() == claims.capability_grants.len()
        && claims
            .capability_grants
            .iter()
            .all(|value| valid_identifier(value))
        && claims.max_input_tokens > 0
        && claims.max_input_tokens <= 10_000_000
        && claims.max_output_tokens > 0
        && claims.max_output_tokens <= 1_000_000
        && claims.max_cost_microusd <= 1_000_000_000
        && is_sha256(&claims.minimization_evidence_sha256)
        && claims.expires_at > Utc::now()
        && claims.expires_at <= Utc::now() + chrono::Duration::hours(4)
}

impl Config {
    /// Load and fully validate the gateway configuration from the environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = std::env::var("SNOWMAN_MODEL_GATEWAY_BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".into());
        let redis_url = std::env::var("SNOWMAN_MODEL_GATEWAY_REDIS_URL")
            .map_err(|_| ConfigError::Invalid("Redis URL is required"))?;
        let valkey_iam_user_id = std::env::var("SNOWMAN_MODEL_GATEWAY_VALKEY_IAM_USER_ID")
            .map_err(|_| ConfigError::Invalid("Valkey IAM user is required"))?;
        let valkey_cache_name = std::env::var("SNOWMAN_MODEL_GATEWAY_VALKEY_CACHE_NAME")
            .map_err(|_| ConfigError::Invalid("Valkey cache name is required"))?;
        let aws_region = std::env::var("AWS_REGION")
            .map_err(|_| ConfigError::Invalid("AWS region is required"))?;
        let agent_grant_key_arn = std::env::var("SNOWMAN_MODEL_GATEWAY_AGENT_GRANT_KEY_ARN")
            .map_err(|_| ConfigError::Invalid("agent grant key is required"))?;
        let database_url = std::env::var("SNOWMAN_MODEL_GATEWAY_DATABASE_URL")
            .map_err(|_| ConfigError::Invalid("database URL is required"))?;
        let database_role = std::env::var("SNOWMAN_MODEL_GATEWAY_DATABASE_ROLE")
            .map_err(|_| ConfigError::Invalid("database role is required"))?;
        let database_max_connections =
            std::env::var("SNOWMAN_MODEL_GATEWAY_DATABASE_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "8".into())
                .parse::<u32>()
                .map_err(|_| ConfigError::Invalid("database connection limit is malformed"))?;
        let principals: Vec<PrincipalPolicy> = serde_json::from_str(
            &std::env::var("SNOWMAN_MODEL_GATEWAY_PRINCIPALS_JSON")
                .map_err(|_| ConfigError::Invalid("principal policy is required"))?,
        )
        .map_err(|_| ConfigError::Invalid("principal policy JSON is malformed"))?;
        let routes: Vec<ModelRoute> = serde_json::from_str(
            &std::env::var("SNOWMAN_MODEL_GATEWAY_ROUTES_JSON")
                .map_err(|_| ConfigError::Invalid("model routes are required"))?,
        )
        .map_err(|_| ConfigError::Invalid("model route JSON is malformed"))?;
        let timeout_seconds = std::env::var("SNOWMAN_MODEL_GATEWAY_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "60".into())
            .parse::<u64>()
            .map_err(|_| ConfigError::Invalid("timeout is malformed"))?;
        if !(1..=120).contains(&timeout_seconds)
            || bind_addr.parse::<std::net::SocketAddr>().is_err()
            || !redis_url.starts_with("rediss://")
            || !valid_identifier(&valkey_iam_user_id)
            || !valid_identifier(&valkey_cache_name)
            || aws_region.is_empty()
            || !valid_hmac_key_arn(&agent_grant_key_arn)
            || agent_grant_key_arn.split(':').nth(3) != Some(aws_region.as_str())
            || !valid_database_url(&database_url)
            || buzz_db::runtime_security::validate_role_name(&database_role).is_err()
            || !(2..=16).contains(&database_max_connections)
            || std::env::var("SNOWMAN_MODEL_GATEWAY_NETWORK_POLICY").as_deref()
                != Ok("private-snowman-only")
        {
            return Err(ConfigError::Invalid(
                "network, database, or timeout policy is invalid",
            ));
        }
        let mut principal_map = BTreeMap::new();
        for policy in principals {
            validate_principal(&policy)?;
            if principal_map
                .insert(policy.principal_id.clone(), policy)
                .is_some()
            {
                return Err(ConfigError::Invalid("principal identifiers must be unique"));
            }
        }
        let mut route_map = BTreeMap::new();
        for route in routes {
            validate_route(&route)?;
            if route_map.insert(route.model_id.clone(), route).is_some() {
                return Err(ConfigError::Invalid("model identifiers must be unique"));
            }
        }
        if principal_map.is_empty() || route_map.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one principal and route are required",
            ));
        }
        Ok(Self {
            bind_addr,
            redis_url,
            valkey_iam_user_id,
            valkey_cache_name,
            aws_region,
            agent_grant_key_arn,
            database_url,
            database_role,
            database_max_connections,
            principals: principal_map,
            routes: route_map,
            timeout: Duration::from_secs(timeout_seconds),
        })
    }
}

/// Shared gateway state.
#[derive(Clone)]
pub struct AppState {
    config: Arc<Config>,
    kms: aws_sdk_kms::Client,
    sagemaker: aws_sdk_sagemakerruntime::Client,
    redis: buzz_pubsub::RedisPool,
    database: PgPool,
    http: Client,
}

impl AppState {
    /// Build production state with AWS KMS, Redis, and a no-proxy/no-redirect
    /// HTTP client.
    pub async fn new(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let credentials = snowman_aws_auth::ElastiCacheIamCredentials::load(
            snowman_aws_auth::ElastiCacheIamConfig {
                user_id: config.valkey_iam_user_id.clone(),
                cache_name: config.valkey_cache_name.clone(),
                region: config.aws_region.clone(),
            },
        )
        .await?;
        let redis = buzz_pubsub::RedisPool::managed(&config.redis_url, 32, credentials).await?;
        let database = PgPoolOptions::new()
            .max_connections(config.database_max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&config.database_url)
            .await?;
        buzz_db::runtime_security::verify_model_gateway_role(&database, &config.database_role)
            .await?;
        let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let http = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self {
            config: Arc::new(config),
            kms: aws_sdk_kms::Client::new(&sdk),
            sagemaker: aws_sdk_sagemakerruntime::Client::new(&sdk),
            redis,
            database,
            http,
        })
    }

    /// Return the configured private bind address.
    pub fn bind_addr(&self) -> &str {
        &self.config.bind_addr
    }
}

/// Build the gateway router with strict request limits and no generic routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(GENERATION_PATH, post(generate))
        .route("/_liveness", get(liveness))
        .route("/_readiness", get(readiness))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .with_state(state)
}

async fn liveness() -> StatusCode {
    StatusCode::OK
}

async fn readiness(State(state): State<AppState>) -> StatusCode {
    let Ok(mut redis) = state.redis.get().await else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    let redis_ready = redis::cmd("PING")
        .query_async::<String>(&mut redis)
        .await
        .is_ok_and(|reply| reply == "PONG");
    let database_ready = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.database)
        .await
        .is_ok_and(|value| value == 1);
    if redis_ready && database_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn generate(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    match execute_generation(&state, &headers, &body).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => {
            tracing::warn!(code = error.code(), "model generation rejected");
            let body = if let GatewayError::Reconcile(receipt) = &error {
                json!({
                    "error": {"code": error.code(), "retryable": false},
                    "reconciliation": receipt,
                })
            } else {
                json!({"error": {"code": error.code(), "retryable": error.retryable()}})
            };
            let mut response = (error.status(), Json(body)).into_response();
            if let Some(seconds) = error.retry_after_seconds() {
                response.headers_mut().insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from_static(seconds),
                );
            }
            response
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum GatewayError {
    #[error("request_invalid")]
    Invalid,
    #[error("authentication_failed")]
    Authentication,
    #[error("authorization_denied")]
    Authorization,
    #[error("request_replayed")]
    Replay,
    #[error("generation_reconciliation_required")]
    Reconcile(Box<GenerationReconciliation>),
    #[error("budget_exceeded")]
    Budget,
    #[error("inference_unavailable")]
    Inference,
}

impl GatewayError {
    fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "request_invalid",
            Self::Authentication => "authentication_failed",
            Self::Authorization => "authorization_denied",
            Self::Replay => "request_replayed",
            Self::Reconcile(_) => "generation_reconciliation_required",
            Self::Budget => "budget_exceeded",
            Self::Inference => "inference_unavailable",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Authentication => StatusCode::UNAUTHORIZED,
            Self::Authorization => StatusCode::FORBIDDEN,
            Self::Replay => StatusCode::CONFLICT,
            Self::Reconcile(_) => StatusCode::CONFLICT,
            Self::Budget => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Inference => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn retryable(&self) -> bool {
        matches!(self, Self::Inference)
    }

    fn retry_after_seconds(&self) -> Option<&'static str> {
        self.retryable().then_some("60")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationRequest {
    schema_version: String,
    generation_id: String,
    tenant_id: String,
    client_id: String,
    project_id: String,
    job_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_generation: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minimization_evidence_sha256: Option<String>,
    correlation_id: String,
    model_id: String,
    specialist_role: String,
    capability: String,
    classification: String,
    content_profile: String,
    instruction: String,
    documents: Vec<GenerationDocument>,
    limits: GenerationLimits,
    submitted_at: String,
    expires_at: String,
    request_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationDocument {
    artifact_ref: ArtifactReference,
    content: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReference {
    artifact_id: String,
    artifact_type: String,
    authority: String,
    classification: String,
    created_at: String,
    sha256: String,
    version_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationLimits {
    max_input_tokens: u64,
    max_output_tokens: u64,
    max_cost_microusd: u64,
}

#[derive(Serialize)]
struct GenerationResponse {
    schema_version: &'static str,
    generation_id: String,
    tenant_id: String,
    client_id: String,
    project_id: String,
    job_id: String,
    correlation_id: String,
    model_id: String,
    output: GenerationOutput,
    usage: GenerationUsage,
    completed_at: String,
    request_sha256: String,
    response_sha256: String,
}

#[derive(Serialize)]
struct GenerationOutput {
    format: &'static str,
    content: String,
    content_sha256: String,
}

#[derive(Serialize)]
struct GenerationUsage {
    input_tokens: u64,
    output_tokens: u64,
    cost_microusd: u64,
    inference_performed: bool,
}

#[derive(Debug, Serialize)]
struct GenerationReconciliation {
    schema_version: &'static str,
    generation_id: Uuid,
    status: String,
    accounted_input_tokens: u64,
    accounted_output_tokens: u64,
    accounted_cost_microusd: u64,
    provider_receipt_sha256: Option<String>,
    response_sha256: Option<String>,
    inference_performed: bool,
}

#[derive(Deserialize, Serialize)]
struct BackendResponse {
    choices: Vec<BackendChoice>,
    usage: BackendUsage,
}

#[derive(Deserialize, Serialize)]
struct BackendChoice {
    message: BackendMessage,
    finish_reason: String,
}

#[derive(Deserialize, Serialize)]
struct BackendMessage {
    content: String,
}

#[derive(Deserialize, Serialize)]
struct BackendUsage {
    prompt_tokens: u64,
    completion_tokens: u64,
}

async fn execute_generation(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Value, GatewayError> {
    let request: GenerationRequest =
        serde_json::from_slice(body).map_err(|_| GatewayError::Invalid)?;
    validate_request(&request)?;
    if let Some(token) = optional_header(headers, AGENT_GRANT_HEADER)? {
        execute_agent_generation(state, &request, token).await
    } else {
        let principal_id = header(headers, "x-snowman-service-principal")?;
        let policy = state
            .config
            .principals
            .get(principal_id)
            .ok_or(GatewayError::Authentication)?;
        authenticate(state, headers, body, policy).await?;
        authorize(&request, policy)?;
        let route = state
            .config
            .routes
            .get(&request.model_id)
            .ok_or(GatewayError::Authorization)?;
        authorize_route(&request, route)?;
        let backend = invoke_backend(state, &request, route).await?;
        build_response(&request, route, &backend)
    }
}

fn validate_request(request: &GenerationRequest) -> Result<(), GatewayError> {
    if request.schema_version != GENERATION_SCHEMA_VERSION
        || request.content_profile != "governed_artifact_projection"
        || request.tenant_id != request.client_id
        || !valid_identifier(&request.generation_id)
        || !valid_identifier(&request.job_id)
        || !valid_identifier(&request.correlation_id)
        || !valid_identifier(&request.model_id)
        || !valid_identifier(&request.specialist_role)
        || !valid_identifier(&request.capability)
        || !matches!(
            request.classification.as_str(),
            "internal" | "confidential" | "restricted"
        )
        || request.instruction.trim().is_empty()
        || request.instruction.len() > 16_384
        || !(1..=32).contains(&request.documents.len())
        || request.limits.max_input_tokens == 0
        || request.limits.max_output_tokens == 0
    {
        return Err(GatewayError::Invalid);
    }
    let submitted = DateTime::parse_from_rfc3339(&request.submitted_at)
        .map_err(|_| GatewayError::Invalid)?
        .with_timezone(&Utc);
    let expires = DateTime::parse_from_rfc3339(&request.expires_at)
        .map_err(|_| GatewayError::Invalid)?
        .with_timezone(&Utc);
    let now = Utc::now();
    if submitted > now + chrono::Duration::seconds(MAX_CLOCK_SKEW_SECONDS)
        || expires <= now
        || expires > submitted + chrono::Duration::minutes(5)
    {
        return Err(GatewayError::Invalid);
    }
    for document in &request.documents {
        if document.content.trim().is_empty()
            || document.content.len() > 32 * 1024
            || document.artifact_ref.authority != "analyst360"
            || document.artifact_ref.classification != request.classification
            || !is_sha256(&document.artifact_ref.sha256)
            || !valid_identifier(&document.artifact_ref.artifact_id)
            || !valid_identifier(&document.artifact_ref.version_id)
            || !valid_identifier(&document.artifact_ref.artifact_type)
            || DateTime::parse_from_rfc3339(&document.artifact_ref.created_at).is_err()
        {
            return Err(GatewayError::Invalid);
        }
    }
    let value = serde_json::to_value(request).map_err(|_| GatewayError::Invalid)?;
    let mut unsigned = value.as_object().cloned().ok_or(GatewayError::Invalid)?;
    unsigned.remove("request_sha256");
    if canonical_sha256(&Value::Object(unsigned))? != request.request_sha256 {
        return Err(GatewayError::Invalid);
    }
    Ok(())
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    policy: &PrincipalPolicy,
) -> Result<(), GatewayError> {
    if header(headers, "x-snowman-assertion-version")? != ASSERTION_VERSION
        || header(headers, "x-snowman-key-id")? != policy.key_id
    {
        return Err(GatewayError::Authentication);
    }
    let nonce = header(headers, "x-snowman-nonce")?;
    let signed_at = header(headers, "x-snowman-signed-at")?;
    if !valid_nonce(nonce) {
        return Err(GatewayError::Authentication);
    }
    let signed_time = DateTime::parse_from_rfc3339(signed_at)
        .map_err(|_| GatewayError::Authentication)?
        .with_timezone(&Utc);
    let age = Utc::now().signed_duration_since(signed_time).num_seconds();
    if !(-MAX_CLOCK_SKEW_SECONDS..=MAX_ASSERTION_AGE_SECONDS).contains(&age) {
        return Err(GatewayError::Authentication);
    }
    let signature = STANDARD
        .decode(header(headers, "x-snowman-signature")?)
        .map_err(|_| GatewayError::Authentication)?;
    if !(128..=1024).contains(&signature.len()) {
        return Err(GatewayError::Authentication);
    }
    let assertion = json!({
        "body_sha256": sha256_hex(body),
        "key_id": policy.key_id,
        "method": "POST",
        "nonce": nonce,
        "operation": OPERATION,
        "principal_id": policy.principal_id,
        "request_target": GENERATION_PATH,
        "signed_at": signed_at,
        "version": ASSERTION_VERSION,
    });
    let verified = state
        .kms
        .verify()
        .key_id(&policy.key_id)
        .message(Blob::new(canonical_json_bytes(&assertion)?))
        .message_type(MessageType::Raw)
        .signature(Blob::new(signature))
        .signing_algorithm(SigningAlgorithmSpec::RsassaPssSha256)
        .send()
        .await
        .map_err(|_| GatewayError::Authentication)?
        .signature_valid();
    if !verified {
        return Err(GatewayError::Authentication);
    }
    let replay_key = format!(
        "snowman:model-gateway:nonce:{}:{}",
        policy.principal_id, nonce
    );
    let mut redis = state
        .redis
        .get()
        .await
        .map_err(|_| GatewayError::Authentication)?;
    let claimed: Option<String> = redis::cmd("SET")
        .arg(replay_key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(600_u64)
        .query_async(&mut redis)
        .await
        .map_err(|_| GatewayError::Authentication)?;
    if claimed.as_deref() != Some("OK") {
        return Err(GatewayError::Replay);
    }
    Ok(())
}

fn authorize(request: &GenerationRequest, policy: &PrincipalPolicy) -> Result<(), GatewayError> {
    if request.tenant_id != policy.tenant_id
        || request.client_id != policy.client_id
        || request.project_id != policy.project_id
        || !policy.model_ids.contains(&request.model_id)
        || !policy.specialist_roles.contains(&request.specialist_role)
        || !policy.capabilities.contains(&request.capability)
        || !policy.classifications.contains(&request.classification)
    {
        return Err(GatewayError::Authorization);
    }
    Ok(())
}

fn authorize_route(request: &GenerationRequest, route: &ModelRoute) -> Result<(), GatewayError> {
    let worst_case_cost = token_cost(
        request.limits.max_input_tokens,
        route.input_microusd_per_million_tokens,
    )?
    .checked_add(token_cost(
        request.limits.max_output_tokens,
        route.output_microusd_per_million_tokens,
    )?)
    .ok_or(GatewayError::Budget)?;
    if request.limits.max_input_tokens > route.max_input_tokens
        || request.limits.max_output_tokens > route.max_output_tokens
        || request.limits.max_cost_microusd > route.max_cost_microusd
        || worst_case_cost > request.limits.max_cost_microusd
    {
        return Err(GatewayError::Budget);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AgentScope {
    tenant_id: Uuid,
    job_id: Uuid,
    task_id: Uuid,
    generation_id: Uuid,
    lease_generation: u32,
}

struct LiveAuthority {
    request_id: Uuid,
}

async fn execute_agent_generation(
    state: &AppState,
    request: &GenerationRequest,
    token: &str,
) -> Result<Value, GatewayError> {
    let claims = verify_agent_model_grant(&state.kms, &state.config.agent_grant_key_arn, token)
        .await
        .map_err(|_| GatewayError::Authentication)?;
    let route = state
        .config
        .routes
        .get(&request.model_id)
        .ok_or(GatewayError::Authorization)?;
    authorize_route(request, route)?;
    let scope = authorize_agent_request(request, route, &claims)?;
    let token_digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if let Some(receipt) =
        reserve_agent_generation(state, request, &claims, scope, &token_digest).await?
    {
        return Err(GatewayError::Reconcile(Box::new(receipt)));
    }
    if !authorize_agent_dispatch(state, request, &claims, scope, &token_digest).await? {
        return Err(GatewayError::Authorization);
    }

    let backend = match invoke_backend(state, request, route).await {
        Ok(response) => response,
        Err(error) => {
            mark_dispatch_finished(&state.database, scope).await;
            return Err(error);
        }
    };
    let provider_receipt =
        canonical_sha256(&serde_json::to_value(&backend).map_err(|_| GatewayError::Inference)?)?;
    let usage = measured_usage(&backend, route);
    let response = usage.as_ref().map_or(Err(GatewayError::Budget), |_| {
        build_response(request, route, &backend)
    });
    let accepted = response.is_ok();
    let Some(usage) = usage else {
        mark_dispatch_finished(&state.database, scope).await;
        return Err(GatewayError::Budget);
    };
    let response_digest = response
        .as_ref()
        .ok()
        .and_then(|value| value.get("response_sha256"))
        .and_then(Value::as_str);
    finalize_agent_generation(
        &state.database,
        scope,
        usage,
        &provider_receipt,
        response_digest,
        accepted,
    )
    .await?;
    response
}

#[derive(Clone, Copy)]
struct AccountedUsage {
    input_tokens: u64,
    output_tokens: u64,
    cost_microusd: u64,
}

fn measured_usage(backend: &BackendResponse, route: &ModelRoute) -> Option<AccountedUsage> {
    let input_tokens = backend.usage.prompt_tokens;
    let output_tokens = backend.usage.completion_tokens;
    let cost_microusd = token_cost(input_tokens, route.input_microusd_per_million_tokens)
        .ok()?
        .checked_add(token_cost(output_tokens, route.output_microusd_per_million_tokens).ok()?)?;
    i64::try_from(input_tokens).ok()?;
    i64::try_from(output_tokens).ok()?;
    i64::try_from(cost_microusd).ok()?;
    Some(AccountedUsage {
        input_tokens,
        output_tokens,
        cost_microusd,
    })
}

fn authorize_agent_request(
    request: &GenerationRequest,
    route: &ModelRoute,
    claims: &ModelGrantClaims,
) -> Result<AgentScope, GatewayError> {
    let tenant_id = request
        .tenant_id
        .parse::<Uuid>()
        .map_err(|_| GatewayError::Authorization)?;
    let job_id = request
        .job_id
        .parse::<Uuid>()
        .map_err(|_| GatewayError::Authorization)?;
    let task_id = request
        .task_id
        .as_deref()
        .ok_or(GatewayError::Authorization)?
        .parse::<Uuid>()
        .map_err(|_| GatewayError::Authorization)?;
    let generation_id = request
        .generation_id
        .parse::<Uuid>()
        .map_err(|_| GatewayError::Authorization)?;
    let lease_generation = request
        .lease_generation
        .ok_or(GatewayError::Authorization)?;
    let minimization_evidence = request
        .minimization_evidence_sha256
        .as_deref()
        .ok_or(GatewayError::Authorization)?;
    let expires_at = DateTime::parse_from_rfc3339(&request.expires_at)
        .map_err(|_| GatewayError::Authorization)?
        .with_timezone(&Utc);
    if tenant_id != claims.tenant_id
        || request.client_id != request.tenant_id
        || request.project_id != request.tenant_id
        || job_id != claims.job_id
        || task_id != claims.task_id
        || lease_generation != claims.generation
        || request.model_id != claims.model_id
        || request.specialist_role != claims.specialist_role
        || request.classification != classification_name(claims.classification)
        || !claims.capability_grants.contains(&request.capability)
        || minimization_evidence != claims.minimization_evidence_sha256
        || !is_sha256(minimization_evidence)
        || request.limits.max_input_tokens > claims.max_input_tokens
        || request.limits.max_output_tokens > claims.max_output_tokens
        || request.limits.max_cost_microusd > claims.max_cost_microusd
        || request.model_id != route.model_id
        || expires_at > claims.expires_at
    {
        return Err(GatewayError::Authorization);
    }
    Ok(AgentScope {
        tenant_id,
        job_id,
        task_id,
        generation_id,
        lease_generation,
    })
}

fn classification_name(value: snowman_agent_contract::Classification) -> &'static str {
    match value {
        snowman_agent_contract::Classification::Internal => "internal",
        snowman_agent_contract::Classification::Confidential => "confidential",
        snowman_agent_contract::Classification::Restricted => "restricted",
    }
}

async fn reserve_agent_generation(
    state: &AppState,
    request: &GenerationRequest,
    claims: &ModelGrantClaims,
    scope: AgentScope,
    token_digest: &[u8; 32],
) -> Result<Option<GenerationReconciliation>, GatewayError> {
    let mut transaction = state
        .database
        .begin()
        .await
        .map_err(|_| GatewayError::Inference)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await
        .map_err(|_| GatewayError::Inference)?;
    if let Some(row) = sqlx::query(
        "SELECT g.job_id,g.task_id,g.lease_generation,g.request_sha256,g.model_id,g.capability,\
         g.status,g.accounted_input_tokens,g.accounted_output_tokens,g.accounted_cost_microusd,\
         g.provider_receipt_sha256,g.response_sha256 \
         FROM snowman_agent_model_generations g JOIN snowman_agent_jobs j \
           ON j.community_id=g.community_id AND j.job_id=g.job_id \
         WHERE g.community_id=$1 AND g.generation_id=$2 AND j.job_id=$3 AND j.task_id=$4 \
           AND j.generation=$5 AND j.model_token_sha256=$6",
    )
    .bind(scope.tenant_id)
    .bind(scope.generation_id)
    .bind(scope.job_id)
    .bind(scope.task_id)
    .bind(i64::from(scope.lease_generation))
    .bind(token_digest.as_slice())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|_| GatewayError::Inference)?
    {
        let exact = row.try_get::<Uuid, _>("job_id").ok() == Some(scope.job_id)
            && row.try_get::<Uuid, _>("task_id").ok() == Some(scope.task_id)
            && row.try_get::<i64, _>("lease_generation").ok()
                == Some(i64::from(scope.lease_generation))
            && row.try_get::<Vec<u8>, _>("request_sha256").ok().as_deref()
                == hex::decode(&request.request_sha256).ok().as_deref()
            && row.try_get::<String, _>("model_id").ok().as_deref()
                == Some(request.model_id.as_str())
            && row.try_get::<String, _>("capability").ok().as_deref()
                == Some(request.capability.as_str());
        transaction
            .rollback()
            .await
            .map_err(|_| GatewayError::Inference)?;
        return if exact {
            Ok(Some(reconciliation_from_row(scope.generation_id, &row)?))
        } else {
            Err(GatewayError::Replay)
        };
    }
    let authority = lock_live_authority(&mut transaction, request, claims, scope, token_digest)
        .await?
        .ok_or(GatewayError::Authorization)?;
    ensure_aggregate_budget(
        &mut transaction,
        authority.request_id,
        request,
        claims,
        scope,
    )
    .await?;
    let request_digest = hex::decode(&request.request_sha256).map_err(|_| GatewayError::Invalid)?;
    let inserted = sqlx::query(
        "INSERT INTO snowman_agent_model_generations \
         (community_id,generation_id,job_id,request_id,task_id,lease_generation,\
          request_sha256,model_id,capability,requested_input_tokens,\
          requested_output_tokens,requested_cost_microusd,accounted_input_tokens,\
          accounted_output_tokens,accounted_cost_microusd,status) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$10,$11,$12,'reserved') \
         ON CONFLICT DO NOTHING",
    )
    .bind(scope.tenant_id)
    .bind(scope.generation_id)
    .bind(scope.job_id)
    .bind(authority.request_id)
    .bind(scope.task_id)
    .bind(i64::from(scope.lease_generation))
    .bind(request_digest)
    .bind(&request.model_id)
    .bind(&request.capability)
    .bind(to_i64(request.limits.max_input_tokens)?)
    .bind(to_i64(request.limits.max_output_tokens)?)
    .bind(to_i64(request.limits.max_cost_microusd)?)
    .execute(&mut *transaction)
    .await
    .map_err(|_| GatewayError::Inference)?;
    if inserted.rows_affected() != 1 {
        return Err(GatewayError::Replay);
    }
    transaction
        .commit()
        .await
        .map_err(|_| GatewayError::Inference)?;
    Ok(None)
}

async fn authorize_agent_dispatch(
    state: &AppState,
    request: &GenerationRequest,
    claims: &ModelGrantClaims,
    scope: AgentScope,
    token_digest: &[u8; 32],
) -> Result<bool, GatewayError> {
    let mut transaction = state
        .database
        .begin()
        .await
        .map_err(|_| GatewayError::Inference)?;
    let live = lock_live_authority(&mut transaction, request, claims, scope, token_digest)
        .await?
        .is_some();
    let status = if live { "indeterminate" } else { "aborted" };
    let updated = sqlx::query(
        "UPDATE snowman_agent_model_generations SET status=$3,\
         invocation_started_at=CASE WHEN $3='indeterminate' THEN NOW() ELSE NULL END,\
         completed_at=CASE WHEN $3='aborted' THEN NOW() ELSE NULL END,\
         accounted_input_tokens=CASE WHEN $3='aborted' THEN 0 ELSE accounted_input_tokens END,\
         accounted_output_tokens=CASE WHEN $3='aborted' THEN 0 ELSE accounted_output_tokens END,\
         accounted_cost_microusd=CASE WHEN $3='aborted' THEN 0 ELSE accounted_cost_microusd END,\
         updated_at=NOW() WHERE community_id=$1 AND generation_id=$2 AND status='reserved'",
    )
    .bind(scope.tenant_id)
    .bind(scope.generation_id)
    .bind(status)
    .execute(&mut *transaction)
    .await
    .map_err(|_| GatewayError::Inference)?;
    if updated.rows_affected() != 1 {
        return Err(GatewayError::Reconcile(Box::new(
            fetch_reconciliation(&state.database, scope).await?,
        )));
    }
    transaction
        .commit()
        .await
        .map_err(|_| GatewayError::Inference)?;
    Ok(live)
}

async fn lock_live_authority(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &GenerationRequest,
    claims: &ModelGrantClaims,
    scope: AgentScope,
    token_digest: &[u8; 32],
) -> Result<Option<LiveAuthority>, GatewayError> {
    let row = sqlx::query(
        "SELECT j.request_id FROM snowman_agent_jobs j \
         JOIN snowman_work_tasks t ON t.community_id=j.community_id \
           AND t.request_id=j.request_id AND t.task_id=j.task_id \
         JOIN snowman_work_requests r ON r.community_id=j.community_id \
           AND r.request_id=j.request_id \
         JOIN snowman_task_leases lease ON lease.community_id=j.community_id \
           AND lease.task_id=j.task_id \
         WHERE j.community_id=$1 AND j.job_id=$2 AND j.task_id=$3 AND j.generation=$4 \
           AND j.status='started' AND j.token_revoked_at IS NULL AND j.deadline_at>NOW() \
           AND j.deadline_at=$5 AND j.model_token_sha256=$6 AND j.model_id=$7 \
           AND j.classification=$8 AND j.capability_grants=$9 \
           AND j.max_input_tokens=$10 AND j.max_output_tokens=$11 AND j.max_cost_microusd=$12 \
           AND t.specialist_role=$13 AND t.status IN ('leased','running') \
           AND r.status IN ('running','reviewing') \
           AND lease.generation=j.generation AND lease.expires_at>NOW() \
         FOR UPDATE OF j,t,r,lease",
    )
    .bind(scope.tenant_id)
    .bind(scope.job_id)
    .bind(scope.task_id)
    .bind(i64::from(scope.lease_generation))
    .bind(claims.expires_at)
    .bind(token_digest.as_slice())
    .bind(&request.model_id)
    .bind(&request.classification)
    .bind(&claims.capability_grants)
    .bind(to_i64(claims.max_input_tokens)?)
    .bind(to_i64(claims.max_output_tokens)?)
    .bind(to_i64(claims.max_cost_microusd)?)
    .bind(&request.specialist_role)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| GatewayError::Inference)?;
    row.map(|row| {
        Ok(LiveAuthority {
            request_id: row
                .try_get("request_id")
                .map_err(|_| GatewayError::Inference)?,
        })
    })
    .transpose()
}

async fn ensure_aggregate_budget(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: Uuid,
    request: &GenerationRequest,
    claims: &ModelGrantClaims,
    scope: AgentScope,
) -> Result<(), GatewayError> {
    let within_budget: bool = sqlx::query_scalar(
        "SELECT \
          COALESCE((SELECT SUM(accounted_input_tokens)::numeric FROM snowman_agent_model_generations \
            WHERE community_id=$1 AND job_id=$2 AND status<>'aborted'),0)+$4 <= $7 \
          AND COALESCE((SELECT SUM(accounted_output_tokens)::numeric FROM snowman_agent_model_generations \
            WHERE community_id=$1 AND job_id=$2 AND status<>'aborted'),0)+$5 <= $8 \
          AND COALESCE((SELECT SUM(accounted_cost_microusd)::numeric FROM snowman_agent_model_generations \
            WHERE community_id=$1 AND job_id=$2 AND status<>'aborted'),0)+$6 <= $9 \
          AND COALESCE((SELECT SUM(input_tokens)::numeric FROM snowman_spend_ledger \
            WHERE community_id=$1 AND request_id=$3),0) \
            +COALESCE((SELECT SUM(accounted_input_tokens)::numeric FROM snowman_agent_model_generations \
              WHERE community_id=$1 AND request_id=$3 AND status IN ('reserved','indeterminate')),0)+$4 \
            <= (SELECT max_input_tokens FROM snowman_work_requests WHERE community_id=$1 AND request_id=$3) \
          AND COALESCE((SELECT SUM(output_tokens)::numeric FROM snowman_spend_ledger \
            WHERE community_id=$1 AND request_id=$3),0) \
            +COALESCE((SELECT SUM(accounted_output_tokens)::numeric FROM snowman_agent_model_generations \
              WHERE community_id=$1 AND request_id=$3 AND status IN ('reserved','indeterminate')),0)+$5 \
            <= (SELECT max_output_tokens FROM snowman_work_requests WHERE community_id=$1 AND request_id=$3) \
          AND COALESCE((SELECT SUM(cost_microusd)::numeric FROM snowman_spend_ledger \
            WHERE community_id=$1 AND request_id=$3),0) \
            +COALESCE((SELECT SUM(accounted_cost_microusd)::numeric FROM snowman_agent_model_generations \
              WHERE community_id=$1 AND request_id=$3 AND status IN ('reserved','indeterminate')),0)+$6 \
            <= (SELECT max_cost_microusd FROM snowman_work_requests WHERE community_id=$1 AND request_id=$3)",
    )
    .bind(scope.tenant_id)
    .bind(scope.job_id)
    .bind(request_id)
    .bind(to_i64(request.limits.max_input_tokens)?)
    .bind(to_i64(request.limits.max_output_tokens)?)
    .bind(to_i64(request.limits.max_cost_microusd)?)
    .bind(to_i64(claims.max_input_tokens)?)
    .bind(to_i64(claims.max_output_tokens)?)
    .bind(to_i64(claims.max_cost_microusd)?)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| GatewayError::Inference)?;
    if within_budget {
        Ok(())
    } else {
        Err(GatewayError::Budget)
    }
}

async fn finalize_agent_generation(
    pool: &PgPool,
    scope: AgentScope,
    usage: AccountedUsage,
    provider_receipt: &str,
    response_digest: Option<&str>,
    accepted: bool,
) -> Result<(), GatewayError> {
    let provider_receipt = hex::decode(provider_receipt).map_err(|_| GatewayError::Inference)?;
    let response_digest = response_digest
        .map(hex::decode)
        .transpose()
        .map_err(|_| GatewayError::Inference)?;
    let mut transaction = pool.begin().await.map_err(|_| GatewayError::Inference)?;
    let status = if accepted {
        "succeeded"
    } else {
        "accounted_rejected"
    };
    let updated = sqlx::query(
        "UPDATE snowman_agent_model_generations SET status=$3,accounted_input_tokens=$4,\
         accounted_output_tokens=$5,accounted_cost_microusd=$6,provider_receipt_sha256=$7,\
         response_sha256=$8,completed_at=NOW(),updated_at=NOW() \
         WHERE community_id=$1 AND generation_id=$2 AND status='indeterminate'",
    )
    .bind(scope.tenant_id)
    .bind(scope.generation_id)
    .bind(status)
    .bind(to_i64(usage.input_tokens)?)
    .bind(to_i64(usage.output_tokens)?)
    .bind(to_i64(usage.cost_microusd)?)
    .bind(&provider_receipt)
    .bind(&response_digest)
    .execute(&mut *transaction)
    .await
    .map_err(|_| GatewayError::Inference)?;
    if updated.rows_affected() != 1 {
        return Err(GatewayError::Reconcile(Box::new(
            fetch_reconciliation(pool, scope).await?,
        )));
    }
    let ledger = sqlx::query(
        "INSERT INTO snowman_spend_ledger \
         (community_id,ledger_entry_id,request_id,task_id,model_id,input_tokens,\
          output_tokens,cost_microusd,provider_receipt_sha256,recorded_at,worker_identity_id) \
         SELECT g.community_id,g.generation_id,g.request_id,g.task_id,g.model_id,\
          g.accounted_input_tokens,g.accounted_output_tokens,g.accounted_cost_microusd,\
          g.provider_receipt_sha256,NOW(),j.service_identity_id \
         FROM snowman_agent_model_generations g JOIN snowman_agent_jobs j \
          ON j.community_id=g.community_id AND j.job_id=g.job_id \
         WHERE g.community_id=$1 AND g.generation_id=$2 ON CONFLICT DO NOTHING",
    )
    .bind(scope.tenant_id)
    .bind(scope.generation_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| GatewayError::Inference)?;
    if ledger.rows_affected() != 1 {
        return Err(GatewayError::Inference);
    }
    transaction
        .commit()
        .await
        .map_err(|_| GatewayError::Inference)
}

async fn fetch_reconciliation(
    pool: &PgPool,
    scope: AgentScope,
) -> Result<GenerationReconciliation, GatewayError> {
    let row = sqlx::query(
        "SELECT status,accounted_input_tokens,accounted_output_tokens,\
         accounted_cost_microusd,provider_receipt_sha256,response_sha256 \
         FROM snowman_agent_model_generations WHERE community_id=$1 AND generation_id=$2",
    )
    .bind(scope.tenant_id)
    .bind(scope.generation_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| GatewayError::Inference)?
    .ok_or(GatewayError::Inference)?;
    reconciliation_from_row(scope.generation_id, &row)
}

fn reconciliation_from_row(
    generation_id: Uuid,
    row: &sqlx::postgres::PgRow,
) -> Result<GenerationReconciliation, GatewayError> {
    let status: String = row.try_get("status").map_err(|_| GatewayError::Inference)?;
    let input = row
        .try_get::<i64, _>("accounted_input_tokens")
        .map_err(|_| GatewayError::Inference)?;
    let output = row
        .try_get::<i64, _>("accounted_output_tokens")
        .map_err(|_| GatewayError::Inference)?;
    let cost = row
        .try_get::<i64, _>("accounted_cost_microusd")
        .map_err(|_| GatewayError::Inference)?;
    Ok(GenerationReconciliation {
        schema_version: GENERATION_SCHEMA_VERSION,
        generation_id,
        inference_performed: matches!(
            status.as_str(),
            "indeterminate" | "succeeded" | "accounted_rejected"
        ),
        status,
        accounted_input_tokens: u64::try_from(input).map_err(|_| GatewayError::Inference)?,
        accounted_output_tokens: u64::try_from(output).map_err(|_| GatewayError::Inference)?,
        accounted_cost_microusd: u64::try_from(cost).map_err(|_| GatewayError::Inference)?,
        provider_receipt_sha256: row
            .try_get::<Option<Vec<u8>>, _>("provider_receipt_sha256")
            .map_err(|_| GatewayError::Inference)?
            .map(hex::encode),
        response_sha256: row
            .try_get::<Option<Vec<u8>>, _>("response_sha256")
            .map_err(|_| GatewayError::Inference)?
            .map(hex::encode),
    })
}

async fn mark_dispatch_finished(pool: &PgPool, scope: AgentScope) {
    if sqlx::query(
        "UPDATE snowman_agent_model_generations SET completed_at=COALESCE(completed_at,NOW()),\
         updated_at=NOW() WHERE community_id=$1 AND generation_id=$2 AND status='indeterminate'",
    )
    .bind(scope.tenant_id)
    .bind(scope.generation_id)
    .execute(pool)
    .await
    .is_err()
    {
        tracing::error!("model dispatch completion marker could not be persisted");
    }
}

fn to_i64(value: u64) -> Result<i64, GatewayError> {
    i64::try_from(value).map_err(|_| GatewayError::Budget)
}

async fn invoke_backend(
    state: &AppState,
    request: &GenerationRequest,
    route: &ModelRoute,
) -> Result<BackendResponse, GatewayError> {
    let prompt = serde_json::to_string(&json!({
        "instruction": request.instruction,
        "classification": request.classification,
        "documents": request.documents,
        "required_output_format": "markdown",
        "citation_rule": "Cite immutable artifact_id and sha256 for every substantive claim.",
    }))
    .map_err(|_| GatewayError::Inference)?;
    let request_body = serde_json::to_vec(&json!({
        "model": route.backend_model,
        "messages": [
            {"role": "system", "content": "You are a scoped Snowman specialist. Use only supplied governed evidence; never invent facts, credentials, citations, or completed actions."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": request.limits.max_output_tokens,
        "temperature": 0.2,
        "stream": false
    }))
    .map_err(|_| GatewayError::Inference)?;
    match route.backend_kind.as_str() {
        "private_openai" => invoke_private_openai(state, route, request_body).await,
        "sagemaker" => invoke_sagemaker(state, route, &request.generation_id, request_body).await,
        _ => Err(GatewayError::Inference),
    }
}

async fn invoke_private_openai(
    state: &AppState,
    route: &ModelRoute,
    request_body: Vec<u8>,
) -> Result<BackendResponse, GatewayError> {
    let origin = Url::parse(
        route
            .backend_origin
            .as_deref()
            .ok_or(GatewayError::Inference)?,
    )
    .map_err(|_| GatewayError::Inference)?;
    let url = origin
        .join("/v1/chat/completions")
        .map_err(|_| GatewayError::Inference)?;
    let response = state
        .http
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(request_body)
        .send()
        .await
        .map_err(|_| GatewayError::Inference)?;
    if response.status() != StatusCode::OK {
        return Err(GatewayError::Inference);
    }
    if !response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media_type| media_type.trim() == "application/json")
        })
    {
        return Err(GatewayError::Inference);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(GatewayError::Inference);
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| GatewayError::Inference)?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(GatewayError::Inference);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| GatewayError::Inference)
}

async fn invoke_sagemaker(
    state: &AppState,
    route: &ModelRoute,
    generation_id: &str,
    request_body: Vec<u8>,
) -> Result<BackendResponse, GatewayError> {
    let endpoint_name = route
        .sagemaker_endpoint_name
        .as_deref()
        .ok_or(GatewayError::Inference)?;
    let inference_component_name = route
        .sagemaker_inference_component_name
        .as_deref()
        .ok_or(GatewayError::Inference)?;
    let output = state
        .sagemaker
        .invoke_endpoint()
        .endpoint_name(endpoint_name)
        .inference_component_name(inference_component_name)
        .content_type("application/json")
        .accept("application/json")
        .inference_id(format!("snowman-{generation_id}"))
        .body(aws_sdk_sagemakerruntime::primitives::Blob::new(
            request_body,
        ))
        .send()
        .await
        .map_err(|_| GatewayError::Inference)?;
    if !output.content_type().is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim() == "application/json")
    }) {
        return Err(GatewayError::Inference);
    }
    let bytes = output.body().ok_or(GatewayError::Inference)?.as_ref();
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(GatewayError::Inference);
    }
    serde_json::from_slice(bytes).map_err(|_| GatewayError::Inference)
}

fn build_response(
    request: &GenerationRequest,
    route: &ModelRoute,
    backend: &BackendResponse,
) -> Result<Value, GatewayError> {
    if backend.choices.len() != 1 || backend.choices[0].finish_reason != "stop" {
        return Err(GatewayError::Inference);
    }
    let content = backend.choices[0].message.content.trim().to_string();
    if content.is_empty() || content.len() > MAX_RESPONSE_BYTES {
        return Err(GatewayError::Inference);
    }
    let input_tokens = backend.usage.prompt_tokens;
    let output_tokens = backend.usage.completion_tokens;
    let input_cost = token_cost(input_tokens, route.input_microusd_per_million_tokens)?;
    let output_cost = token_cost(output_tokens, route.output_microusd_per_million_tokens)?;
    let cost_microusd = input_cost
        .checked_add(output_cost)
        .ok_or(GatewayError::Budget)?;
    if input_tokens > request.limits.max_input_tokens
        || output_tokens > request.limits.max_output_tokens
        || cost_microusd > request.limits.max_cost_microusd
    {
        return Err(GatewayError::Budget);
    }
    let response = GenerationResponse {
        schema_version: GENERATION_SCHEMA_VERSION,
        generation_id: request.generation_id.clone(),
        tenant_id: request.tenant_id.clone(),
        client_id: request.client_id.clone(),
        project_id: request.project_id.clone(),
        job_id: request.job_id.clone(),
        correlation_id: request.correlation_id.clone(),
        model_id: request.model_id.clone(),
        output: GenerationOutput {
            format: "markdown",
            content_sha256: sha256_hex(content.as_bytes()),
            content,
        },
        usage: GenerationUsage {
            input_tokens,
            output_tokens,
            cost_microusd,
            inference_performed: true,
        },
        completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        request_sha256: request.request_sha256.clone(),
        response_sha256: String::new(),
    };
    let mut value = serde_json::to_value(response).map_err(|_| GatewayError::Inference)?;
    value
        .as_object_mut()
        .ok_or(GatewayError::Inference)?
        .remove("response_sha256");
    let digest = canonical_sha256(&value)?;
    value
        .as_object_mut()
        .ok_or(GatewayError::Inference)?
        .insert("response_sha256".into(), Value::String(digest));
    Ok(value)
}

fn validate_principal(policy: &PrincipalPolicy) -> Result<(), ConfigError> {
    if !valid_identifier(&policy.principal_id)
        || !valid_kms_key_arn(&policy.key_id)
        || !valid_identifier(&policy.tenant_id)
        || policy.tenant_id != policy.client_id
        || !valid_identifier(&policy.project_id)
        || policy.model_ids.is_empty()
        || policy.specialist_roles.is_empty()
        || policy.capabilities.is_empty()
        || policy.classifications.is_empty()
        || policy.model_ids.iter().any(|item| !valid_identifier(item))
        || policy
            .specialist_roles
            .iter()
            .any(|item| !valid_identifier(item))
        || policy
            .capabilities
            .iter()
            .any(|item| !valid_identifier(item))
        || policy
            .classifications
            .iter()
            .any(|item| !matches!(item.as_str(), "internal" | "confidential" | "restricted"))
    {
        return Err(ConfigError::Invalid(
            "principal policy violates the trust boundary",
        ));
    }
    Ok(())
}

fn validate_route(route: &ModelRoute) -> Result<(), ConfigError> {
    if !valid_identifier(&route.model_id)
        || !valid_identifier(&route.backend_model)
        || route.max_input_tokens == 0
        || route.max_output_tokens == 0
        || route.max_cost_microusd == 0
    {
        return Err(ConfigError::Invalid(
            "model route violates the Snowman-only boundary",
        ));
    }
    match route.backend_kind.as_str() {
        "private_openai" => {
            let origin = Url::parse(
                route
                    .backend_origin
                    .as_deref()
                    .ok_or(ConfigError::Invalid("private model origin is required"))?,
            )
            .map_err(|_| ConfigError::Invalid("model route origin is malformed"))?;
            let host = origin.host_str().unwrap_or_default();
            let private_http = origin.scheme() == "http"
                && (host.ends_with(".internal") || host.ends_with(".local"));
            let snowman_https = origin.scheme() == "https"
                && (host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
                && origin.port_or_known_default() == Some(443);
            if route.sagemaker_endpoint_name.is_some()
                || route.sagemaker_inference_component_name.is_some()
                || origin.username() != ""
                || origin.password().is_some()
                || !matches!(origin.path(), "" | "/")
                || origin.query().is_some()
                || origin.fragment().is_some()
                || !(private_http || snowman_https)
            {
                return Err(ConfigError::Invalid("private model route is invalid"));
            }
        }
        "sagemaker" => {
            let endpoint = route
                .sagemaker_endpoint_name
                .as_deref()
                .ok_or(ConfigError::Invalid("SageMaker endpoint is required"))?;
            let inference_component =
                route
                    .sagemaker_inference_component_name
                    .as_deref()
                    .ok_or(ConfigError::Invalid(
                        "SageMaker inference component is required",
                    ))?;
            if route.backend_origin.is_some()
                || !valid_sagemaker_name(endpoint)
                || !valid_sagemaker_name(inference_component)
            {
                return Err(ConfigError::Invalid("SageMaker model route is invalid"));
            }
        }
        _ => return Err(ConfigError::Invalid("model backend kind is invalid")),
    }
    Ok(())
}

fn valid_sagemaker_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|value| value.is_ascii_alphanumeric() || *value == b'-')
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, GatewayError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .ok_or(GatewayError::Authentication)
}

fn optional_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, GatewayError> {
    headers
        .get(name)
        .map(|value| value.to_str().map_err(|_| GatewayError::Authentication))
        .transpose()
}

fn valid_database_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.scheme() == "postgres"
        && !url.username().is_empty()
        && url.password().is_some_and(|password| password.len() >= 32)
        && url.host_str().is_some()
        && url.path().len() > 1
        && url.query().is_some_and(|query| {
            query
                .split('&')
                .any(|pair| pair == "sslmode=require" || pair == "sslmode=verify-full")
        })
        && url.fragment().is_none()
}

fn valid_identifier(value: &str) -> bool {
    (3..=200).contains(&value.len())
        && value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_alphanumeric()
                || (index > 0 && matches!(character, '.' | '_' | ':' | '/' | '-'))
        })
        && !value.contains("://")
}

fn valid_nonce(value: &str) -> bool {
    (24..=200).contains(&value.len())
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn valid_kms_key_arn(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 6
        && parts[0] == "arn"
        && parts[1].starts_with("aws")
        && parts[2] == "kms"
        && !parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].chars().all(|character| character.is_ascii_digit())
        && parts[5].starts_with("key/")
        && parts[5].len() == 40
}

fn valid_hmac_key_arn(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 6
        && parts[0] == "arn"
        && parts[1].starts_with("aws")
        && parts[2] == "kms"
        && !parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].chars().all(|character| character.is_ascii_digit())
        && parts[5].starts_with("key/")
        && parts[5].len() > 4
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, GatewayError> {
    serde_json::to_vec(value).map_err(|_| GatewayError::Invalid)
}

fn canonical_sha256(value: &Value) -> Result<String, GatewayError> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn token_cost(tokens: u64, rate: u64) -> Result<u64, GatewayError> {
    let numerator = u128::from(tokens)
        .checked_mul(u128::from(rate))
        .ok_or(GatewayError::Budget)?;
    u64::try_from(numerator.div_ceil(1_000_000)).map_err(|_| GatewayError::Budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    type RequestMutation = Box<dyn Fn(&mut GenerationRequest)>;

    fn model_grant_token() -> String {
        let claims = ModelGrantClaims {
            schema_version: MODEL_GRANT_SCHEMA.into(),
            tenant_id: "20000000-0000-4000-8000-000000000001".parse().unwrap(),
            job_id: "20000000-0000-4000-8000-000000000002".parse().unwrap(),
            task_id: "20000000-0000-4000-8000-000000000003".parse().unwrap(),
            generation: 2,
            model_id: "snowman-research-v1".into(),
            specialist_role: "research_evidence".into(),
            classification: snowman_agent_contract::Classification::Confidential,
            capability_grants: vec!["artifact.draft".into()],
            max_input_tokens: 100_000,
            max_output_tokens: 20_000,
            max_cost_microusd: 50_000,
            minimization_evidence_sha256: "ab".repeat(32),
            expires_at: Utc::now() + chrono::Duration::minutes(30),
        };
        let payload = serde_json::to_vec(&claims).unwrap();
        format!(
            "smg1_{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32])
        )
    }

    fn route(origin: &str) -> ModelRoute {
        ModelRoute {
            model_id: "snowman-delivery-best".into(),
            backend_kind: "private_openai".into(),
            backend_origin: Some(origin.into()),
            sagemaker_endpoint_name: None,
            sagemaker_inference_component_name: None,
            backend_model: "snowman-llama-70b".into(),
            max_input_tokens: 10_000,
            max_output_tokens: 2_000,
            max_cost_microusd: 100_000,
            input_microusd_per_million_tokens: 1_000_000,
            output_microusd_per_million_tokens: 2_000_000,
        }
    }

    fn agent_claims() -> ModelGrantClaims {
        ModelGrantClaims {
            schema_version: MODEL_GRANT_SCHEMA.into(),
            tenant_id: "20000000-0000-4000-8000-000000000001".parse().unwrap(),
            job_id: "20000000-0000-4000-8000-000000000002".parse().unwrap(),
            task_id: "20000000-0000-4000-8000-000000000003".parse().unwrap(),
            generation: 7,
            model_id: "snowman-delivery-best".into(),
            specialist_role: "client_delivery".into(),
            classification: snowman_agent_contract::Classification::Confidential,
            capability_grants: vec!["artifact.build".into(), "artifact.review".into()],
            max_input_tokens: 10_000,
            max_output_tokens: 2_000,
            max_cost_microusd: 100_000,
            minimization_evidence_sha256: "ab".repeat(32),
            expires_at: Utc::now() + chrono::Duration::minutes(30),
        }
    }

    fn agent_request(claims: &ModelGrantClaims) -> GenerationRequest {
        GenerationRequest {
            schema_version: GENERATION_SCHEMA_VERSION.into(),
            generation_id: "20000000-0000-4000-8000-000000000004".into(),
            tenant_id: claims.tenant_id.to_string(),
            client_id: claims.tenant_id.to_string(),
            project_id: claims.tenant_id.to_string(),
            job_id: claims.job_id.to_string(),
            task_id: Some(claims.task_id.to_string()),
            lease_generation: Some(claims.generation),
            minimization_evidence_sha256: Some(claims.minimization_evidence_sha256.clone()),
            correlation_id: "request-123".into(),
            model_id: claims.model_id.clone(),
            specialist_role: claims.specialist_role.clone(),
            capability: claims.capability_grants[0].clone(),
            classification: classification_name(claims.classification).into(),
            content_profile: "governed_artifact_projection".into(),
            instruction: "Create the governed readout.".into(),
            documents: vec![],
            limits: GenerationLimits {
                max_input_tokens: 1_000,
                max_output_tokens: 100,
                max_cost_microusd: 1_200,
            },
            submitted_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
            request_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn routes_allow_only_private_or_snowman_owned_backends() {
        assert!(validate_route(&route("http://vllm.inference.internal:8000")).is_ok());
        assert!(validate_route(&route("https://inference.snowmanai.org")).is_ok());
        for origin in [
            "https://api.openai.com",
            "https://snowmanai.org.evil.example",
            "http://public.example",
            "https://user:secret@inference.snowmanai.org",
            "https://inference.snowmanai.org/v1",
        ] {
            assert!(validate_route(&route(origin)).is_err(), "accepted {origin}");
        }
        let mut sagemaker = route("http://vllm.inference.internal:8000");
        sagemaker.backend_kind = "sagemaker".into();
        sagemaker.backend_origin = None;
        sagemaker.sagemaker_endpoint_name = Some("snowman-staging-delivery".into());
        sagemaker.sagemaker_inference_component_name =
            Some("snowman-staging-delivery-component".into());
        assert!(validate_route(&sagemaker).is_ok());
        sagemaker.backend_origin = Some("https://api.openai.com".into());
        assert!(validate_route(&sagemaker).is_err());
    }

    #[test]
    fn model_grant_is_canonical_bounded_and_scope_complete() {
        let token = model_grant_token();
        let (_, mac, claims) = decode_agent_model_grant(&token).unwrap();
        assert_eq!(mac, vec![7_u8; 32]);
        assert_eq!(claims.model_id, "snowman-research-v1");
        assert_eq!(claims.capability_grants, ["artifact.draft"]);
        assert!(decode_agent_model_grant(&format!("{token}.extra")).is_err());
        assert!(!valid_hmac_key_arn("arn:aws:kms:us-west-2:other:key/key"));
        assert!(valid_hmac_key_arn(
            "arn:aws:kms:us-west-2:123456789012:key/00000000-0000-4000-8000-000000000001"
        ));
    }

    #[test]
    fn token_cost_rounds_up_and_cannot_overflow() {
        assert_eq!(token_cost(1, 1).unwrap(), 1);
        assert_eq!(token_cost(1_000_000, 2_000_000).unwrap(), 2_000_000);
        assert!(token_cost(u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn agent_authority_binds_every_live_scope_and_budget_coordinate() {
        let claims = agent_claims();
        let request = agent_request(&claims);
        let route = route("http://vllm.inference.internal:8000");
        let scope = authorize_agent_request(&request, &route, &claims).unwrap();
        assert_eq!(scope.job_id, claims.job_id);
        assert_eq!(scope.task_id, claims.task_id);
        assert_eq!(scope.lease_generation, claims.generation);

        let mutations: Vec<RequestMutation> = vec![
            Box::new(|value| value.tenant_id = Uuid::new_v4().to_string()),
            Box::new(|value| value.client_id = Uuid::new_v4().to_string()),
            Box::new(|value| value.project_id = Uuid::new_v4().to_string()),
            Box::new(|value| value.job_id = Uuid::new_v4().to_string()),
            Box::new(|value| value.task_id = Some(Uuid::new_v4().to_string())),
            Box::new(|value| value.lease_generation = Some(8)),
            Box::new(|value| value.model_id = "snowman-other-model".into()),
            Box::new(|value| value.specialist_role = "other_role".into()),
            Box::new(|value| value.capability = "artifact.delete".into()),
            Box::new(|value| value.classification = "restricted".into()),
            Box::new(|value| value.minimization_evidence_sha256 = Some("cd".repeat(32))),
            Box::new(|value| value.limits.max_input_tokens = 10_001),
            Box::new(|value| value.limits.max_output_tokens = 2_001),
            Box::new(|value| value.limits.max_cost_microusd = 100_001),
        ];
        for mutate in mutations {
            let mut changed = request.clone();
            mutate(&mut changed);
            assert!(authorize_agent_request(&changed, &route, &claims).is_err());
        }
    }

    #[test]
    fn route_requires_limits_to_cover_worst_case_priced_usage() {
        let route = route("http://vllm.inference.internal:8000");
        let claims = agent_claims();
        let mut request = agent_request(&claims);
        request.limits.max_cost_microusd = 1_199;
        assert_eq!(
            authorize_route(&request, &route).unwrap_err().code(),
            "budget_exceeded"
        );
        request.limits.max_cost_microusd = 1_200;
        assert!(authorize_route(&request, &route).is_ok());
    }

    #[test]
    fn measured_usage_is_exact_and_database_bounded() {
        let backend = BackendResponse {
            choices: vec![],
            usage: BackendUsage {
                prompt_tokens: 4,
                completion_tokens: 3,
            },
        };
        let usage =
            measured_usage(&backend, &route("http://vllm.inference.internal:8000")).unwrap();
        assert_eq!(usage.input_tokens, 4);
        assert_eq!(usage.output_tokens, 3);
        assert_eq!(usage.cost_microusd, 10);
    }

    #[test]
    fn database_configuration_requires_tls_and_a_real_secret() {
        assert!(valid_database_url(
            "postgres://snowman_model_gateway:0123456789abcdef0123456789abcdef@db.internal/snowmancc?sslmode=verify-full"
        ));
        for value in [
            "postgres://role:short@db.internal/snowmancc?sslmode=require",
            "postgres://role:0123456789abcdef0123456789abcdef@db.internal/snowmancc",
            "postgres://role:0123456789abcdef0123456789abcdef@db.internal/?sslmode=require",
            "https://role:0123456789abcdef0123456789abcdef@db.internal/snowmancc?sslmode=require",
        ] {
            assert!(!valid_database_url(value), "accepted {value}");
        }
    }

    #[test]
    fn model_authority_migration_preserves_worst_case_and_append_only_evidence() {
        let sql = include_str!("../../../migrations/0047_snowman_agent_model_authority.sql");
        for fragment in [
            "PRIMARY KEY (community_id, generation_id)",
            "FOREIGN KEY (community_id, job_id)",
            "FOREIGN KEY (community_id, request_id, task_id)",
            "'reserved','succeeded','accounted_rejected','indeterminate','aborted'",
            "accounted_input_tokens = requested_input_tokens",
            "accounted_output_tokens = requested_output_tokens",
            "accounted_cost_microusd = requested_cost_microusd",
            "idx_snowman_agent_model_generations_request_reservations",
        ] {
            assert!(
                sql.contains(fragment),
                "missing database contract: {fragment}"
            );
        }
        assert!(!sql.contains("prompt"));
        assert!(!sql.contains("output_content"));
        assert!(!sql.contains("provider_credential"));
    }

    #[test]
    fn only_inference_unavailability_is_retryable() {
        assert_eq!(
            GatewayError::Inference.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(GatewayError::Inference.retryable());
        assert_eq!(GatewayError::Inference.retry_after_seconds(), Some("60"));
        for error in [
            GatewayError::Invalid,
            GatewayError::Authentication,
            GatewayError::Authorization,
            GatewayError::Replay,
            GatewayError::Budget,
        ] {
            assert!(!error.retryable());
            assert_eq!(error.retry_after_seconds(), None);
        }
    }

    #[test]
    fn response_is_scope_bound_and_canonically_digested() {
        let request = GenerationRequest {
            schema_version: GENERATION_SCHEMA_VERSION.into(),
            generation_id: "gen_12345678901234567890123456789012".into(),
            tenant_id: "aptive".into(),
            client_id: "aptive".into(),
            project_id: "aptive-prod".into(),
            job_id: "cc_job_123".into(),
            task_id: None,
            lease_generation: None,
            minimization_evidence_sha256: None,
            correlation_id: "request-123".into(),
            model_id: "snowman-delivery-best".into(),
            specialist_role: "client_delivery".into(),
            capability: "artifact.build".into(),
            classification: "confidential".into(),
            content_profile: "governed_artifact_projection".into(),
            instruction: "Create the governed readout.".into(),
            documents: vec![],
            limits: GenerationLimits {
                max_input_tokens: 100,
                max_output_tokens: 100,
                max_cost_microusd: 100,
            },
            submitted_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
            request_sha256: "a".repeat(64),
        };
        let backend = BackendResponse {
            choices: vec![BackendChoice {
                message: BackendMessage {
                    content: "Result".into(),
                },
                finish_reason: "stop".into(),
            }],
            usage: BackendUsage {
                prompt_tokens: 1,
                completion_tokens: 1,
            },
        };
        let value = build_response(
            &request,
            &route("http://vllm.inference.internal:8000"),
            &backend,
        )
        .unwrap();
        let claimed = value["response_sha256"].as_str().unwrap().to_string();
        let mut unsigned = value.as_object().unwrap().clone();
        unsigned.remove("response_sha256");
        assert_eq!(claimed, canonical_sha256(&Value::Object(unsigned)).unwrap());
    }
}
