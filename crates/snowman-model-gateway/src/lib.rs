#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Private, deny-by-default inference boundary for Snowman workforce agents.
//!
//! The gateway authenticates exact KMS-signed Analyst 360 requests, consumes
//! nonces in Redis, re-evaluates tenant/model/capability/classification and
//! budget policy, and calls only a configured private Snowman inference
//! backend. It never accepts an endpoint, credential, or arbitrary tool from a
//! caller and it does not persist prompts or model output.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
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
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;

/// Exact generation route exposed behind the private Snowman load balancer.
pub const GENERATION_PATH: &str = "/internal/snowman/v1/model-generations";
/// Versioned generation contract.
pub const GENERATION_SCHEMA_VERSION: &str = "snowman.model-generation.v1";
const ASSERTION_VERSION: &str = "snowman.service-request.v1";
const OPERATION: &str = "models.generate";
const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_ASSERTION_AGE_SECONDS: i64 = 90;
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;

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
#[derive(Debug, Clone)]
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
        {
            return Err(ConfigError::Invalid("bind address or timeout is invalid"));
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
    match redis::cmd("PING").query_async::<String>(&mut redis).await {
        Ok(reply) if reply == "PONG" => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn generate(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    match execute_generation(&state, &headers, &body).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => {
            tracing::warn!(code = error.code(), "model generation rejected");
            (
                error.status(),
                Json(json!({"error": {"code": error.code()}})),
            )
                .into_response()
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
            Self::Budget => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Inference => StatusCode::BAD_GATEWAY,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationRequest {
    schema_version: String,
    generation_id: String,
    tenant_id: String,
    client_id: String,
    project_id: String,
    job_id: String,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationDocument {
    artifact_ref: ArtifactReference,
    content: String,
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Deserialize)]
struct BackendResponse {
    choices: Vec<BackendChoice>,
    usage: BackendUsage,
}

#[derive(Deserialize)]
struct BackendChoice {
    message: BackendMessage,
    finish_reason: String,
}

#[derive(Deserialize)]
struct BackendMessage {
    content: String,
}

#[derive(Deserialize)]
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
    build_response(request, route, backend)
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
    if request.limits.max_input_tokens > route.max_input_tokens
        || request.limits.max_output_tokens > route.max_output_tokens
        || request.limits.max_cost_microusd > route.max_cost_microusd
    {
        return Err(GatewayError::Budget);
    }
    Ok(())
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
    let output = state
        .sagemaker
        .invoke_endpoint()
        .endpoint_name(endpoint_name)
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
    request: GenerationRequest,
    route: &ModelRoute,
    backend: BackendResponse,
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
        generation_id: request.generation_id,
        tenant_id: request.tenant_id,
        client_id: request.client_id,
        project_id: request.project_id,
        job_id: request.job_id,
        correlation_id: request.correlation_id,
        model_id: request.model_id,
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
        request_sha256: request.request_sha256,
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
            if route.backend_origin.is_some() || !valid_sagemaker_endpoint_name(endpoint) {
                return Err(ConfigError::Invalid("SageMaker model route is invalid"));
            }
        }
        _ => return Err(ConfigError::Invalid("model backend kind is invalid")),
    }
    Ok(())
}

fn valid_sagemaker_endpoint_name(value: &str) -> bool {
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

    fn route(origin: &str) -> ModelRoute {
        ModelRoute {
            model_id: "snowman-delivery-best".into(),
            backend_kind: "private_openai".into(),
            backend_origin: Some(origin.into()),
            sagemaker_endpoint_name: None,
            backend_model: "snowman-llama-70b".into(),
            max_input_tokens: 10_000,
            max_output_tokens: 2_000,
            max_cost_microusd: 100_000,
            input_microusd_per_million_tokens: 1_000_000,
            output_microusd_per_million_tokens: 2_000_000,
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
        assert!(validate_route(&sagemaker).is_ok());
        sagemaker.backend_origin = Some("https://api.openai.com".into());
        assert!(validate_route(&sagemaker).is_err());
    }

    #[test]
    fn token_cost_rounds_up_and_cannot_overflow() {
        assert_eq!(token_cost(1, 1).unwrap(), 1);
        assert_eq!(token_cost(1_000_000, 2_000_000).unwrap(), 2_000_000);
        assert!(token_cost(u64::MAX, u64::MAX).is_err());
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
            request,
            &route("http://vllm.inference.internal:8000"),
            backend,
        )
        .unwrap();
        let claimed = value["response_sha256"].as_str().unwrap().to_string();
        let mut unsigned = value.as_object().unwrap().clone();
        unsigned.remove("response_sha256");
        assert_eq!(claimed, canonical_sha256(&Value::Object(unsigned)).unwrap());
    }
}
