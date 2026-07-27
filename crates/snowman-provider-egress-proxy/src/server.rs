//! Private production runtime adapters for the provider-egress core.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ClaimOutcome, HttpMethod, Provider, ProviderTransport, Proxy, ProxyError, Receipt,
    ReceiptStatus, RequestEnvelope, RequestFence, Resolver, RoutePolicy, SecretReference,
    SignatureVerifier, SignedRequest, TransportRequest, TransportResponse, MAX_REQUEST_BYTES,
};

const MAX_WIRE_BYTES: usize = 12 * 1024 * 1024;
const CANCEL_SCHEMA: &str = "snowman.provider-egress.cancel.v1";

/// Runtime configuration loaded from non-secret task metadata and dedicated secrets.
pub struct Config {
    bind_addr: SocketAddr,
    database_url: String,
    database_role: String,
    aws_account_id: String,
    policy: RuntimePolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimePolicy {
    policy_generation: u64,
    max_concurrency: usize,
    principals: Vec<PrincipalPolicy>,
    routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalPolicy {
    principal_id: String,
    kms_key_arn: String,
    tenant_ids: BTreeSet<Uuid>,
    capabilities: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteConfig {
    destination_id: String,
    provider: Provider,
    endpoint: String,
    method: String,
    secret_arn: String,
    secret_json_key: String,
    principal_ids: BTreeSet<String>,
    tenant_ids: BTreeSet<Uuid>,
    purposes: BTreeSet<String>,
    classifications: BTreeSet<String>,
    request_content_types: BTreeSet<String>,
    response_content_types: BTreeSet<String>,
    max_budget_microusd: u64,
    max_request_bytes: usize,
    max_response_bytes: usize,
    timeout_seconds: u64,
}

/// Non-sensitive startup failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Static configuration is invalid.
    #[error("Snowman provider-egress configuration is invalid")]
    Invalid,
    /// Dedicated persistence identity is unavailable or over-privileged.
    #[error("Snowman provider-egress database authority is unavailable")]
    Database,
}

impl Config {
    /// Load exact operations-owned configuration. No provider credential is accepted here.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = env("SNOWMAN_PROVIDER_EGRESS_BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8443".into())
            .parse()
            .map_err(|_| ConfigError::Invalid)?;
        let database_url = required("SNOWMAN_PROVIDER_EGRESS_DATABASE_URL")?;
        let database_role = required("SNOWMAN_PROVIDER_EGRESS_DATABASE_ROLE")?;
        let aws_account_id = required("SNOWMAN_PROVIDER_EGRESS_AWS_ACCOUNT_ID")?;
        let policy: RuntimePolicy =
            serde_json::from_str(&required("SNOWMAN_PROVIDER_EGRESS_POLICY_JSON")?)
                .map_err(|_| ConfigError::Invalid)?;
        if env("SNOWMAN_PROVIDER_EGRESS_NETWORK_POLICY").as_deref()
            != Some("private-snowman-provider-only")
            || !valid_database_url(&database_url)
            || !valid_identifier(&database_role)
            || aws_account_id.len() != 12
            || !aws_account_id.bytes().all(|byte| byte.is_ascii_digit())
            || policy.principals.is_empty()
        {
            return Err(ConfigError::Invalid);
        }
        Ok(Self {
            bind_addr,
            database_url,
            database_role,
            aws_account_id,
            policy,
        })
    }
}

/// Shared private HTTP state.
#[derive(Clone)]
pub struct AppState {
    proxy: Arc<Proxy>,
    verifier: Arc<KmsWorkloadVerifier>,
    fence: Arc<PostgresFence>,
    pool: PgPool,
    bind_addr: SocketAddr,
    metrics: Arc<Metrics>,
}

impl AppState {
    /// Build live AWS, PostgreSQL, DNS, and direct-transport adapters.
    pub async fn new(config: Config) -> Result<Self, ConfigError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&config.database_url)
            .await
            .map_err(|_| ConfigError::Database)?;
        verify_database_role(&pool, &config.database_role)
            .await
            .map_err(|_| ConfigError::Database)?;
        let sdk = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let verifier = Arc::new(KmsWorkloadVerifier::new(
            aws_sdk_kms::Client::new(&sdk),
            config.policy.principals,
            &config.aws_account_id,
        )?);
        let routes = config
            .policy
            .routes
            .into_iter()
            .map(|route| route.into_policy(&config.aws_account_id))
            .collect::<Result<Vec<_>, _>>()?;
        if routes.iter().any(|route| {
            route.principal_ids.iter().any(|principal| {
                route.tenant_ids.iter().any(|tenant| {
                    !verifier.authorizes(principal, *tenant, "provider_egress.dispatch")
                })
            })
        }) {
            return Err(ConfigError::Invalid);
        }
        let fence = Arc::new(PostgresFence::new(pool.clone()));
        let proxy = Arc::new(
            Proxy::new(
                config.policy.policy_generation,
                routes,
                config.policy.max_concurrency,
                verifier.clone(),
                Arc::new(TokioResolver),
                Arc::new(AwsDirectTransport::new(
                    aws_sdk_secretsmanager::Client::new(&sdk),
                )),
                fence.clone(),
            )
            .map_err(|_| ConfigError::Invalid)?,
        );
        Ok(Self {
            proxy,
            verifier,
            fence,
            pool,
            bind_addr: config.bind_addr,
            metrics: Arc::new(Metrics::default()),
        })
    }

    /// Private listener address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

impl RouteConfig {
    fn into_policy(self, account_id: &str) -> Result<RoutePolicy, ConfigError> {
        if !same_account_secret_arn(&self.secret_arn, account_id) {
            return Err(ConfigError::Invalid);
        }
        let method = match self.method.as_str() {
            "GET" => HttpMethod::Get,
            "POST" => HttpMethod::Post,
            "DELETE" => HttpMethod::Delete,
            _ => return Err(ConfigError::Invalid),
        };
        Ok(RoutePolicy {
            destination_id: self.destination_id,
            provider: self.provider,
            endpoint: Url::parse(&self.endpoint).map_err(|_| ConfigError::Invalid)?,
            method,
            secret: SecretReference {
                arn: self.secret_arn,
                json_key: self.secret_json_key,
            },
            principal_ids: self.principal_ids,
            tenant_ids: self.tenant_ids,
            purposes: self.purposes,
            classifications: self.classifications,
            request_content_types: self.request_content_types,
            response_content_types: self.response_content_types,
            max_budget_microusd: self.max_budget_microusd,
            max_request_bytes: self.max_request_bytes,
            max_response_bytes: self.max_response_bytes,
            timeout: Duration::from_secs(self.timeout_seconds),
        })
    }
}

/// Build private health, dispatch, cancellation, and bounded metrics routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/_liveness", get(|| async { StatusCode::NO_CONTENT }))
        .route("/_readiness", get(readiness))
        .route("/metrics", get(metrics))
        .route("/v1/tenants/{tenant_id}/dispatch", post(dispatch))
        .route(
            "/v1/tenants/{tenant_id}/sessions/{session_id}/generations/{generation}/cancel",
            post(cancel),
        )
        .layer(RequestBodyLimitLayer::new(MAX_WIRE_BYTES))
        .with_state(state)
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    envelope: RequestEnvelope,
    payload_base64: String,
    signature_base64: String,
}

#[derive(Debug, Serialize)]
struct WireResponse {
    receipt: Receipt,
    response_base64: Option<String>,
    response_content_type: Option<String>,
    replayed: bool,
}

async fn dispatch(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    Json(wire): Json<WireRequest>,
) -> Result<Json<WireResponse>, ApiError> {
    if wire.envelope.tenant_id != tenant_id
        || wire.payload_base64.len() > encoded_limit(MAX_REQUEST_BYTES)
        || wire.signature_base64.len() > 2048
    {
        state.metrics.denied.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError(ProxyError::InvalidRequest));
    }
    let payload = STANDARD
        .decode(wire.payload_base64)
        .map_err(|_| ApiError(ProxyError::InvalidRequest))?;
    let signature = STANDARD
        .decode(wire.signature_base64)
        .map_err(|_| ApiError(ProxyError::Authentication))?;
    let result = state
        .proxy
        .execute(SignedRequest {
            envelope: wire.envelope,
            payload,
            signature,
        })
        .await
        .map_err(|error| {
            state.metrics.denied.fetch_add(1, Ordering::Relaxed);
            ApiError(error)
        })?;
    state.metrics.accepted.fetch_add(1, Ordering::Relaxed);
    if result.replayed {
        state.metrics.replayed.fetch_add(1, Ordering::Relaxed);
    }
    if result.receipt.status == ReceiptStatus::Indeterminate {
        state.metrics.indeterminate.fetch_add(1, Ordering::Relaxed);
    }
    Ok(Json(WireResponse {
        receipt: result.receipt,
        response_base64: result.response.map(|body| STANDARD.encode(body)),
        response_content_type: result.response_content_type,
        replayed: result.replayed,
    }))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CancelEnvelope {
    schema_version: String,
    tenant_id: Uuid,
    session_id: Uuid,
    generation: u64,
    principal_id: String,
    reason_sha256: String,
    issued_at: DateTime<Utc>,
    deadline: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelRequest {
    envelope: CancelEnvelope,
    signature_base64: String,
}

async fn cancel(
    State(state): State<AppState>,
    Path((tenant_id, session_id, generation)): Path<(Uuid, Uuid, u64)>,
    Json(request): Json<CancelRequest>,
) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let envelope = &request.envelope;
    if envelope.schema_version != CANCEL_SCHEMA
        || envelope.tenant_id != tenant_id
        || envelope.session_id != session_id
        || envelope.generation != generation
        || generation == 0
        || !is_sha256(&envelope.reason_sha256)
        || envelope.issued_at < now - chrono::Duration::seconds(60)
        || envelope.issued_at > now + chrono::Duration::seconds(10)
        || envelope.deadline <= now
        || envelope.deadline > now + chrono::Duration::seconds(120)
        || !state
            .verifier
            .authorizes(&envelope.principal_id, tenant_id, "provider_egress.cancel")
    {
        return Err(ApiError(ProxyError::InvalidRequest));
    }
    let canonical =
        serde_json::to_vec(envelope).map_err(|_| ApiError(ProxyError::InvalidRequest))?;
    let signature = STANDARD
        .decode(&request.signature_base64)
        .map_err(|_| ApiError(ProxyError::Authentication))?;
    state
        .verifier
        .verify(&envelope.principal_id, &canonical, &signature)
        .await
        .map_err(ApiError)?;
    state
        .fence
        .cancel(
            tenant_id,
            session_id,
            generation,
            &envelope.principal_id,
            &envelope.reason_sha256,
        )
        .await
        .map_err(ApiError)?;
    state.metrics.cancelled.fetch_add(1, Ordering::Relaxed);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Default)]
struct Metrics {
    accepted: AtomicU64,
    denied: AtomicU64,
    replayed: AtomicU64,
    indeterminate: AtomicU64,
    cancelled: AtomicU64,
}

async fn metrics(State(state): State<AppState>) -> Response {
    let body = format!(
        "# TYPE snowman_provider_egress_requests_total counter\n\
snowman_provider_egress_requests_total{{outcome=\"accepted\"}} {}\n\
snowman_provider_egress_requests_total{{outcome=\"denied\"}} {}\n\
snowman_provider_egress_requests_total{{outcome=\"replayed\"}} {}\n\
snowman_provider_egress_requests_total{{outcome=\"indeterminate\"}} {}\n\
snowman_provider_egress_cancellations_total {}\n",
        state.metrics.accepted.load(Ordering::Relaxed),
        state.metrics.denied.load(Ordering::Relaxed),
        state.metrics.replayed.load(Ordering::Relaxed),
        state.metrics.indeterminate.load(Ordering::Relaxed),
        state.metrics.cancelled.load(Ordering::Relaxed),
    );
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response()
}

struct ApiError(ProxyError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            ProxyError::InvalidRequest => StatusCode::BAD_REQUEST,
            ProxyError::Authentication => StatusCode::UNAUTHORIZED,
            ProxyError::PolicyDenied | ProxyError::ResolutionDenied => StatusCode::FORBIDDEN,
            ProxyError::ReplayConflict => StatusCode::CONFLICT,
            ProxyError::TransportDenied => StatusCode::BAD_GATEWAY,
            ProxyError::AuthorityUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, "provider egress request failed").into_response()
    }
}

struct KmsWorkloadVerifier {
    client: aws_sdk_kms::Client,
    principals: BTreeMap<String, PrincipalPolicy>,
}

impl KmsWorkloadVerifier {
    fn new(
        client: aws_sdk_kms::Client,
        principals: Vec<PrincipalPolicy>,
        account_id: &str,
    ) -> Result<Self, ConfigError> {
        let mut indexed = BTreeMap::new();
        for principal in principals {
            if !valid_identifier(&principal.principal_id)
                || principal.tenant_ids.is_empty()
                || principal.capabilities.is_empty()
                || principal.capabilities.iter().any(|capability| {
                    !matches!(
                        capability.as_str(),
                        "provider_egress.dispatch" | "provider_egress.cancel"
                    )
                })
                || !same_account_kms_arn(&principal.kms_key_arn, account_id)
                || indexed
                    .insert(principal.principal_id.clone(), principal)
                    .is_some()
            {
                return Err(ConfigError::Invalid);
            }
        }
        Ok(Self {
            client,
            principals: indexed,
        })
    }

    fn authorizes(&self, principal_id: &str, tenant_id: Uuid, capability: &str) -> bool {
        self.principals.get(principal_id).is_some_and(|principal| {
            principal.tenant_ids.contains(&tenant_id) && principal.capabilities.contains(capability)
        })
    }
}

#[async_trait]
impl SignatureVerifier for KmsWorkloadVerifier {
    async fn verify(
        &self,
        principal_id: &str,
        canonical: &[u8],
        signature: &[u8],
    ) -> Result<(), ProxyError> {
        let principal = self
            .principals
            .get(principal_id)
            .ok_or(ProxyError::Authentication)?;
        if !(128..=1024).contains(&signature.len()) {
            return Err(ProxyError::Authentication);
        }
        let output = self
            .client
            .verify()
            .key_id(&principal.kms_key_arn)
            .message(Blob::new(canonical))
            .message_type(MessageType::Raw)
            .signature(Blob::new(signature))
            .signing_algorithm(SigningAlgorithmSpec::RsassaPssSha256)
            .send()
            .await
            .map_err(|_| ProxyError::Authentication)?;
        if output.signature_valid() {
            Ok(())
        } else {
            Err(ProxyError::Authentication)
        }
    }
}

struct TokioResolver;

#[async_trait]
impl Resolver for TokioResolver {
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, ProxyError> {
        let absolute_name = format!("{hostname}.");
        let mut addresses = tokio::net::lookup_host((absolute_name.as_str(), 443))
            .await
            .map_err(|_| ProxyError::ResolutionDenied)?
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        Ok(addresses)
    }
}

struct AwsDirectTransport {
    secrets: aws_sdk_secretsmanager::Client,
}

impl AwsDirectTransport {
    fn new(secrets: aws_sdk_secretsmanager::Client) -> Self {
        Self { secrets }
    }
}

#[async_trait]
impl ProviderTransport for AwsDirectTransport {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, ProxyError> {
        let secret_output = self
            .secrets
            .get_secret_value()
            .secret_id(&request.secret.arn)
            .send()
            .await
            .map_err(|_| ProxyError::AuthorityUnavailable)?;
        let secret_document = secret_output
            .secret_string()
            .ok_or(ProxyError::AuthorityUnavailable)?;
        let mut parsed: Value =
            serde_json::from_str(secret_document).map_err(|_| ProxyError::AuthorityUnavailable)?;
        let credential = parsed
            .get(&request.secret.json_key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 8192)
            .map(|value| Zeroizing::new(value.to_owned()))
            .ok_or(ProxyError::AuthorityUnavailable)?;
        scrub_json_strings(&mut parsed);
        drop(secret_output);

        let pinned = request
            .resolved_ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, 443))
            .collect::<Vec<_>>();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .resolve_to_addrs(&request.tls_server_name, &pinned)
            .build()
            .map_err(|_| ProxyError::TransportDenied)?;
        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Delete => reqwest::Method::DELETE,
        };
        let mut outbound = client
            .request(method, request.endpoint)
            .header(header::CONTENT_TYPE, &request.content_type)
            .header("idempotency-key", request.idempotency_key.to_string())
            .body(request.body);
        outbound = match request.provider {
            Provider::OpenAi => outbound.bearer_auth(credential.as_str()),
            Provider::Twilio => outbound.header(header::AUTHORIZATION, credential.as_str()),
            Provider::ElevenLabs => outbound.header("xi-api-key", credential.as_str()),
        };
        let mut response = outbound
            .send()
            .await
            .map_err(|_| ProxyError::TransportDenied)?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();
        if response
            .content_length()
            .is_some_and(|size| size > request.max_response_bytes as u64)
        {
            return Err(ProxyError::TransportDenied);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ProxyError::TransportDenied)?
        {
            if body.len().saturating_add(chunk.len()) > request.max_response_bytes {
                return Err(ProxyError::TransportDenied);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(TransportResponse {
            status,
            content_type,
            body,
        })
    }
}

struct PostgresFence {
    pool: PgPool,
}

impl PostgresFence {
    fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn tenant_tx(&self, tenant_id: Uuid) -> Result<Transaction<'_, Postgres>, ProxyError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| ProxyError::AuthorityUnavailable)?;
        sqlx::query("SELECT set_config('snowman.tenant_id', $1, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|_| ProxyError::AuthorityUnavailable)?;
        Ok(tx)
    }

    async fn cancel(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u64,
        principal_id: &str,
        reason_sha256: &str,
    ) -> Result<(), ProxyError> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let live_generation: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM snowman_meeting_media_sessions \
             WHERE community_id=$1 AND media_session_id=$2 AND session_generation=$3 \
             AND status IN ('joining','indeterminate','active','stopping'))",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(i64::try_from(generation).map_err(|_| ProxyError::InvalidRequest)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ProxyError::AuthorityUnavailable)?;
        if !live_generation {
            return Err(ProxyError::PolicyDenied);
        }
        sqlx::query(
            "INSERT INTO snowman_provider_egress_cancellations \
             (community_id,session_id,generation,principal_id,reason_sha256) \
             VALUES ($1,$2,$3,$4,decode($5,'hex')) ON CONFLICT DO NOTHING",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(i64::try_from(generation).map_err(|_| ProxyError::InvalidRequest)?)
        .bind(principal_id)
        .bind(reason_sha256)
        .execute(&mut *tx)
        .await
        .map_err(|_| ProxyError::AuthorityUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| ProxyError::AuthorityUnavailable)
    }

    async fn persist(&self, receipt: &Receipt, transition: &str) -> Result<(), ProxyError> {
        let mut tx = self.tenant_tx(receipt.tenant_id).await?;
        let status = status_name(receipt.status);
        let response_digest = if receipt.status == ReceiptStatus::Succeeded {
            Some(&receipt.response_sha256)
        } else {
            None
        };
        let rows = sqlx::query(
            "UPDATE snowman_provider_egress_requests SET status=$3, \
             response_sha256=CASE WHEN $4::TEXT IS NULL THEN NULL ELSE decode($4,'hex') END, \
             response_bytes=$5,completed_at=$6 \
             WHERE community_id=$1 AND request_id=$2 AND request_sha256=decode($7,'hex') \
             AND status IN ('claimed','indeterminate')",
        )
        .bind(receipt.tenant_id)
        .bind(receipt.request_id)
        .bind(status)
        .bind(response_digest)
        .bind(i64::try_from(receipt.response_bytes).map_err(|_| ProxyError::InvalidRequest)?)
        .bind(receipt.completed_at)
        .bind(&receipt.request_sha256)
        .execute(&mut *tx)
        .await
        .map_err(|_| ProxyError::AuthorityUnavailable)?
        .rows_affected();
        if rows != 1 {
            return Err(ProxyError::AuthorityUnavailable);
        }
        let digest = receipt_digest(receipt)?;
        sqlx::query(
            "INSERT INTO snowman_provider_egress_receipt_events \
             (community_id,request_id,transition,receipt_sha256,status) \
             VALUES ($1,$2,$3,decode($4,'hex'),$5) ON CONFLICT DO NOTHING",
        )
        .bind(receipt.tenant_id)
        .bind(receipt.request_id)
        .bind(transition)
        .bind(digest)
        .bind(status)
        .execute(&mut *tx)
        .await
        .map_err(|_| ProxyError::AuthorityUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| ProxyError::AuthorityUnavailable)
    }
}

#[async_trait]
impl RequestFence for PostgresFence {
    async fn claim(
        &self,
        envelope: &RequestEnvelope,
        request_sha256: &str,
    ) -> Result<ClaimOutcome, ProxyError> {
        let tenant_id = envelope.tenant_id;
        let request_id = envelope.request_id;
        let session_id = envelope.session_id;
        let generation = envelope.generation;
        let mut tx = self.tenant_tx(tenant_id).await?;
        let live_generation: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM snowman_meeting_media_sessions \
             WHERE community_id=$1 AND media_session_id=$2 AND session_generation=$3 \
             AND status IN ('joining','indeterminate','active','stopping'))",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(i64::try_from(generation).map_err(|_| ProxyError::InvalidRequest)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ProxyError::AuthorityUnavailable)?;
        if !live_generation {
            return Err(ProxyError::PolicyDenied);
        }
        let cancelled: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM snowman_provider_egress_cancellations \
             WHERE community_id=$1 AND session_id=$2 AND generation=$3)",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(i64::try_from(generation).map_err(|_| ProxyError::InvalidRequest)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ProxyError::AuthorityUnavailable)?;
        let inserted = sqlx::query(
            "INSERT INTO snowman_provider_egress_requests \
             (community_id,request_id,session_id,generation,request_sha256,provider,purpose,classification,budget_microusd,policy_generation,destination_id,status,deadline) \
             VALUES ($1,$2,$3,$4,decode($5,'hex'),$6,$7,$8,$9,$10,$11,'claimed',$12) \
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant_id)
        .bind(request_id)
        .bind(session_id)
        .bind(i64::try_from(generation).map_err(|_| ProxyError::InvalidRequest)?)
        .bind(request_sha256)
        .bind(provider_name(envelope.provider))
        .bind(&envelope.purpose)
        .bind(&envelope.classification)
        .bind(i64::try_from(envelope.budget_microusd).map_err(|_| ProxyError::InvalidRequest)?)
        .bind(i64::try_from(envelope.policy_generation).map_err(|_| ProxyError::InvalidRequest)?)
        .bind(&envelope.destination_id)
        .bind(envelope.deadline)
        .execute(&mut *tx)
        .await
        .map_err(|_| ProxyError::AuthorityUnavailable)?
        .rows_affected();
        if inserted == 1 {
            tx.commit()
                .await
                .map_err(|_| ProxyError::AuthorityUnavailable)?;
            return Ok(if cancelled {
                ClaimOutcome::Cancelled
            } else {
                ClaimOutcome::Claimed
            });
        }
        let row = sqlx::query(
            "SELECT encode(request_sha256,'hex') digest,status,session_id,generation, \
             provider,purpose,classification,budget_microusd,policy_generation,destination_id, \
             COALESCE(encode(response_sha256,'hex'),repeat('0',64)) response_sha256, \
             response_bytes,completed_at FROM snowman_provider_egress_requests \
             WHERE community_id=$1 AND request_id=$2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(request_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ProxyError::AuthorityUnavailable)?;
        if row.try_get::<String, _>("digest").ok().as_deref() != Some(request_sha256) {
            return Ok(ClaimOutcome::Conflict);
        }
        let status: String = row
            .try_get("status")
            .map_err(|_| ProxyError::AuthorityUnavailable)?;
        if status == "claimed" {
            if cancelled {
                tx.commit()
                    .await
                    .map_err(|_| ProxyError::AuthorityUnavailable)?;
                return Ok(ClaimOutcome::Cancelled);
            }
            return Err(ProxyError::AuthorityUnavailable);
        }
        let receipt = row_to_receipt(tenant_id, request_id, request_sha256, &row)?;
        tx.commit()
            .await
            .map_err(|_| ProxyError::AuthorityUnavailable)?;
        Ok(ClaimOutcome::Duplicate(Box::new(receipt)))
    }

    async fn is_cancelled(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u64,
    ) -> Result<bool, ProxyError> {
        let mut tx = self.tenant_tx(tenant_id).await?;
        let cancelled = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM snowman_provider_egress_cancellations \
             WHERE community_id=$1 AND session_id=$2 AND generation=$3)",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(i64::try_from(generation).map_err(|_| ProxyError::InvalidRequest)?)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ProxyError::AuthorityUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| ProxyError::AuthorityUnavailable)?;
        Ok(cancelled)
    }

    async fn wait_cancelled(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u64,
    ) -> Result<(), ProxyError> {
        loop {
            if self.is_cancelled(tenant_id, session_id, generation).await? {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn mark_dispatched(&self, receipt: &Receipt) -> Result<(), ProxyError> {
        self.persist(receipt, "dispatched").await
    }

    async fn complete(&self, receipt: &Receipt) -> Result<(), ProxyError> {
        self.persist(receipt, "completed").await
    }
}

fn row_to_receipt(
    tenant_id: Uuid,
    request_id: Uuid,
    request_sha256: &str,
    row: &sqlx::postgres::PgRow,
) -> Result<Receipt, ProxyError> {
    let provider = match row.try_get::<String, _>("provider").ok().as_deref() {
        Some("twilio") => Provider::Twilio,
        Some("open_ai") => Provider::OpenAi,
        Some("eleven_labs") => Provider::ElevenLabs,
        _ => return Err(ProxyError::AuthorityUnavailable),
    };
    let status_name: String = row
        .try_get("status")
        .map_err(|_| ProxyError::AuthorityUnavailable)?;
    Ok(Receipt {
        schema_version: crate::RECEIPT_SCHEMA.into(),
        request_id,
        tenant_id,
        session_id: row
            .try_get("session_id")
            .map_err(|_| ProxyError::AuthorityUnavailable)?,
        generation: u64::try_from(
            row.try_get::<i64, _>("generation")
                .map_err(|_| ProxyError::AuthorityUnavailable)?,
        )
        .map_err(|_| ProxyError::AuthorityUnavailable)?,
        provider,
        purpose: row
            .try_get("purpose")
            .map_err(|_| ProxyError::AuthorityUnavailable)?,
        classification: row
            .try_get("classification")
            .map_err(|_| ProxyError::AuthorityUnavailable)?,
        budget_microusd: u64::try_from(
            row.try_get::<i64, _>("budget_microusd")
                .map_err(|_| ProxyError::AuthorityUnavailable)?,
        )
        .map_err(|_| ProxyError::AuthorityUnavailable)?,
        policy_generation: u64::try_from(
            row.try_get::<i64, _>("policy_generation")
                .map_err(|_| ProxyError::AuthorityUnavailable)?,
        )
        .map_err(|_| ProxyError::AuthorityUnavailable)?,
        destination_id: row
            .try_get("destination_id")
            .map_err(|_| ProxyError::AuthorityUnavailable)?,
        request_sha256: request_sha256.into(),
        response_sha256: row
            .try_get("response_sha256")
            .map_err(|_| ProxyError::AuthorityUnavailable)?,
        response_bytes: usize::try_from(
            row.try_get::<i64, _>("response_bytes")
                .map_err(|_| ProxyError::AuthorityUnavailable)?,
        )
        .map_err(|_| ProxyError::AuthorityUnavailable)?,
        status: parse_status(&status_name)?,
        completed_at: row
            .try_get("completed_at")
            .map_err(|_| ProxyError::AuthorityUnavailable)?,
    })
}

fn status_name(status: ReceiptStatus) -> &'static str {
    match status {
        ReceiptStatus::Succeeded => "succeeded",
        ReceiptStatus::ProviderRejected => "provider_rejected",
        ReceiptStatus::Cancelled => "cancelled",
        ReceiptStatus::Expired => "expired",
        ReceiptStatus::PreDispatchDenied => "pre_dispatch_denied",
        ReceiptStatus::Indeterminate => "indeterminate",
    }
}

fn provider_name(provider: Provider) -> &'static str {
    match provider {
        Provider::Twilio => "twilio",
        Provider::OpenAi => "open_ai",
        Provider::ElevenLabs => "eleven_labs",
    }
}

fn parse_status(status: &str) -> Result<ReceiptStatus, ProxyError> {
    match status {
        "succeeded" => Ok(ReceiptStatus::Succeeded),
        "provider_rejected" => Ok(ReceiptStatus::ProviderRejected),
        "cancelled" => Ok(ReceiptStatus::Cancelled),
        "expired" => Ok(ReceiptStatus::Expired),
        "pre_dispatch_denied" => Ok(ReceiptStatus::PreDispatchDenied),
        "indeterminate" => Ok(ReceiptStatus::Indeterminate),
        _ => Err(ProxyError::AuthorityUnavailable),
    }
}

fn receipt_digest(receipt: &Receipt) -> Result<String, ProxyError> {
    serde_json::to_vec(receipt)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|_| ProxyError::AuthorityUnavailable)
}

async fn verify_database_role(pool: &PgPool, expected: &str) -> Result<(), ()> {
    let valid: bool = sqlx::query_scalar(
        "SELECT current_user=$1 AND NOT usesuper AND NOT usecreatedb AND NOT usecreaterole \
         AND NOT has_schema_privilege(current_user,'public','CREATE') \
         AND has_schema_privilege(current_user,'public','USAGE') \
         AND has_table_privilege(current_user,'snowman_provider_egress_cancellations','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_provider_egress_cancellations','UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_provider_egress_requests','SELECT,INSERT,UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_provider_egress_requests','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_provider_egress_receipt_events','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_provider_egress_receipt_events','UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_sessions','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_sessions','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'events','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'audit_log','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') \
         FROM pg_user WHERE usename=current_user",
    )
    .bind(expected)
    .fetch_one(pool)
    .await
    .map_err(|_| ())?;
    if valid {
        Ok(())
    } else {
        Err(())
    }
}

fn scrub_json_strings(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(scrub_json_strings),
        Value::Object(values) => values.values_mut().for_each(scrub_json_strings),
        _ => {}
    }
}

fn same_account_kms_arn(value: &str, account_id: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts[0] == "arn"
        && parts[2] == "kms"
        && parts[4] == account_id
        && parts[5].starts_with("key/")
        && !value.contains('*')
}

fn same_account_secret_arn(value: &str, account_id: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 7
        && parts[0] == "arn"
        && parts[2] == "secretsmanager"
        && parts[4] == account_id
        && parts[5] == "secret"
        && parts[6].starts_with("snowman-")
        && !value.contains('*')
}

fn valid_database_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "postgres" | "postgresql")
            && url.host_str().is_some()
            && !url.username().is_empty()
    })
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encoded_limit(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn required(name: &str) -> Result<String, ConfigError> {
    env(name).ok_or(ConfigError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_arns_are_exact_and_same_account() {
        let account = "625242091862";
        assert!(same_account_kms_arn(
            "arn:aws:kms:us-west-2:625242091862:key/00000000-0000-4000-8000-000000000001",
            account
        ));
        assert!(same_account_secret_arn(
            "arn:aws:secretsmanager:us-west-2:625242091862:secret:snowman-openai-key",
            account
        ));
        assert!(!same_account_secret_arn(
            "arn:aws:secretsmanager:us-west-2:111111111111:secret:snowman-openai-key",
            account
        ));
        assert!(!same_account_secret_arn(
            "arn:aws:secretsmanager:us-west-2:625242091862:secret:block-key",
            account
        ));
    }

    #[test]
    fn wire_bound_accounts_for_base64_expansion() {
        assert_eq!(encoded_limit(1), 4);
        assert_eq!(encoded_limit(3), 4);
        assert_eq!(encoded_limit(4), 8);
    }
}
