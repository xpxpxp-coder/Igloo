//! Default-off private HTTP service for governed meeting media.
//!
//! Control calls and provider callbacks use different routers and listener
//! addresses. The control router authenticates a short-lived, tenant-scoped
//! service token by digest. The callback router delegates exact signature
//! verification to an injected Snowman policy-proxy verifier before accepting
//! a body or WebSocket upgrade. Production provider transport is injected; the
//! executable ships fail-closed and cannot reach providers directly.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration as StdDuration,
};

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{ws::Message, ws::WebSocketUpgrade, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use snowman_meeting_control::{
    ConferenceKind, DataClass, MeetingToolIntentEnvelope, RetentionMode,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tokio::sync::Semaphore;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};
use url::Url;
use uuid::Uuid;

use crate::{
    canonical_digest, validate_digest, validate_join_boundaries, ConversationRoute, Error,
    GatewayPolicy, IngressRoute, JoinCommand, MediaExecutionGrant, MediaSession, Provider,
    ProviderEstablished, ProviderPlan, RendererRoute, SessionStatus, StopCommand, UsageAccounting,
    UsageReceipt,
};

const MAX_CONTROL_BODY_BYTES: usize = 256 * 1024;
const MAX_CALLBACK_BODY_BYTES: usize = 256 * 1024;
const MAX_AUDIO_FRAME_BYTES: usize = 1024 * 1024;
const MAX_AUTH_TOKEN_BYTES: usize = 512;
const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 15;

/// Stable response returned by an applied or replayed control operation.
#[derive(Debug, Serialize)]
pub struct ControlReceipt<T> {
    /// Exact request outcome.
    pub status: &'static str,
    /// Digest-only durable receipt.
    pub receipt_sha256: String,
    /// Bounded result; it contains no raw coordinate or credential.
    pub result: T,
}

/// Join response safe for the private meeting-command caller.
#[derive(Debug, Clone, Serialize)]
pub struct JoinResult {
    /// Exact media session.
    pub session_id: Uuid,
    /// Exact cancellation fence.
    pub session_generation: u32,
    /// Resulting lifecycle state.
    pub session_status: SessionStatus,
    /// Effective deadline.
    pub deadline: DateTime<Utc>,
    /// Effective spend ceiling.
    pub max_cost_microusd: u64,
}

/// Stop response.
#[derive(Debug, Clone, Serialize)]
pub struct StopResult {
    /// Resulting lifecycle state.
    pub session_status: SessionStatus,
}

/// Intent append response.
#[derive(Debug, Clone, Serialize)]
pub struct IntentResult {
    /// Exact intent idempotency key.
    pub intent_id: Uuid,
}

/// Provider runtime result containing only digest evidence.
#[derive(Debug, Clone)]
pub struct RuntimeJoinReceipt {
    /// Established session legs. Raw provider identifiers are already hashed.
    pub established: Vec<ProviderEstablished>,
    /// Digest of the complete provider-session set.
    pub provider_session_set_sha256: String,
}

/// Injected, provider-neutral execution arm. Implementations must use only a
/// Snowman policy proxy and purpose-specific Secrets Manager references.
#[async_trait]
pub trait ProviderRuntime: Send + Sync {
    /// Establish all admitted legs. Audio must remain transient.
    async fn join(
        &self,
        session: &MediaSession,
        plan: &ProviderPlan,
        now: DateTime<Utc>,
    ) -> Result<RuntimeJoinReceipt, Error>;

    /// Stop every established provider leg and return a digest-only receipt.
    async fn stop(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u32,
        now: DateTime<Utc>,
    ) -> Result<String, Error>;
}

/// Fail-closed executable default. It proves the server cannot accidentally
/// contact a provider before the policy-proxy runtime is packaged and tested.
pub struct DisabledProviderRuntime;

#[async_trait]
impl ProviderRuntime for DisabledProviderRuntime {
    async fn join(
        &self,
        _session: &MediaSession,
        _plan: &ProviderPlan,
        _now: DateTime<Utc>,
    ) -> Result<RuntimeJoinReceipt, Error> {
        Err(Error::ProviderDisabled)
    }

    async fn stop(
        &self,
        _tenant_id: Uuid,
        _session_id: Uuid,
        _generation: u32,
        _now: DateTime<Utc>,
    ) -> Result<String, Error> {
        Err(Error::ProviderDisabled)
    }
}

/// Exact provider callback presented to the injected policy-proxy verifier.
pub struct CallbackRequest<'a> {
    /// Provider path value.
    pub provider: Provider,
    /// Operations-owned binding identifier.
    pub callback_binding_id: Uuid,
    /// Original headers needed by the provider algorithm.
    pub headers: &'a HeaderMap,
    /// Original bytes; never logged or persisted.
    pub body: &'a [u8],
    /// Whether this request is a WebSocket upgrade.
    pub websocket_upgrade: bool,
    /// Gateway receipt time.
    pub received_at: DateTime<Utc>,
}

/// Result returned only after exact provider signature verification.
#[derive(Debug, Clone)]
pub struct VerifiedCallback {
    /// Exact tenant bound by the operations registration.
    pub tenant_id: Uuid,
    /// Digest of the stable provider delivery identifier.
    pub delivery_id_sha256: String,
    /// Digest of exact URL and raw request bytes.
    pub request_sha256: String,
    /// Digest of the exact authenticator key version.
    pub authentication_key_version_sha256: String,
    /// Optional fenced media session.
    pub session_id: Option<Uuid>,
    /// Required with a session id.
    pub session_generation: Option<u32>,
}

/// Separately injected provider callback authentication boundary.
#[async_trait]
pub trait CallbackAuthenticator: Send + Sync {
    /// Verify exact provider bytes through the Snowman policy proxy.
    async fn verify(&self, request: CallbackRequest<'_>) -> Result<VerifiedCallback, Error>;
}

/// Fail-closed callback default.
pub struct DisabledCallbackAuthenticator;

#[async_trait]
impl CallbackAuthenticator for DisabledCallbackAuthenticator {
    async fn verify(&self, _request: CallbackRequest<'_>) -> Result<VerifiedCallback, Error> {
        Err(Error::ProviderDisabled)
    }
}

/// Non-sensitive service configuration.
pub struct Config {
    control_bind_addr: SocketAddr,
    callback_bind_addr: Option<SocketAddr>,
    database_url: String,
    database_role: String,
    max_connections: u32,
    max_inflight_requests: usize,
    provider_egress_enabled: bool,
    callback_ingress_enabled: bool,
    policy_proxy_origin: Option<Url>,
}

/// Fail-closed configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Environment or static policy is invalid.
    #[error("Snowman meeting media configuration is invalid: {0}")]
    Invalid(&'static str),
    /// Database initialization or role verification failed.
    #[error("Snowman meeting media database initialization failed")]
    Database,
}

impl Config {
    /// Read executable configuration. Provider activation is rejected because
    /// this binary intentionally contains no direct provider transport.
    pub fn from_env() -> Result<Self, ConfigError> {
        let control_bind_addr = value("SNOWMAN_MEETING_MEDIA_BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()
            .map_err(|_| ConfigError::Invalid("control bind address"))?;
        let database_url = required("SNOWMAN_MEETING_MEDIA_DATABASE_URL")?;
        let database_role = required("SNOWMAN_MEETING_MEDIA_DATABASE_ROLE")?;
        buzz_db::runtime_security::validate_role_name(&database_role)
            .map_err(|_| ConfigError::Invalid("database role"))?;
        let max_connections =
            parse_bounded::<u32>("SNOWMAN_MEETING_MEDIA_MAX_CONNECTIONS", "8", 1, 16)?;
        let max_inflight_requests =
            parse_bounded::<usize>("SNOWMAN_MEETING_MEDIA_MAX_INFLIGHT_REQUESTS", "32", 1, 128)?;
        let provider_egress_enabled = exact_bool("SNOWMAN_MEETING_MEDIA_PROVIDER_EGRESS_ENABLED")?;
        let callback_ingress_enabled =
            exact_bool("SNOWMAN_MEETING_MEDIA_CALLBACK_INGRESS_ENABLED")?;
        let callback_bind_addr = if callback_ingress_enabled {
            Some(
                required("SNOWMAN_MEETING_MEDIA_CALLBACK_BIND_ADDR")?
                    .parse()
                    .map_err(|_| ConfigError::Invalid("callback bind address"))?,
            )
        } else {
            None
        };
        let policy_proxy_origin = value("SNOWMAN_MEETING_MEDIA_PROVIDER_EGRESS_PROXY_ORIGIN")
            .map(|raw| parse_private_proxy_origin(&raw))
            .transpose()?;
        if !valid_database_url(&database_url)
            || database_role != "snowman_meeting_media"
            || value("SNOWMAN_MEETING_MEDIA_NETWORK_POLICY").as_deref()
                != Some("private-snowman-only")
            || value("SNOWMAN_MEETING_MEDIA_RAW_AUDIO_RETENTION").as_deref() != Some("none")
            || provider_egress_enabled
            || callback_ingress_enabled
            || policy_proxy_origin.is_some()
        {
            return Err(ConfigError::Invalid(
                "provider/callback activation requires the separately reviewed injected runtime",
            ));
        }
        Ok(Self {
            control_bind_addr,
            callback_bind_addr,
            database_url,
            database_role,
            max_connections,
            max_inflight_requests,
            provider_egress_enabled,
            callback_ingress_enabled,
            policy_proxy_origin,
        })
    }
}

#[derive(Default)]
struct Metrics {
    accepted: AtomicU64,
    rejected: AtomicU64,
    transient_audio_frames: AtomicU64,
    callback_replays: AtomicU64,
}

/// Shared service state.
#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    runtime: Arc<dyn ProviderRuntime>,
    callbacks: Arc<dyn CallbackAuthenticator>,
    permits: Arc<Semaphore>,
    stream_permits: Arc<Semaphore>,
    metrics: Arc<Metrics>,
    control_bind_addr: SocketAddr,
    callback_bind_addr: Option<SocketAddr>,
    callback_enabled: bool,
}

impl AppState {
    /// Initialize the fail-closed executable state and verify the exact DB role.
    pub async fn new(config: Config) -> Result<Self, ConfigError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(StdDuration::from_secs(10))
            .connect(&config.database_url)
            .await
            .map_err(|_| ConfigError::Database)?;
        buzz_db::runtime_security::verify_meeting_media_role(&pool, &config.database_role)
            .await
            .map_err(|_| ConfigError::Database)?;
        if config.provider_egress_enabled
            || config.callback_ingress_enabled
            || config.policy_proxy_origin.is_some()
        {
            return Err(ConfigError::Invalid("unpackaged provider runtime"));
        }
        Ok(Self::from_parts(
            pool,
            Arc::new(DisabledProviderRuntime),
            Arc::new(DisabledCallbackAuthenticator),
            config.control_bind_addr,
            config.callback_bind_addr,
            config.max_inflight_requests,
            false,
        ))
    }

    /// Construct injected state for integration tests and a future reviewed
    /// policy-proxy package. This performs no ambient credential discovery.
    pub fn from_parts(
        pool: PgPool,
        runtime: Arc<dyn ProviderRuntime>,
        callbacks: Arc<dyn CallbackAuthenticator>,
        control_bind_addr: SocketAddr,
        callback_bind_addr: Option<SocketAddr>,
        max_inflight_requests: usize,
        callback_enabled: bool,
    ) -> Self {
        Self {
            pool,
            runtime,
            callbacks,
            permits: Arc::new(Semaphore::new(max_inflight_requests)),
            stream_permits: Arc::new(Semaphore::new(max_inflight_requests.min(32))),
            metrics: Arc::new(Metrics::default()),
            control_bind_addr,
            callback_bind_addr,
            callback_enabled,
        }
    }

    /// Private control listener.
    pub fn control_bind_addr(&self) -> SocketAddr {
        self.control_bind_addr
    }

    /// Separately firewalled callback listener, when reviewed and enabled.
    pub fn callback_bind_addr(&self) -> Option<SocketAddr> {
        self.callback_bind_addr
    }
}

/// Private control router.
pub fn control_router(state: AppState) -> Router {
    Router::new()
        .route("/_liveness", get(|| async { StatusCode::NO_CONTENT }))
        .route("/_readiness", get(readiness))
        .route("/_metrics", get(metrics))
        .route(
            "/v1/tenants/{tenant_id}/media-sessions/{session_id}/join",
            post(join),
        )
        .route(
            "/v1/tenants/{tenant_id}/media-sessions/{session_id}/stop",
            post(stop),
        )
        .route(
            "/v1/tenants/{tenant_id}/media-sessions/{session_id}/usage",
            post(usage),
        )
        .route(
            "/v1/tenants/{tenant_id}/media-sessions/{session_id}/intents",
            post(intent),
        )
        .layer(RequestBodyLimitLayer::new(MAX_CONTROL_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            StdDuration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECONDS),
        ))
        .with_state(state)
}

/// Separately authenticated callback/WebSocket router.
pub fn callback_router(state: AppState) -> Router {
    Router::new()
        .route("/_liveness", get(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/v1/provider-callbacks/{provider}/{binding_id}",
            post(provider_callback),
        )
        .route(
            "/v1/provider-streams/{provider}/{binding_id}",
            get(provider_stream),
        )
        .layer(RequestBodyLimitLayer::new(MAX_CALLBACK_BODY_BYTES))
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

async fn metrics(State(state): State<AppState>) -> Json<Value> {
    Json(serde_json::json!({
        "accepted_requests": state.metrics.accepted.load(Ordering::Relaxed),
        "rejected_requests": state.metrics.rejected.load(Ordering::Relaxed),
        "transient_audio_frames": state.metrics.transient_audio_frames.load(Ordering::Relaxed),
        "callback_replays": state.metrics.callback_replays.load(Ordering::Relaxed),
    }))
}

#[derive(Clone)]
struct Caller {
    identity_id: Uuid,
    authentication_sha256: [u8; 32],
}

async fn authenticate(
    state: &AppState,
    tenant_id: Uuid,
    headers: &HeaderMap,
    scope: &str,
) -> Result<Caller, ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| (32..=MAX_AUTH_TOKEN_BYTES).contains(&v.len()))
        .ok_or(ApiError::Unauthorized)?;
    let token_sha256: [u8; 32] = Sha256::digest(value.as_bytes()).into();
    let row = sqlx::query(
        "SELECT c.service_identity_id,c.authority_evidence_sha256 \
         FROM snowman_meeting_media_callers c \
         JOIN snowman_workforce_identities i \
           ON i.community_id=c.community_id AND i.identity_id=c.service_identity_id \
         WHERE c.community_id=$1 AND c.token_sha256=$2 AND $3=ANY(c.scopes) \
           AND c.status='active' AND c.revoked_at IS NULL AND c.expires_at>NOW() \
           AND i.identity_type='service' AND i.status='active' \
           AND (i.expires_at IS NULL OR i.expires_at>NOW())",
    )
    .bind(tenant_id)
    .bind(token_sha256.as_slice())
    .bind(scope)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| ApiError::Unavailable)?
    .ok_or(ApiError::Unauthorized)?;
    let identity_id: Uuid = row.try_get("service_identity_id").map_err(db)?;
    let authority: Vec<u8> = row.try_get("authority_evidence_sha256").map_err(db)?;
    let authentication_sha256 = Sha256::digest(
        [
            token_sha256.as_slice(),
            authority.as_slice(),
            scope.as_bytes(),
        ]
        .concat(),
    )
    .into();
    Ok(Caller {
        identity_id,
        authentication_sha256,
    })
}

async fn join(
    State(state): State<AppState>,
    Path((tenant_id, session_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ControlReceipt<JoinResult>>, ApiError> {
    let _permit = state
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let caller = authenticate(&state, tenant_id, &headers, "meeting.media.join").await?;
    let command: JoinCommand = parse_body(&body)?;
    if command.tenant_id != tenant_id || command.session_id != session_id {
        return Err(ApiError::Invalid);
    }
    let (session, plan, receipt, duplicate) = reserve_join(&state.pool, command, caller).await?;
    if duplicate {
        state.metrics.accepted.fetch_add(1, Ordering::Relaxed);
        return Ok(Json(ControlReceipt {
            status: "duplicate",
            receipt_sha256: receipt,
            result: JoinResult {
                session_id,
                session_generation: session.session_generation(),
                session_status: session.status(),
                deadline: plan.deadline,
                max_cost_microusd: plan.max_cost_microusd,
            },
        }));
    }
    let now = Utc::now();
    let runtime = state.runtime.join(&session, &plan, now).await;
    let status = finalize_join(
        &state.pool,
        tenant_id,
        session_id,
        session.session_generation(),
        runtime,
    )
    .await?;
    state.metrics.accepted.fetch_add(1, Ordering::Relaxed);
    Ok(Json(ControlReceipt {
        status: "applied",
        receipt_sha256: receipt,
        result: JoinResult {
            session_id,
            session_generation: session.session_generation(),
            session_status: status,
            deadline: plan.deadline,
            max_cost_microusd: plan.max_cost_microusd,
        },
    }))
}

async fn reserve_join(
    pool: &PgPool,
    command: JoinCommand,
    caller: Caller,
) -> Result<(MediaSession, ProviderPlan, String, bool), ApiError> {
    command.validate().map_err(|_| ApiError::Invalid)?;
    let command_sha256 = canonical_digest(&command).map_err(|_| ApiError::Invalid)?;
    let now = Utc::now();
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if let Some(row) = sqlx::query(
        "SELECT c.command_sha256,c.result_receipt_sha256,s.status,s.deadline, \
                s.max_cost_microusd,s.session_generation \
         FROM snowman_meeting_media_commands c \
         JOIN snowman_meeting_media_sessions s \
           ON s.community_id=c.community_id AND s.media_session_id=c.media_session_id \
         WHERE c.community_id=$1 AND c.command_id=$2",
    )
    .bind(command.tenant_id)
    .bind(command.command_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?
    {
        let prior: Vec<u8> = row.try_get("command_sha256").map_err(db)?;
        if prior != hex::decode(&command_sha256).map_err(|_| ApiError::Invalid)? {
            return Err(ApiError::Conflict);
        }
        let status = parse_session_status(row.try_get("status").map_err(db)?)?;
        let session = load_media_session(&mut tx, command.tenant_id, command.session_id).await?;
        let plan = ProviderPlan {
            session_id: command.session_id,
            session_generation: u32::try_from(
                row.try_get::<i64, _>("session_generation").map_err(db)?,
            )
            .map_err(|_| ApiError::Invalid)?,
            ingress_route: session.grant.ingress_route,
            conversation_route: session.grant.conversation_route,
            renderer_route: session.grant.renderer_route,
            sealed_coordinate_ref: session.grant.sealed_coordinate_ref.clone(),
            conference_approval_sha256: session.grant.conference_approval_sha256.clone(),
            deadline: row.try_get("deadline").map_err(db)?,
            max_duration_seconds: session.grant.max_duration_seconds,
            max_cost_microusd: u64::try_from(
                row.try_get::<i64, _>("max_cost_microusd").map_err(db)?,
            )
            .map_err(|_| ApiError::Invalid)?,
        };
        let receipt = hex::encode(
            row.try_get::<Vec<u8>, _>("result_receipt_sha256")
                .map_err(db)?,
        );
        tx.commit().await.map_err(db)?;
        let mut session = session;
        session.status = status;
        return Ok((session, plan, receipt, true));
    }

    let (policy, grant) = load_join_authority(&mut tx, &command, now).await?;
    validate_join_boundaries(&policy, &grant, &command, now).map_err(map_domain)?;
    let concurrent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM snowman_meeting_media_sessions \
         WHERE community_id=$1 AND workspace_id=$2 \
           AND status IN ('joining','indeterminate','active','stopping')",
    )
    .bind(command.tenant_id)
    .bind(command.workspace_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;
    if concurrent >= i64::from(policy.max_concurrent_sessions) {
        return Err(ApiError::Conflict);
    }
    let max_duration_seconds = policy
        .max_session_duration_seconds
        .min(grant.max_duration_seconds);
    let deadline = command
        .deadline
        .min(grant.ends_at)
        .min(now + Duration::seconds(i64::from(max_duration_seconds)));
    let max_cost_microusd = policy
        .max_session_cost_microusd
        .min(grant.max_cost_microusd);
    if deadline <= now || max_cost_microusd == 0 {
        return Err(ApiError::Conflict);
    }
    let plan = ProviderPlan {
        session_id: grant.session_id,
        session_generation: grant.session_generation,
        ingress_route: grant.ingress_route,
        conversation_route: grant.conversation_route,
        renderer_route: grant.renderer_route,
        sealed_coordinate_ref: grant.sealed_coordinate_ref.clone(),
        conference_approval_sha256: grant.conference_approval_sha256.clone(),
        deadline,
        max_duration_seconds,
        max_cost_microusd,
    };
    let receipt = canonical_digest(&(
        grant.tenant_id,
        grant.meeting_id,
        grant.session_id,
        grant.session_generation,
        &command_sha256,
        deadline,
        max_cost_microusd,
    ))
    .map_err(|_| ApiError::Invalid)?;
    let policy_sha256 = canonical_digest(&policy).map_err(|_| ApiError::Invalid)?;
    sqlx::query(
        "INSERT INTO snowman_meeting_media_sessions \
         (community_id,media_session_id,meeting_id,meeting_session_id,session_generation, \
          workspace_id,mailbox_identity_id,meeting_agent_identity_id,gateway_service_identity_id, \
          provider_revision,schedule_revision,conference_kind,ingress_route,conversation_route, \
          renderer_route,status,provider_binding_sha256,conference_approval_sha256, \
          admission_evidence_sha256,consent_evidence_sha256,gateway_policy_sha256, \
          raw_audio_retention,transcript_authority,max_cost_microusd,spent_microusd, \
          started_at,deadline,last_receipt_sha256) \
         VALUES ($1,$2,$3,$2,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'indeterminate', \
                 $15,$16,$17,$18,$19,'none',$20,$21,0,$22,$23,$24)",
    )
    .bind(grant.tenant_id)
    .bind(grant.session_id)
    .bind(grant.meeting_id)
    .bind(i64::from(grant.session_generation))
    .bind(grant.workspace_id)
    .bind(grant.mailbox_identity_id)
    .bind(grant.meeting_agent_identity_id)
    .bind(policy.gateway_service_identity_id)
    .bind(i64::try_from(grant.provider_revision).map_err(|_| ApiError::Invalid)?)
    .bind(i64::try_from(grant.schedule_revision).map_err(|_| ApiError::Invalid)?)
    .bind(conference_kind(grant.conference_kind))
    .bind(ingress_route(grant.ingress_route))
    .bind(conversation_route(grant.conversation_route))
    .bind(renderer_route(grant.renderer_route))
    .bind(hex::decode(&policy.provider_binding_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(hex::decode(&grant.conference_approval_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(hex::decode(&grant.admission_evidence_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(hex::decode(&grant.consent_evidence_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(hex::decode(&policy_sha256).map_err(|_| ApiError::Invalid)?)
    .bind((grant.transcript_retention == RetentionMode::AnalystEvidence).then_some("analyst360"))
    .bind(i64::try_from(max_cost_microusd).map_err(|_| ApiError::Invalid)?)
    .bind(now)
    .bind(deadline)
    .bind(hex::decode(&receipt).map_err(|_| ApiError::Invalid)?)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    sqlx::query(
        "INSERT INTO snowman_meeting_media_commands \
         (community_id,command_id,media_session_id,command_kind,command_sha256,session_generation, \
          issuer_evidence_sha256,result_receipt_sha256,applied_at,caller_service_identity_id,authentication_sha256) \
         VALUES ($1,$2,$3,'join',$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(command.tenant_id)
    .bind(command.command_id)
    .bind(command.session_id)
    .bind(hex::decode(&command_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(i64::from(command.session_generation))
    .bind(hex::decode(&command.issuer_evidence_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(hex::decode(&receipt).map_err(|_| ApiError::Invalid)?)
    .bind(now)
    .bind(caller.identity_id)
    .bind(caller.authentication_sha256.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    let session = MediaSession {
        grant,
        gateway_service_identity_id: policy.gateway_service_identity_id,
        provider_binding_sha256: policy.provider_binding_sha256,
        status: SessionStatus::Indeterminate,
        provider_session_ids_sha256: BTreeMap::new(),
        spent_microusd: 0,
        cost_ceiling_microusd: max_cost_microusd,
        started_at: now,
        deadline,
        stopped_at: None,
        last_receipt_sha256: receipt.clone(),
    };
    Ok((session, plan, receipt, false))
}

async fn finalize_join(
    pool: &PgPool,
    tenant_id: Uuid,
    session_id: Uuid,
    generation: u32,
    runtime: Result<RuntimeJoinReceipt, Error>,
) -> Result<SessionStatus, ApiError> {
    let now = Utc::now();
    match runtime {
        Ok(receipt) => {
            validate_digest(&receipt.provider_session_set_sha256, "provider session set")
                .map_err(|_| ApiError::Invalid)?;
            let mut tx = pool.begin().await.map_err(db)?;
            for event in receipt.established {
                validate_digest(&event.provider_session_id_sha256, "provider session")
                    .map_err(|_| ApiError::Invalid)?;
                validate_digest(&event.handshake_sha256, "provider handshake")
                    .map_err(|_| ApiError::Invalid)?;
                sqlx::query(
                    "INSERT INTO snowman_meeting_media_provider_sessions \
                     (community_id,media_session_id,session_generation,provider,provider_session_id_sha256, \
                      handshake_sha256,established_at) VALUES ($1,$2,$3,$4,$5,$6,$7) \
                     ON CONFLICT (community_id,media_session_id,provider) DO NOTHING",
                )
                .bind(tenant_id)
                .bind(session_id)
                .bind(i64::from(generation))
                .bind(provider(event.provider))
                .bind(hex::decode(event.provider_session_id_sha256).map_err(|_| ApiError::Invalid)?)
                .bind(hex::decode(event.handshake_sha256).map_err(|_| ApiError::Invalid)?)
                .bind(event.observed_at)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            }
            let updated = sqlx::query(
                "UPDATE snowman_meeting_media_sessions SET status='active', \
                   provider_session_set_sha256=$4,last_receipt_sha256=$4,updated_at=$5 \
                 WHERE community_id=$1 AND media_session_id=$2 AND session_generation=$3 \
                   AND status='indeterminate' AND deadline>$5",
            )
            .bind(tenant_id)
            .bind(session_id)
            .bind(i64::from(generation))
            .bind(hex::decode(receipt.provider_session_set_sha256).map_err(|_| ApiError::Invalid)?)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            if updated.rows_affected() != 1 {
                return Err(ApiError::Conflict);
            }
            tx.commit().await.map_err(db)?;
            Ok(SessionStatus::Active)
        }
        Err(_) => {
            sqlx::query(
                "UPDATE snowman_meeting_media_sessions SET status='failed',stopped_at=$4, \
                   failure_code='provider_start_failed',updated_at=$4 \
                 WHERE community_id=$1 AND media_session_id=$2 AND session_generation=$3 \
                   AND status='indeterminate'",
            )
            .bind(tenant_id)
            .bind(session_id)
            .bind(i64::from(generation))
            .bind(now)
            .execute(pool)
            .await
            .map_err(db)?;
            Err(ApiError::Unavailable)
        }
    }
}

async fn stop(
    State(state): State<AppState>,
    Path((tenant_id, session_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ControlReceipt<StopResult>>, ApiError> {
    let _permit = state
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let caller = authenticate(&state, tenant_id, &headers, "meeting.media.stop").await?;
    let command: StopCommand = parse_body(&body)?;
    if command.tenant_id != tenant_id || command.session_id != session_id {
        return Err(ApiError::Invalid);
    }
    command.validate().map_err(|_| ApiError::Invalid)?;
    let digest = canonical_digest(&command).map_err(|_| ApiError::Invalid)?;
    let now = Utc::now();
    let mut tx = state.pool.begin().await.map_err(db)?;
    if let Some(row) = sqlx::query(
        "SELECT command_sha256,result_receipt_sha256 FROM snowman_meeting_media_commands \
         WHERE community_id=$1 AND command_id=$2",
    )
    .bind(tenant_id)
    .bind(command.command_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?
    {
        let prior: Vec<u8> = row.try_get("command_sha256").map_err(db)?;
        if prior != hex::decode(&digest).map_err(|_| ApiError::Invalid)? {
            return Err(ApiError::Conflict);
        }
        let receipt = hex::encode(
            row.try_get::<Vec<u8>, _>("result_receipt_sha256")
                .map_err(db)?,
        );
        tx.commit().await.map_err(db)?;
        return Ok(Json(ControlReceipt {
            status: "duplicate",
            receipt_sha256: receipt,
            result: StopResult {
                session_status: SessionStatus::Stopping,
            },
        }));
    }
    let row = sqlx::query(
        "SELECT meeting_id,session_generation,status FROM snowman_meeting_media_sessions \
         WHERE community_id=$1 AND media_session_id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?
    .ok_or(ApiError::NotFound)?;
    let meeting_id: Uuid = row.try_get("meeting_id").map_err(db)?;
    let generation: i64 = row.try_get("session_generation").map_err(db)?;
    if meeting_id != command.meeting_id || i64::from(command.cancellation_generation) < generation {
        return Err(ApiError::Conflict);
    }
    let receipt = canonical_digest(&(
        tenant_id,
        session_id,
        command.cancellation_generation,
        &digest,
        now,
    ))
    .map_err(|_| ApiError::Invalid)?;
    sqlx::query(
        "UPDATE snowman_meeting_media_sessions SET status='stopping',last_receipt_sha256=$3, \
           updated_at=$4 WHERE community_id=$1 AND media_session_id=$2 \
           AND status NOT IN ('stopped','failed')",
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(hex::decode(&command.evidence_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    sqlx::query(
        "INSERT INTO snowman_meeting_media_commands \
         (community_id,command_id,media_session_id,command_kind,command_sha256,session_generation, \
          issuer_evidence_sha256,result_receipt_sha256,applied_at,caller_service_identity_id,authentication_sha256) \
         VALUES ($1,$2,$3,'stop',$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(tenant_id)
    .bind(command.command_id)
    .bind(session_id)
    .bind(hex::decode(&digest).map_err(|_| ApiError::Invalid)?)
    .bind(generation)
    .bind(hex::decode(&command.evidence_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(hex::decode(&receipt).map_err(|_| ApiError::Invalid)?)
    .bind(now)
    .bind(caller.identity_id)
    .bind(caller.authentication_sha256.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    tx.commit().await.map_err(db)?;
    let stopped = state
        .runtime
        .stop(
            tenant_id,
            session_id,
            u32::try_from(generation).map_err(|_| ApiError::Invalid)?,
            now,
        )
        .await;
    let status = if let Ok(provider_receipt) = stopped {
        validate_digest(&provider_receipt, "provider stop receipt")
            .map_err(|_| ApiError::Invalid)?;
        sqlx::query(
            "UPDATE snowman_meeting_media_sessions SET status='stopped',stopped_at=$4, \
               last_receipt_sha256=$5,updated_at=$4 WHERE community_id=$1 AND media_session_id=$2 \
               AND session_generation=$3 AND status='stopping'",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(generation)
        .bind(Utc::now())
        .bind(hex::decode(provider_receipt).map_err(|_| ApiError::Invalid)?)
        .execute(&state.pool)
        .await
        .map_err(db)?;
        SessionStatus::Stopped
    } else {
        SessionStatus::Stopping
    };
    Ok(Json(ControlReceipt {
        status: "applied",
        receipt_sha256: receipt,
        result: StopResult {
            session_status: status,
        },
    }))
}

async fn usage(
    State(state): State<AppState>,
    Path((tenant_id, session_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ControlReceipt<UsageAccounting>>, ApiError> {
    let _permit = state
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let _caller = authenticate(&state, tenant_id, &headers, "meeting.media.usage").await?;
    let envelope: UsageEnvelope = parse_body(&body)?;
    if envelope.session_id != session_id || envelope.session_generation == 0 {
        return Err(ApiError::Invalid);
    }
    envelope.receipt.validate().map_err(|_| ApiError::Invalid)?;
    let digest = canonical_digest(&envelope.receipt).map_err(|_| ApiError::Invalid)?;
    let now = Utc::now();
    let mut tx = state.pool.begin().await.map_err(db)?;
    if let Some(prior) = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT response_sha256 FROM snowman_meeting_media_usage_receipts \
         WHERE community_id=$1 AND provider=$2 AND provider_receipt_sha256=$3",
    )
    .bind(tenant_id)
    .bind(provider(envelope.receipt.provider))
    .bind(hex::decode(&envelope.receipt.provider_receipt_sha256).map_err(|_| ApiError::Invalid)?)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?
    {
        if prior != hex::decode(&envelope.receipt.response_sha256).map_err(|_| ApiError::Invalid)? {
            return Err(ApiError::Conflict);
        }
        tx.commit().await.map_err(db)?;
        return Ok(Json(ControlReceipt {
            status: "duplicate",
            receipt_sha256: digest,
            result: UsageAccounting::Accounted { spent_microusd: 0 },
        }));
    }
    let row = sqlx::query(
        "SELECT m.spent_microusd,m.max_cost_microusd,m.deadline,m.status \
         FROM snowman_meeting_media_sessions m \
         JOIN snowman_meeting_sessions s ON s.community_id=m.community_id \
           AND s.session_id=m.meeting_session_id AND s.generation=m.session_generation \
         WHERE m.community_id=$1 AND m.media_session_id=$2 AND m.session_generation=$3 \
           AND s.status='active' AND s.consent_complete FOR UPDATE OF m",
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(i64::from(envelope.session_generation))
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?
    .ok_or(ApiError::Conflict)?;
    let spent = u64::try_from(row.try_get::<i64, _>("spent_microusd").map_err(db)?)
        .map_err(|_| ApiError::Invalid)?;
    let ceiling = u64::try_from(row.try_get::<i64, _>("max_cost_microusd").map_err(db)?)
        .map_err(|_| ApiError::Invalid)?;
    let deadline: DateTime<Utc> = row.try_get("deadline").map_err(db)?;
    if row.try_get::<String, _>("status").map_err(db)? != "active" {
        return Err(ApiError::Conflict);
    }
    let next = spent
        .checked_add(envelope.receipt.cost_microusd)
        .ok_or(ApiError::Conflict)?;
    let teardown = now >= deadline || next > ceiling;
    sqlx::query(
        "INSERT INTO snowman_meeting_media_usage_receipts \
         (community_id,media_session_id,session_generation,provider,provider_receipt_sha256, \
          response_sha256,cost_microusd,input_units,output_units,observed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(tenant_id)
    .bind(session_id)
    .bind(i64::from(envelope.session_generation))
    .bind(provider(envelope.receipt.provider))
    .bind(hex::decode(&envelope.receipt.provider_receipt_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(hex::decode(&envelope.receipt.response_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(i64::try_from(envelope.receipt.cost_microusd).map_err(|_| ApiError::Invalid)?)
    .bind(i64::try_from(envelope.receipt.input_units).map_err(|_| ApiError::Invalid)?)
    .bind(i64::try_from(envelope.receipt.output_units).map_err(|_| ApiError::Invalid)?)
    .bind(envelope.receipt.observed_at)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    if teardown {
        sqlx::query(
            "UPDATE snowman_meeting_media_sessions SET status='stopping',last_receipt_sha256=$3, \
               updated_at=$4 WHERE community_id=$1 AND media_session_id=$2 AND status='active'",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(hex::decode(&envelope.receipt.response_sha256).map_err(|_| ApiError::Invalid)?)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    } else {
        sqlx::query(
            "UPDATE snowman_meeting_media_sessions SET spent_microusd=$3,last_receipt_sha256=$4, \
               updated_at=$5 WHERE community_id=$1 AND media_session_id=$2 AND status='active'",
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(i64::try_from(next).map_err(|_| ApiError::Invalid)?)
        .bind(hex::decode(&envelope.receipt.response_sha256).map_err(|_| ApiError::Invalid)?)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    }
    tx.commit().await.map_err(db)?;
    let result = if teardown {
        UsageAccounting::TeardownRequired {
            spent_before_microusd: spent,
            attempted_increment_microusd: envelope.receipt.cost_microusd,
            ceiling_microusd: ceiling,
        }
    } else {
        UsageAccounting::Accounted {
            spent_microusd: next,
        }
    };
    Ok(Json(ControlReceipt {
        status: "applied",
        receipt_sha256: digest,
        result,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageEnvelope {
    session_id: Uuid,
    session_generation: u32,
    receipt: UsageReceipt,
}

async fn intent(
    State(state): State<AppState>,
    Path((tenant_id, session_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ControlReceipt<IntentResult>>, ApiError> {
    let _permit = state
        .permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let caller = authenticate(&state, tenant_id, &headers, "meeting.media.intent").await?;
    let envelope: MeetingToolIntentEnvelope = parse_body(&body)?;
    envelope.validate().map_err(|_| ApiError::Invalid)?;
    if envelope.tenant_id != tenant_id
        || envelope.session_id != session_id
        || envelope.service_identity_id != caller.identity_id
    {
        return Err(ApiError::Invalid);
    }
    let value = serde_json::to_value(&envelope.intent).map_err(|_| ApiError::Invalid)?;
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(ApiError::Invalid)?;
    let intent_body = serde_json::to_vec(&envelope.intent).map_err(|_| ApiError::Invalid)?;
    let intent_sha256: [u8; 32] = Sha256::digest(&intent_body).into();
    let inserted = sqlx::query(
        "INSERT INTO snowman_meeting_tool_intents \
         (community_id,intent_id,meeting_id,session_id,session_generation,service_identity_id, \
          intent_kind,intent_body,intent_sha256,source_turn_sha256,input_trust,status,observed_at) \
         SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'untrusted','proposed',$11 \
         FROM snowman_meeting_media_sessions m \
         JOIN snowman_meeting_sessions s ON s.community_id=m.community_id \
           AND s.session_id=m.meeting_session_id AND s.generation=m.session_generation \
         WHERE m.community_id=$1 AND m.media_session_id=$4 AND m.meeting_id=$3 \
           AND m.session_generation=$5 AND m.workspace_id=$12 AND m.status='active' \
           AND m.meeting_agent_identity_id=$6 AND m.deadline>NOW() \
           AND s.status='active' AND s.consent_complete \
         ON CONFLICT (community_id,intent_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(envelope.intent_id)
    .bind(envelope.meeting_id)
    .bind(session_id)
    .bind(i64::from(envelope.session_generation))
    .bind(envelope.service_identity_id)
    .bind(kind)
    .bind(&intent_body)
    .bind(intent_sha256.as_slice())
    .bind(hex::decode(&envelope.source_turn_sha256).map_err(|_| ApiError::Invalid)?)
    .bind(envelope.observed_at)
    .bind(envelope.workspace_id)
    .execute(&state.pool)
    .await
    .map_err(db)?;
    if inserted.rows_affected() == 0 {
        let exact: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM snowman_meeting_tool_intents \
             WHERE community_id=$1 AND intent_id=$2 AND intent_sha256=$3 \
               AND session_id=$4 AND session_generation=$5)",
        )
        .bind(tenant_id)
        .bind(envelope.intent_id)
        .bind(intent_sha256.as_slice())
        .bind(session_id)
        .bind(i64::from(envelope.session_generation))
        .fetch_one(&state.pool)
        .await
        .map_err(db)?;
        if !exact {
            return Err(ApiError::Conflict);
        }
    }
    Ok(Json(ControlReceipt {
        status: if inserted.rows_affected() == 0 {
            "duplicate"
        } else {
            "applied"
        },
        receipt_sha256: hex::encode(intent_sha256),
        result: IntentResult {
            intent_id: envelope.intent_id,
        },
    }))
}

async fn provider_callback(
    State(state): State<AppState>,
    Path((provider_name, binding_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    if !state.callback_enabled {
        return Err(ApiError::NotFound);
    }
    let provider = parse_callback_provider(&provider_name)?;
    let verified = state
        .callbacks
        .verify(CallbackRequest {
            provider,
            callback_binding_id: binding_id,
            headers: &headers,
            body: &body,
            websocket_upgrade: false,
            received_at: Utc::now(),
        })
        .await
        .map_err(|_| ApiError::Unauthorized)?;
    persist_callback(&state.pool, provider, binding_id, &verified).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn provider_stream(
    State(state): State<AppState>,
    Path((provider_name, binding_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    if !state.callback_enabled {
        return Err(ApiError::NotFound);
    }
    let provider = parse_callback_provider(&provider_name)?;
    let verified = state
        .callbacks
        .verify(CallbackRequest {
            provider,
            callback_binding_id: binding_id,
            headers: &headers,
            body: &[],
            websocket_upgrade: true,
            received_at: Utc::now(),
        })
        .await
        .map_err(|_| ApiError::Unauthorized)?;
    persist_callback(&state.pool, provider, binding_id, &verified).await?;
    let permit = state
        .stream_permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Busy)?;
    let metrics = state.metrics.clone();
    Ok(upgrade
        .max_message_size(MAX_AUDIO_FRAME_BYTES)
        .max_frame_size(MAX_AUDIO_FRAME_BYTES)
        .on_upgrade(move |mut socket| async move {
            let _permit = permit;
            while let Some(Ok(message)) = socket.recv().await {
                match message {
                    Message::Binary(bytes) if bytes.len() <= MAX_AUDIO_FRAME_BYTES => {
                        // The digest is deliberately discarded here: no audio or
                        // per-frame evidence persists at the ingress boundary.
                        let _frame_sha256 = Sha256::digest(&bytes);
                        metrics
                            .transient_audio_frames
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Message::Close(_) => break,
                    Message::Ping(bytes) => {
                        if socket.send(Message::Pong(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Message::Text(_) | Message::Pong(_) | Message::Binary(_) => break,
                }
            }
        }))
}

async fn persist_callback(
    pool: &PgPool,
    provider_value: Provider,
    binding_id: Uuid,
    verified: &VerifiedCallback,
) -> Result<(), ApiError> {
    for digest in [
        &verified.delivery_id_sha256,
        &verified.request_sha256,
        &verified.authentication_key_version_sha256,
    ] {
        validate_digest(digest, "callback digest").map_err(|_| ApiError::Unauthorized)?;
    }
    if verified.session_id.is_some() != verified.session_generation.is_some() {
        return Err(ApiError::Unauthorized);
    }
    let inserted = sqlx::query(
        "INSERT INTO snowman_meeting_media_webhook_receipts \
         (community_id,provider,delivery_id_sha256,request_sha256, \
          authentication_key_version_sha256,media_session_id,session_generation,received_at) \
         SELECT $1,$2,$3,$4,$5,$6,$7,$8 \
         FROM snowman_meeting_media_callback_bindings b \
         WHERE b.community_id=$1 AND b.callback_binding_id=$9 AND b.provider=$2 \
           AND b.status='active' \
         ON CONFLICT (community_id,provider,delivery_id_sha256) DO NOTHING",
    )
    .bind(verified.tenant_id)
    .bind(provider(provider_value))
    .bind(hex::decode(&verified.delivery_id_sha256).map_err(|_| ApiError::Unauthorized)?)
    .bind(hex::decode(&verified.request_sha256).map_err(|_| ApiError::Unauthorized)?)
    .bind(
        hex::decode(&verified.authentication_key_version_sha256)
            .map_err(|_| ApiError::Unauthorized)?,
    )
    .bind(verified.session_id)
    .bind(verified.session_generation.map(i64::from))
    .bind(Utc::now())
    .bind(binding_id)
    .execute(pool)
    .await
    .map_err(db)?;
    if inserted.rows_affected() == 0 {
        let exact: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM snowman_meeting_media_webhook_receipts \
             WHERE community_id=$1 AND provider=$2 AND delivery_id_sha256=$3 \
               AND request_sha256=$4)",
        )
        .bind(verified.tenant_id)
        .bind(provider(provider_value))
        .bind(hex::decode(&verified.delivery_id_sha256).map_err(|_| ApiError::Unauthorized)?)
        .bind(hex::decode(&verified.request_sha256).map_err(|_| ApiError::Unauthorized)?)
        .fetch_one(pool)
        .await
        .map_err(db)?;
        if !exact {
            return Err(ApiError::Conflict);
        }
    }
    Ok(())
}

async fn load_join_authority(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &JoinCommand,
    now: DateTime<Utc>,
) -> Result<(GatewayPolicy, MediaExecutionGrant), ApiError> {
    let row = sqlx::query(
        "SELECT r.activation_enabled,r.allow_snowman_huddle,r.allow_snowman_aws,r.allow_twilio, \
                r.allow_openai_realtime,r.allow_eleven_labs,r.provider_binding_sha256, \
                r.policy_evidence_sha256,r.max_session_cost_microusd,r.max_session_duration_seconds, \
                r.max_concurrent_sessions,m.workspace_id,m.mailbox_identity_id,m.meeting_agent_identity_id, \
                m.provider_event_id_sha256,m.provider_revision,m.schedule_revision,m.data_class, \
                m.conference_kind,m.sealed_coordinate_ref,m.conference_approval_sha256,m.voice_route, \
                m.speech_output_route,m.starts_at,m.ends_at,m.join_not_before,m.join_not_after, \
                m.max_cost_microusd AS meeting_max_cost,m.max_duration_seconds AS meeting_max_duration, \
                m.raw_audio_retention,m.transcript_retention,m.admission_evidence_sha256, \
                s.source_policy_sha256,s.status AS session_status,s.consent_complete \
         FROM snowman_meeting_media_routes r \
         JOIN snowman_meetings m ON m.community_id=r.community_id \
           AND m.workspace_id=r.workspace_id AND m.mailbox_identity_id=r.mailbox_identity_id \
         JOIN snowman_meeting_sessions s ON s.community_id=m.community_id \
           AND s.meeting_id=m.meeting_id \
         JOIN snowman_meeting_mailboxes mb ON mb.community_id=m.community_id \
           AND mb.mailbox_identity_id=m.mailbox_identity_id \
         WHERE r.community_id=$1 AND m.meeting_id=$2 AND s.session_id=$3 \
           AND s.generation=$4 AND m.activation_enabled AND m.status IN ('joining','active') \
           AND s.status='active' AND s.consent_complete AND mb.status='active' \
           AND r.gateway_service_identity_id=$5 \
         FOR UPDATE OF r,s",
    )
    .bind(command.tenant_id)
    .bind(command.meeting_id)
    .bind(command.session_id)
    .bind(i64::from(command.session_generation))
    .bind(command.gateway_service_identity_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?
    .ok_or(ApiError::Conflict)?;
    let mut providers = BTreeSet::new();
    for (column, provider_value) in [
        ("allow_snowman_huddle", Provider::SnowmanHuddle),
        ("allow_snowman_aws", Provider::SnowmanAws),
        ("allow_twilio", Provider::Twilio),
        ("allow_openai_realtime", Provider::OpenAiRealtime),
        ("allow_eleven_labs", Provider::ElevenLabs),
    ] {
        if row.try_get::<bool, _>(column).map_err(db)? {
            providers.insert(provider_value);
        }
    }
    let conference_kind = parse_conference_kind(row.try_get("conference_kind").map_err(db)?)?;
    let ingress = match conference_kind {
        ConferenceKind::SnowmanHuddle => IngressRoute::SnowmanHuddle,
        ConferenceKind::Telephony => IngressRoute::TwilioTelephony,
        ConferenceKind::GoogleMeet => return Err(ApiError::Conflict),
    };
    let conversation = parse_conversation_route(row.try_get("voice_route").map_err(db)?)?;
    let renderer = parse_renderer_route(row.try_get("speech_output_route").map_err(db)?)?;
    let policy = GatewayPolicy {
        tenant_id: command.tenant_id,
        workspace_id: row.try_get("workspace_id").map_err(db)?,
        mailbox_identity_id: row.try_get("mailbox_identity_id").map_err(db)?,
        gateway_service_identity_id: command.gateway_service_identity_id,
        activation_enabled: row.try_get("activation_enabled").map_err(db)?,
        allowed_providers: providers,
        provider_binding_sha256: digest_column(&row, "provider_binding_sha256")?,
        policy_evidence_sha256: digest_column(&row, "policy_evidence_sha256")?,
        max_session_cost_microusd: as_u64(&row, "max_session_cost_microusd")?,
        max_session_duration_seconds: as_u32(&row, "max_session_duration_seconds")?,
        max_concurrent_sessions: u16::try_from(
            row.try_get::<i32, _>("max_concurrent_sessions")
                .map_err(db)?,
        )
        .map_err(|_| ApiError::Invalid)?,
    };
    let grant = MediaExecutionGrant {
        tenant_id: command.tenant_id,
        workspace_id: row.try_get("workspace_id").map_err(db)?,
        meeting_id: command.meeting_id,
        mailbox_identity_id: row.try_get("mailbox_identity_id").map_err(db)?,
        meeting_agent_identity_id: row.try_get("meeting_agent_identity_id").map_err(db)?,
        provider_event_id_sha256: digest_column(&row, "provider_event_id_sha256")?,
        provider_revision: as_u64(&row, "provider_revision")?,
        schedule_revision: as_u64(&row, "schedule_revision")?,
        session_id: command.session_id,
        session_generation: command.session_generation,
        data_class: parse_data_class(row.try_get("data_class").map_err(db)?)?,
        conference_kind,
        sealed_coordinate_ref: row.try_get("sealed_coordinate_ref").map_err(db)?,
        conference_approval_sha256: digest_column(&row, "conference_approval_sha256")?,
        ingress_route: ingress,
        conversation_route: conversation,
        renderer_route: renderer,
        starts_at: row.try_get("starts_at").map_err(db)?,
        ends_at: row.try_get("ends_at").map_err(db)?,
        join_not_before: row.try_get("join_not_before").map_err(db)?,
        join_not_after: row.try_get("join_not_after").map_err(db)?,
        max_cost_microusd: as_u64(&row, "meeting_max_cost")?,
        max_duration_seconds: as_u32(&row, "meeting_max_duration")?,
        raw_audio_retention: parse_retention(row.try_get("raw_audio_retention").map_err(db)?)?,
        transcript_retention: parse_retention(row.try_get("transcript_retention").map_err(db)?)?,
        admission_evidence_sha256: digest_column(&row, "admission_evidence_sha256")?,
        consent_evidence_sha256: digest_column(&row, "source_policy_sha256")?,
    };
    if now < grant.join_not_before || now > grant.join_not_after {
        return Err(ApiError::Conflict);
    }
    Ok((policy, grant))
}

async fn load_media_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    session_id: Uuid,
) -> Result<MediaSession, ApiError> {
    let row = sqlx::query(
        "SELECT m.*,r.max_session_duration_seconds,mt.provider_event_id_sha256,mt.data_class, \
                mt.sealed_coordinate_ref,mt.starts_at,mt.ends_at,mt.join_not_before,mt.join_not_after, \
                mt.raw_audio_retention,mt.transcript_retention \
         FROM snowman_meeting_media_sessions m \
         JOIN snowman_meeting_media_routes r ON r.community_id=m.community_id \
           AND r.workspace_id=m.workspace_id AND r.mailbox_identity_id=m.mailbox_identity_id \
         JOIN snowman_meetings mt ON mt.community_id=m.community_id AND mt.meeting_id=m.meeting_id \
         WHERE m.community_id=$1 AND m.media_session_id=$2",
    )
    .bind(tenant_id)
    .bind(session_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?
    .ok_or(ApiError::NotFound)?;
    let grant = MediaExecutionGrant {
        tenant_id,
        workspace_id: row.try_get("workspace_id").map_err(db)?,
        meeting_id: row.try_get("meeting_id").map_err(db)?,
        mailbox_identity_id: row.try_get("mailbox_identity_id").map_err(db)?,
        meeting_agent_identity_id: row.try_get("meeting_agent_identity_id").map_err(db)?,
        provider_event_id_sha256: digest_column(&row, "provider_event_id_sha256")?,
        provider_revision: as_u64(&row, "provider_revision")?,
        schedule_revision: as_u64(&row, "schedule_revision")?,
        session_id,
        session_generation: as_u32_i64(&row, "session_generation")?,
        data_class: parse_data_class(row.try_get("data_class").map_err(db)?)?,
        conference_kind: parse_conference_kind(row.try_get("conference_kind").map_err(db)?)?,
        sealed_coordinate_ref: row.try_get("sealed_coordinate_ref").map_err(db)?,
        conference_approval_sha256: digest_column(&row, "conference_approval_sha256")?,
        ingress_route: parse_ingress_route(row.try_get("ingress_route").map_err(db)?)?,
        conversation_route: parse_conversation_route(
            row.try_get("conversation_route").map_err(db)?,
        )?,
        renderer_route: parse_renderer_route_db(row.try_get("renderer_route").map_err(db)?)?,
        starts_at: row.try_get("starts_at").map_err(db)?,
        ends_at: row.try_get("ends_at").map_err(db)?,
        join_not_before: row.try_get("join_not_before").map_err(db)?,
        join_not_after: row.try_get("join_not_after").map_err(db)?,
        max_cost_microusd: as_u64(&row, "max_cost_microusd")?,
        max_duration_seconds: as_u32(&row, "max_session_duration_seconds")?,
        raw_audio_retention: parse_retention(row.try_get("raw_audio_retention").map_err(db)?)?,
        transcript_retention: parse_retention(row.try_get("transcript_retention").map_err(db)?)?,
        admission_evidence_sha256: digest_column(&row, "admission_evidence_sha256")?,
        consent_evidence_sha256: digest_column(&row, "consent_evidence_sha256")?,
    };
    Ok(MediaSession {
        grant,
        gateway_service_identity_id: row.try_get("gateway_service_identity_id").map_err(db)?,
        provider_binding_sha256: digest_column(&row, "provider_binding_sha256")?,
        status: parse_session_status(row.try_get("status").map_err(db)?)?,
        provider_session_ids_sha256: BTreeMap::new(),
        spent_microusd: as_u64(&row, "spent_microusd")?,
        cost_ceiling_microusd: as_u64(&row, "max_cost_microusd")?,
        started_at: row.try_get("started_at").map_err(db)?,
        deadline: row.try_get("deadline").map_err(db)?,
        stopped_at: row.try_get("stopped_at").map_err(db)?,
        last_receipt_sha256: digest_column(&row, "last_receipt_sha256")?,
    })
}

fn parse_body<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, ApiError> {
    if body.is_empty() || body.len() > MAX_CONTROL_BODY_BYTES {
        return Err(ApiError::Invalid);
    }
    serde_json::from_slice(body).map_err(|_| ApiError::Invalid)
}

fn digest_column(row: &sqlx::postgres::PgRow, column: &str) -> Result<String, ApiError> {
    Ok(hex::encode(row.try_get::<Vec<u8>, _>(column).map_err(db)?))
}
fn as_u64(row: &sqlx::postgres::PgRow, column: &str) -> Result<u64, ApiError> {
    u64::try_from(row.try_get::<i64, _>(column).map_err(db)?).map_err(|_| ApiError::Invalid)
}
fn as_u32(row: &sqlx::postgres::PgRow, column: &str) -> Result<u32, ApiError> {
    u32::try_from(row.try_get::<i32, _>(column).map_err(db)?).map_err(|_| ApiError::Invalid)
}
fn as_u32_i64(row: &sqlx::postgres::PgRow, column: &str) -> Result<u32, ApiError> {
    u32::try_from(row.try_get::<i64, _>(column).map_err(db)?).map_err(|_| ApiError::Invalid)
}

fn provider(value: Provider) -> &'static str {
    match value {
        Provider::SnowmanHuddle => "snowman_huddle",
        Provider::SnowmanAws => "snowman_aws",
        Provider::Twilio => "twilio",
        Provider::OpenAiRealtime => "open_ai_realtime",
        Provider::ElevenLabs => "eleven_labs",
    }
}
fn conference_kind(value: ConferenceKind) -> &'static str {
    match value {
        ConferenceKind::SnowmanHuddle => "snowman_huddle",
        ConferenceKind::GoogleMeet => "google_meet",
        ConferenceKind::Telephony => "telephony",
    }
}
fn ingress_route(value: IngressRoute) -> &'static str {
    match value {
        IngressRoute::SnowmanHuddle => "snowman_huddle",
        IngressRoute::TwilioTelephony => "twilio_telephony",
    }
}
fn conversation_route(value: ConversationRoute) -> &'static str {
    match value {
        ConversationRoute::SnowmanAws => "snowman_aws",
        ConversationRoute::OpenAiRealtime => "open_ai_realtime",
    }
}
fn renderer_route(value: RendererRoute) -> &'static str {
    match value {
        RendererRoute::ConversationNative => "conversation_native",
        RendererRoute::SnowmanAws => "snowman_aws",
        RendererRoute::ElevenLabs => "eleven_labs",
    }
}
fn parse_callback_provider(value: &str) -> Result<Provider, ApiError> {
    match value {
        "twilio" => Ok(Provider::Twilio),
        "open_ai_realtime" => Ok(Provider::OpenAiRealtime),
        _ => Err(ApiError::NotFound),
    }
}
fn parse_conference_kind(value: String) -> Result<ConferenceKind, ApiError> {
    match value.as_str() {
        "snowman_huddle" => Ok(ConferenceKind::SnowmanHuddle),
        "google_meet" => Ok(ConferenceKind::GoogleMeet),
        "telephony" => Ok(ConferenceKind::Telephony),
        _ => Err(ApiError::Invalid),
    }
}
fn parse_ingress_route(value: String) -> Result<IngressRoute, ApiError> {
    match value.as_str() {
        "snowman_huddle" => Ok(IngressRoute::SnowmanHuddle),
        "twilio_telephony" => Ok(IngressRoute::TwilioTelephony),
        _ => Err(ApiError::Invalid),
    }
}
fn parse_conversation_route(value: String) -> Result<ConversationRoute, ApiError> {
    match value.as_str() {
        "snowman_aws" => Ok(ConversationRoute::SnowmanAws),
        "open_ai_realtime" => Ok(ConversationRoute::OpenAiRealtime),
        _ => Err(ApiError::Invalid),
    }
}
fn parse_renderer_route(value: String) -> Result<RendererRoute, ApiError> {
    match value.as_str() {
        "voice_route" => Ok(RendererRoute::ConversationNative),
        "snowman_aws" => Ok(RendererRoute::SnowmanAws),
        "eleven_labs" => Ok(RendererRoute::ElevenLabs),
        _ => Err(ApiError::Invalid),
    }
}
fn parse_renderer_route_db(value: String) -> Result<RendererRoute, ApiError> {
    match value.as_str() {
        "conversation_native" => Ok(RendererRoute::ConversationNative),
        _ => parse_renderer_route(value),
    }
}
fn parse_data_class(value: String) -> Result<DataClass, ApiError> {
    match value.as_str() {
        "internal" => Ok(DataClass::Internal),
        "confidential" => Ok(DataClass::Confidential),
        "restricted" => Ok(DataClass::Restricted),
        _ => Err(ApiError::Invalid),
    }
}
fn parse_retention(value: String) -> Result<RetentionMode, ApiError> {
    match value.as_str() {
        "none" => Ok(RetentionMode::None),
        "analyst_evidence" => Ok(RetentionMode::AnalystEvidence),
        _ => Err(ApiError::Invalid),
    }
}
fn parse_session_status(value: String) -> Result<SessionStatus, ApiError> {
    match value.as_str() {
        "joining" => Ok(SessionStatus::Joining),
        "indeterminate" => Ok(SessionStatus::Indeterminate),
        "active" => Ok(SessionStatus::Active),
        "stopping" => Ok(SessionStatus::Stopping),
        "stopped" => Ok(SessionStatus::Stopped),
        "failed" => Ok(SessionStatus::Failed),
        _ => Err(ApiError::Invalid),
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    value(name).ok_or(ConfigError::Invalid(name))
}
fn value(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}
fn exact_bool(name: &'static str) -> Result<bool, ConfigError> {
    match value(name).as_deref().unwrap_or("false") {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ConfigError::Invalid(name)),
    }
}
fn parse_bounded<T>(name: &'static str, default: &str, min: T, max: T) -> Result<T, ConfigError>
where
    T: FromStr + PartialOrd + Copy,
{
    let parsed = value(name)
        .unwrap_or_else(|| default.into())
        .parse::<T>()
        .map_err(|_| ConfigError::Invalid(name))?;
    if parsed < min || parsed > max {
        return Err(ConfigError::Invalid(name));
    }
    Ok(parsed)
}
fn valid_database_url(value: &str) -> bool {
    if sqlx::postgres::PgConnectOptions::from_str(value).is_err() {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let modes: Vec<_> = url
        .query_pairs()
        .filter_map(|(key, value)| (key == "sslmode").then_some(value.into_owned()))
        .collect();
    url.scheme() == "postgresql"
        && url.host_str().is_some_and(|host| {
            host.ends_with(".rds.amazonaws.com") || host.ends_with(".rds.amazonaws.com.cn")
        })
        && url.port_or_known_default() == Some(5432)
        && !url.username().is_empty()
        && url.password().is_some_and(|password| password.len() >= 32)
        && modes == ["verify-full"]
}
fn parse_private_proxy_origin(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("policy proxy origin"))?;
    let host = url.host_str().unwrap_or_default();
    if value != value.to_ascii_lowercase()
        || url.scheme() != "https"
        || !host.ends_with(".internal.snowmanai.org")
        || url.port() != Some(8443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::Invalid("policy proxy origin"));
    }
    Ok(url)
}

fn db(_error: sqlx::Error) -> ApiError {
    ApiError::Unavailable
}
fn map_domain(error: Error) -> ApiError {
    match error {
        Error::BoundaryMismatch | Error::IdempotencyConflict | Error::InvalidTransition => {
            ApiError::Conflict
        }
        Error::ProviderDisabled | Error::ConsentIncomplete | Error::BudgetExceeded => {
            ApiError::Conflict
        }
        _ => ApiError::Invalid,
    }
}

#[derive(Debug)]
enum ApiError {
    Invalid,
    Unauthorized,
    NotFound,
    Conflict,
    Busy,
    Unavailable,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "authority_conflict"),
            Self::Busy => (StatusCode::TOO_MANY_REQUESTS, "capacity_exhausted"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable"),
        };
        (status, Json(serde_json::json!({ "error": code }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_provider_is_exact() {
        assert_eq!(
            parse_callback_provider("twilio").ok(),
            Some(Provider::Twilio)
        );
        assert!(parse_callback_provider("block").is_err());
        assert!(parse_callback_provider("TWILIO").is_err());
    }

    #[test]
    fn private_proxy_origin_is_snowman_only() {
        assert!(parse_private_proxy_origin(
            "https://providers.staging.internal.snowmanai.org:8443/"
        )
        .is_ok());
        for value in [
            "https://provider.example:8443/",
            "https://block.xyz:8443/",
            "http://providers.staging.internal.snowmanai.org:8443/",
            "https://providers.staging.internal.snowmanai.org/",
        ] {
            assert!(parse_private_proxy_origin(value).is_err(), "{value}");
        }
    }

    #[test]
    fn server_source_has_no_audio_persistence_sink() {
        let source = include_str!("server.rs");
        for forbidden in [
            ["raw_audio", " BYTEA"].concat(),
            ["transcript", "_text"].concat(),
            ["api.openai", ".com"].concat(),
            ["api.twilio", ".com"].concat(),
        ] {
            assert!(!source.contains(&forbidden), "{forbidden}");
        }
        assert!(source.contains("DisabledProviderRuntime"));
        assert!(source.contains("status='indeterminate'"));
    }
}
