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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snowman_agent_contract::{AgentDataPolicy, Classification, JobSnapshot, JOB_SNAPSHOT_SCHEMA};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
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

const ORCHESTRATION_DISPATCH_SCHEMA: &str = "snowman.orchestration.coordinator-dispatch.v1";
const ORCHESTRATION_CONTROL_SCHEMA: &str = "snowman.orchestration.control-command.v1";
const DESTINATION_RECEIPT_SCHEMA: &str = "snowman.orchestration.destination-receipt.v1";

/// Reviewed local mapping from an opaque orchestration model-route coordinate
/// to the existing immutable coordinator runtime catalog.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationRouteProfile {
    /// Opaque Snowman route coordinate, never a provider URL.
    pub model_route_reference: String,
    /// Existing coordinator runtime policy ID.
    pub runtime_id: String,
    /// Exact evaluated model catalog ID.
    pub model_id: String,
    /// Exact specialist role allowed to use the route.
    pub specialist_role: String,
    /// Maximum classification allowed on this route.
    pub classification: Classification,
    /// Reviewed Snowman system policy; no task or client content is loaded here.
    pub system_prompt: String,
    /// Hard input token ceiling.
    pub max_input_tokens: u64,
    /// Hard output token ceiling.
    pub max_output_tokens: u64,
}

impl OrchestrationRouteProfile {
    fn validate(&self) -> Result<(), ConfigError> {
        if !valid_route_reference(&self.model_route_reference)
            || !valid_policy_label(&self.runtime_id, 128)
            || !valid_policy_label(&self.model_id, 128)
            || !valid_policy_label(&self.specialist_role, 64)
            || self.system_prompt.is_empty()
            || self.system_prompt.len() > 4096
            || self.system_prompt.contains("http://")
            || self.system_prompt.contains("https://")
            || self.max_input_tokens == 0
            || self.max_input_tokens > 1_000_000
            || self.max_output_tokens == 0
            || self.max_output_tokens > 250_000
        {
            return Err(ConfigError::Invalid(
                "orchestration route profile is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorDispatchEnvelope {
    schema_version: String,
    community_id: Uuid,
    workspace_id: Uuid,
    dispatch_id: Uuid,
    plan_id: Uuid,
    plan_generation: u64,
    request_id: Uuid,
    task_id: Uuid,
    execution_snapshot_sha256: String,
    model_id: String,
    specialist_role: String,
    classification: Classification,
    lease_generation: u64,
    cancellation_generation: u64,
    coordinator_job_reference: String,
    model_route_reference: String,
    analyst_context_references: Vec<String>,
    required_capabilities: Vec<String>,
    reserved_cost_microusd: u64,
    deadline_at: chrono::DateTime<Utc>,
    lease_expires_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OrchestrationControlKind {
    CancelDispatch,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrchestrationCancellationCommand {
    schema_version: String,
    community_id: Uuid,
    workspace_id: Uuid,
    outbox_id: Uuid,
    command_kind: OrchestrationControlKind,
    plan_id: Uuid,
    plan_generation: u64,
    dispatch_id: Option<Uuid>,
    occurrence_id: Uuid,
    command_sha256: String,
    coordinator_job_reference: Option<String>,
    lease_generation: u64,
    lease_expires_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct DestinationReceipt {
    schema_version: String,
    request_id: Uuid,
    delivery_reference: String,
    response_sha256: String,
}

/// Exact service configuration loaded from a dedicated secret and static ECS policy.
pub struct Config {
    bind_addr: SocketAddr,
    database_url: String,
    database_role: String,
    max_connections: u32,
    public_origin: Url,
    coordinator: CoordinatorConfig,
    token_hmac_key_arn: String,
    orchestration_routes: BTreeMap<String, OrchestrationRouteProfile>,
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
        let profiles: Vec<OrchestrationRouteProfile> = serde_json::from_str(&required(
            "SNOWMAN_AGENT_COORDINATOR_ORCHESTRATION_ROUTES_JSON",
        )?)
        .map_err(|_| ConfigError::Invalid("orchestration route JSON is invalid"))?;
        let mut orchestration_routes = BTreeMap::new();
        for profile in profiles {
            profile.validate()?;
            if orchestration_routes
                .insert(profile.model_route_reference.clone(), profile)
                .is_some()
            {
                return Err(ConfigError::Invalid(
                    "orchestration model route references must be unique",
                ));
            }
        }
        if max_connections == 0
            || max_connections > 16
            || !valid_database_url(&database_url)
            || orchestration_routes.len() > 32
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
            orchestration_routes,
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
    orchestration_routes: Arc<BTreeMap<String, OrchestrationRouteProfile>>,
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
            orchestration_routes: Arc::new(config.orchestration_routes),
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
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/orchestration/dispatches/{dispatch_id}",
            post(post_orchestration_dispatch),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/orchestration/cancellations/{outbox_id}",
            post(post_orchestration_cancellation),
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

async fn post_orchestration_dispatch(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id, dispatch_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<DestinationReceipt>, ApiError> {
    check_orchestration_body(&body)?;
    let expected_url = state
        .public_origin
        .join(&format!(
            "v1/tenants/{tenant_id}/workspaces/{workspace_id}/orchestration/dispatches/{dispatch_id}"
        ))
        .map_err(|_| ApiError::Internal)?;
    let auth = verify_auth(&headers, expected_url.as_str(), &body)?;
    let command: CoordinatorDispatchEnvelope =
        serde_json::from_slice(&body).map_err(|_| ApiError::Invalid)?;
    validate_dispatch(&command, tenant_id, workspace_id, dispatch_id)?;
    let body_sha256: [u8; 32] = Sha256::digest(&body).into();
    if let Some(receipt) = claim_destination_receipt(
        &state.pool,
        tenant_id,
        workspace_id,
        "dispatch",
        dispatch_id,
        body_sha256,
        &command.coordinator_job_reference,
    )
    .await?
    {
        return Ok(Json(receipt));
    }
    let route = state
        .orchestration_routes
        .get(&command.model_route_reference)
        .ok_or(ApiError::Invalid)?;
    if route.model_id != command.model_id
        || route.specialist_role != command.specialist_role
        || route.classification != command.classification
    {
        return Err(ApiError::Invalid);
    }
    let (job_id, generation) = parse_job_reference(&command.coordinator_job_reference)?;
    let prompt = serde_json::to_string(&serde_json::json!({
        "schema_version": "snowman.orchestration.agent-projection.v1",
        "plan_id": command.plan_id,
        "plan_generation": command.plan_generation,
        "task_id": command.task_id,
        "context_manifest_references": command.analyst_context_references,
    }))
    .map_err(|_| ApiError::Internal)?;
    let snapshot = JobSnapshot {
        schema_version: JOB_SNAPSHOT_SCHEMA.into(),
        job_id,
        tenant_id: tenant_id.to_string(),
        workspace_id,
        request_id: command.request_id,
        task_id: command.task_id,
        generation,
        runtime_id: route.runtime_id.clone(),
        model_id: route.model_id.clone(),
        specialist_role: route.specialist_role.clone(),
        classification: route.classification,
        data_policy: AgentDataPolicy {
            pii_prohibited: true,
            minimization_evidence_sha256: command.execution_snapshot_sha256.clone(),
        },
        system_prompt: route.system_prompt.clone(),
        prompt,
        capability_grants: command.required_capabilities.clone(),
        max_input_tokens: route.max_input_tokens,
        max_output_tokens: route.max_output_tokens,
        max_cost_microusd: command.reserved_cost_microusd,
        deadline_at: command.deadline_at,
    };
    let now = Utc::now();
    state
        .coordinator
        .submit_orchestrated(VerifiedLaunchRequest {
            snapshot,
            request_sha256: body_sha256,
            requester_pubkey: auth.pubkey,
            auth_event_id: auth.event_id,
            auth_observed_at: now,
            auth_expires_at: now + ChronoDuration::seconds(AUTH_EVIDENCE_SECONDS),
        })
        .await
        .map_err(ApiError::from)?;
    let response_sha256 = stable_destination_digest(
        "dispatch",
        dispatch_id,
        &command.coordinator_job_reference,
        body_sha256,
    );
    let receipt = DestinationReceipt {
        schema_version: DESTINATION_RECEIPT_SCHEMA.into(),
        request_id: dispatch_id,
        delivery_reference: command.coordinator_job_reference,
        response_sha256,
    };
    complete_destination_receipt(&state.pool, tenant_id, dispatch_id, &receipt).await?;
    Ok(Json(receipt))
}

async fn post_orchestration_cancellation(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id, outbox_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<DestinationReceipt>, ApiError> {
    check_orchestration_body(&body)?;
    let expected_url = state
        .public_origin
        .join(&format!(
            "v1/tenants/{tenant_id}/workspaces/{workspace_id}/orchestration/cancellations/{outbox_id}"
        ))
        .map_err(|_| ApiError::Internal)?;
    verify_auth(&headers, expected_url.as_str(), &body)?;
    let command: OrchestrationCancellationCommand =
        serde_json::from_slice(&body).map_err(|_| ApiError::Invalid)?;
    let reference = validate_cancellation(&command, tenant_id, workspace_id, outbox_id)?;
    let body_sha256: [u8; 32] = Sha256::digest(&body).into();
    if let Some(receipt) = claim_destination_receipt(
        &state.pool,
        tenant_id,
        workspace_id,
        "cancel",
        outbox_id,
        body_sha256,
        &reference,
    )
    .await?
    {
        return Ok(Json(receipt));
    }
    let (job_id, _) = parse_job_reference(&reference)?;
    state
        .coordinator
        .cancel_job(tenant_id, job_id, "orchestration_cancelled")
        .await
        .map_err(ApiError::from)?;
    let receipt = DestinationReceipt {
        schema_version: DESTINATION_RECEIPT_SCHEMA.into(),
        request_id: outbox_id,
        delivery_reference: reference.clone(),
        response_sha256: stable_destination_digest("cancel", outbox_id, &reference, body_sha256),
    };
    complete_destination_receipt(&state.pool, tenant_id, outbox_id, &receipt).await?;
    Ok(Json(receipt))
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

fn check_orchestration_body(body: &[u8]) -> Result<(), ApiError> {
    if body.is_empty() || body.len() > 256 * 1024 {
        Err(ApiError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_dispatch(
    command: &CoordinatorDispatchEnvelope,
    tenant_id: Uuid,
    workspace_id: Uuid,
    dispatch_id: Uuid,
) -> Result<(), ApiError> {
    let now = Utc::now();
    if command.schema_version != ORCHESTRATION_DISPATCH_SCHEMA
        || command.community_id != tenant_id
        || command.workspace_id != workspace_id
        || command.dispatch_id != dispatch_id
        || command.plan_id.is_nil()
        || command.plan_generation == 0
        || command.request_id.is_nil()
        || command.task_id.is_nil()
        || command.lease_generation == 0
        || command.cancellation_generation > i64::MAX as u64
        || command.reserved_cost_microusd == 0
        || command.deadline_at <= now
        || command.lease_expires_at <= now
        || command.lease_expires_at > now + ChronoDuration::minutes(20)
        || !valid_sha256(&command.execution_snapshot_sha256)
        || command.analyst_context_references.is_empty()
        || command.analyst_context_references.len() > 32
        || command.required_capabilities.is_empty()
        || command.required_capabilities.len() > 32
        || command
            .analyst_context_references
            .iter()
            .any(|value| !valid_analyst_reference(value))
        || command
            .required_capabilities
            .iter()
            .any(|value| !valid_policy_label(value, 128) || value.contains('*'))
    {
        return Err(ApiError::Invalid);
    }
    parse_job_reference(&command.coordinator_job_reference)?;
    Ok(())
}

fn validate_cancellation(
    command: &OrchestrationCancellationCommand,
    tenant_id: Uuid,
    workspace_id: Uuid,
    outbox_id: Uuid,
) -> Result<String, ApiError> {
    if command.schema_version != ORCHESTRATION_CONTROL_SCHEMA
        || command.community_id != tenant_id
        || command.workspace_id != workspace_id
        || command.outbox_id != outbox_id
        || command.command_kind != OrchestrationControlKind::CancelDispatch
        || command.plan_id.is_nil()
        || command.plan_generation == 0
        || command.dispatch_id.is_none_or(|value| value.is_nil())
        || command.occurrence_id.is_nil()
        || command.lease_generation == 0
        || command.lease_expires_at <= Utc::now()
        || !valid_sha256(&command.command_sha256)
    {
        return Err(ApiError::Invalid);
    }
    let reference = command
        .coordinator_job_reference
        .clone()
        .ok_or(ApiError::Invalid)?;
    parse_job_reference(&reference)?;
    Ok(reference)
}

fn parse_job_reference(reference: &str) -> Result<(Uuid, u32), ApiError> {
    let fields = reference.split(':').collect::<Vec<_>>();
    if fields.len() != 5 || fields[0..2] != ["snowman", "agent-job"] || fields[3] != "generation" {
        return Err(ApiError::Invalid);
    }
    let job_id = Uuid::parse_str(fields[2]).map_err(|_| ApiError::Invalid)?;
    let generation = fields[4].parse::<u32>().map_err(|_| ApiError::Invalid)?;
    if job_id.is_nil() || generation == 0 {
        return Err(ApiError::Invalid);
    }
    Ok((job_id, generation))
}

async fn claim_destination_receipt(
    pool: &PgPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    destination_kind: &str,
    request_id: Uuid,
    request_sha256: [u8; 32],
    delivery_reference: &str,
) -> Result<Option<DestinationReceipt>, ApiError> {
    let authority_exists: bool = match destination_kind {
        "dispatch" => sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM snowman_orchestration_dispatches \
             WHERE community_id=$1 AND workspace_id=$2 AND dispatch_id=$3)",
        )
        .bind(tenant_id)
        .bind(workspace_id)
        .bind(request_id)
        .fetch_one(pool)
        .await
        .map_err(|_| ApiError::Internal)?,
        "cancel" => sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM snowman_orchestration_control_outbox \
             WHERE community_id=$1 AND workspace_id=$2 AND outbox_id=$3 AND command_kind='cancel_dispatch')",
        )
        .bind(tenant_id)
        .bind(workspace_id)
        .bind(request_id)
        .fetch_one(pool)
        .await
        .map_err(|_| ApiError::Internal)?,
        _ => return Err(ApiError::Invalid),
    };
    if !authority_exists {
        return Err(ApiError::Conflict);
    }
    sqlx::query(
        "INSERT INTO snowman_orchestration_destination_receipts \
         (community_id,workspace_id,destination_kind,request_id,request_sha256,delivery_reference,status) \
         VALUES ($1,$2,$3,$4,$5,$6,'processing') ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(destination_kind)
    .bind(request_id)
    .bind(request_sha256.as_slice())
    .bind(delivery_reference)
    .execute(pool)
    .await
    .map_err(|_| ApiError::Internal)?;
    let row = sqlx::query(
        "SELECT workspace_id,destination_kind,request_sha256,delivery_reference,status,response_sha256 \
         FROM snowman_orchestration_destination_receipts WHERE community_id=$1 AND request_id=$2",
    )
    .bind(tenant_id)
    .bind(request_id)
    .fetch_one(pool)
    .await
    .map_err(|_| ApiError::Internal)?;
    if row.try_get::<Uuid, _>("workspace_id").ok() != Some(workspace_id)
        || row.try_get::<String, _>("destination_kind").ok().as_deref() != Some(destination_kind)
        || row.try_get::<Vec<u8>, _>("request_sha256").ok().as_deref()
            != Some(request_sha256.as_slice())
        || row
            .try_get::<String, _>("delivery_reference")
            .ok()
            .as_deref()
            != Some(delivery_reference)
    {
        return Err(ApiError::Conflict);
    }
    if row.try_get::<String, _>("status").ok().as_deref() == Some("completed") {
        let response = row
            .try_get::<Vec<u8>, _>("response_sha256")
            .map_err(|_| ApiError::Internal)?;
        if response.len() != 32 {
            return Err(ApiError::Internal);
        }
        return Ok(Some(DestinationReceipt {
            schema_version: DESTINATION_RECEIPT_SCHEMA.into(),
            request_id,
            delivery_reference: delivery_reference.into(),
            response_sha256: hex::encode(response),
        }));
    }
    Ok(None)
}

async fn complete_destination_receipt(
    pool: &PgPool,
    tenant_id: Uuid,
    request_id: Uuid,
    receipt: &DestinationReceipt,
) -> Result<(), ApiError> {
    let response = hex::decode(&receipt.response_sha256).map_err(|_| ApiError::Internal)?;
    let updated = sqlx::query(
        "UPDATE snowman_orchestration_destination_receipts SET status='completed',response_sha256=$1,completed_at=NOW() \
         WHERE community_id=$2 AND request_id=$3 AND delivery_reference=$4 AND status IN ('processing','completed')",
    )
    .bind(response)
    .bind(tenant_id)
    .bind(request_id)
    .bind(&receipt.delivery_reference)
    .execute(pool)
    .await
    .map_err(|_| ApiError::Internal)?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::Conflict);
    }
    Ok(())
}

fn stable_destination_digest(
    kind: &str,
    request_id: Uuid,
    reference: &str,
    request_sha256: [u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.orchestration.destination-receipt.v1\0");
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(request_id.as_bytes());
    hasher.update(reference.as_bytes());
    hasher.update(request_sha256);
    hex::encode(hasher.finalize())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_policy_label(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_route_reference(value: &str) -> bool {
    value.starts_with("snowman:model-route:")
        && value.contains(":revision:")
        && valid_policy_label(value, 192)
}

fn valid_analyst_reference(value: &str) -> bool {
    value.starts_with("snowman:analyst360:") && value.len() <= 256 && valid_policy_label(value, 256)
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

    #[test]
    fn orchestration_job_reference_is_exact_and_generation_bound() {
        let job = Uuid::new_v4();
        assert_eq!(
            parse_job_reference(&format!("snowman:agent-job:{job}:generation:7")).unwrap(),
            (job, 7)
        );
        for denied in [
            format!("snowman:agent-job:{job}:generation:0"),
            format!("https://coordinator/{job}"),
            format!("snowman:agent-job:{job}:generation:7:extra"),
        ] {
            assert!(parse_job_reference(&denied).is_err(), "{denied}");
        }
    }

    #[test]
    fn orchestration_route_profile_rejects_provider_urls() {
        let mut profile = OrchestrationRouteProfile {
            model_route_reference: format!("snowman:model-route:{}:revision:1", Uuid::new_v4()),
            runtime_id: "native-acp".into(),
            model_id: "snowman-evaluated-model-v1".into(),
            specialist_role: "research_analyst".into(),
            classification: Classification::Confidential,
            system_prompt: "Use only governed Snowman references and capabilities.".into(),
            max_input_tokens: 16_000,
            max_output_tokens: 4_000,
        };
        assert!(profile.validate().is_ok());
        profile.system_prompt = "send to https://attacker.test".into();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn destination_receipt_digest_is_stable_and_request_bound() {
        let request_id = Uuid::new_v4();
        let reference = format!("snowman:agent-job:{}:generation:1", Uuid::new_v4());
        let first = stable_destination_digest("dispatch", request_id, &reference, [3; 32]);
        assert_eq!(
            first,
            stable_destination_digest("dispatch", request_id, &reference, [3; 32])
        );
        assert_ne!(
            first,
            stable_destination_digest("cancel", request_id, &reference, [3; 32])
        );
        assert!(valid_sha256(&first));
    }

    #[test]
    fn destination_authority_rejects_orphan_and_cross_workspace_coordinates() {
        let source = include_str!("service.rs");
        for query in [
            "WHERE community_id=$1 AND workspace_id=$2 AND dispatch_id=$3",
            "WHERE community_id=$1 AND workspace_id=$2 AND outbox_id=$3",
        ] {
            assert!(source.contains(query), "{query}");
        }
        let migration =
            include_str!("../../../migrations/0059_snowman_orchestration_destinations.sql");
        assert!(migration.contains("FOREIGN KEY (community_id, workspace_id, dispatch_id)"));
        assert!(migration.contains("FOREIGN KEY (community_id, workspace_id, outbox_id)"));
    }
}
