//! Governed Snowman AI Workforce HTTP API.
//!
//! Human callers submit objectives through a live Snowman workforce session.
//! The relay derives tenant and actor identity server-side, creates only a
//! capability-bounded planning task, and returns a metadata-only status view.
//! Specialist execution remains behind the private worker plane.

use std::{collections::BTreeSet, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use buzz_auth::LimitType;
use buzz_db::workforce::{
    NewContextPacket, NewPlannedTask, NewProactiveAction, NewWorkPlan, NewWorkRequest, NewWorkTask,
    SpendEntry, StoredContextPacket, StoredModelRoute, WorkApproval, WorkRequestCancellation,
    WorkTaskCompletion,
};
use snowman_workforce::{
    decide_proactive_action, govern_team_plan, Classification, ContextAuthority, ContextNextAction,
    ContextPacketManifest, GovernedTeamPlan, ModelRoute, PlannedTask, ProactiveAction,
    ProactiveDecision, ProactiveTrigger, RiskTier, SpecialistRole,
};

use crate::{authorization, state::AppState};

use super::{api_error, bridge, internal_error, relay_members};

const CREATE_PATH: &str = "/api/snowman/v1/work-requests";
const MAX_OBJECTIVE_BYTES: usize = 8_000;
const MAX_CONTEXT_REFS: usize = 64;
const DEFAULT_MAX_COST_MICROUSD: i64 = 25_000_000;
const MAX_COST_MICROUSD: i64 = 500_000_000;
const DEFAULT_MAX_INPUT_TOKENS: i64 = 2_000_000;
const MAX_INPUT_TOKENS: i64 = 20_000_000;
const DEFAULT_MAX_OUTPUT_TOKENS: i64 = 500_000;
const MAX_OUTPUT_TOKENS: i64 = 5_000_000;
const WORKER_PATH: &str = "/internal/snowman/v1/workforce";
const LEASE_SECONDS: i64 = 120;

type HmacSha256 = Hmac<Sha256>;

/// Bounded, metadata-only objective accepted from an authorized human.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateWorkRequest {
    objective: String,
    #[serde(default = "default_classification")]
    classification: String,
    #[serde(default)]
    deadline_at: Option<DateTime<Utc>>,
    #[serde(default = "default_max_cost")]
    max_cost_microusd: i64,
    #[serde(default = "default_max_input")]
    max_input_tokens: i64,
    #[serde(default = "default_max_output")]
    max_output_tokens: i64,
    #[serde(default = "default_true")]
    client_ready_delivery: bool,
    #[serde(default)]
    context_references: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimWorkTask {
    claim_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceTickRequest {
    schema_version: String,
    tick_id: Uuid,
    requested_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseProof {
    generation: i64,
    lease_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelWorkRequest {
    cancellation_id: Uuid,
    reason_code: String,
    occurred_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideWorkTaskApproval {
    approval_id: Uuid,
    task_snapshot_sha256: String,
    decision: String,
    rationale_sha256: String,
    decided_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordSpendRequest {
    generation: i64,
    lease_token: String,
    ledger_entry_id: Uuid,
    request_id: Uuid,
    model_id: String,
    input_tokens: i64,
    output_tokens: i64,
    cost_microusd: i64,
    provider_receipt_sha256: String,
    recorded_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishWorkTaskRequest {
    generation: i64,
    lease_token: String,
    completion_id: Uuid,
    succeeded: bool,
    result_sha256: String,
    #[serde(default)]
    artifact_references: Vec<String>,
    #[serde(default)]
    failure_code: Option<String>,
    occurred_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitTeamPlanRequest {
    schema_version: String,
    plan_id: Uuid,
    request_id: Uuid,
    generation: i64,
    lease_token: String,
    tasks: Vec<ProposedTeamTask>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishContextPacketRequest {
    schema_version: String,
    context_packet_id: Uuid,
    source_task_id: Uuid,
    generation: i64,
    lease_token: String,
    classification: Classification,
    authority: ContextAuthority,
    objective_sha256: String,
    content_reference: String,
    content_sha256: String,
    source_event_sha256: String,
    size_bytes: u64,
    #[serde(default)]
    artifact_references: BTreeSet<String>,
    #[serde(default)]
    evidence_references: BTreeSet<String>,
    #[serde(default)]
    decision_digests: BTreeSet<String>,
    #[serde(default)]
    open_question_digests: BTreeSet<String>,
    #[serde(default)]
    next_actions: Vec<ContextNextActionInput>,
    artifact_id: String,
    artifact_version: String,
    artifact_type: String,
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
    occurred_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextNextActionInput {
    action_id: Uuid,
    capability: String,
    risk_tier: RiskTier,
    reversible: bool,
    approval_required: bool,
    expected_cost_microusd: u64,
    confidence_basis_points: u16,
    usefulness_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposeProactiveActionRequest {
    schema_version: String,
    action_id: Uuid,
    trigger: ProactiveTrigger,
    capability: String,
    executor_identity_id: Uuid,
    specialist_role: SpecialistRole,
    instruction_reference: String,
    #[serde(default)]
    context_references: BTreeSet<String>,
    #[serde(default)]
    requested_model_id: Option<String>,
    expected_input_tokens: u64,
    max_output_tokens: u64,
    expected_artifact_type: String,
    #[serde(default = "default_proactive_max_attempts")]
    max_attempts: i32,
    risk_tier: RiskTier,
    reversible: bool,
    expected_cost_microusd: u64,
    confidence_basis_points: u16,
    usefulness_sha256: String,
    source_event_sha256: String,
    scheduled_for: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    occurred_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposedTeamTask {
    task_id: Uuid,
    service_identity_id: Uuid,
    specialist_role: SpecialistRole,
    #[serde(default)]
    depends_on: BTreeSet<Uuid>,
    required_capabilities: BTreeSet<String>,
    #[serde(default)]
    context_references: BTreeSet<String>,
    #[serde(default)]
    requested_model_id: Option<String>,
    expected_input_tokens: u64,
    max_output_tokens: u64,
    max_cost_microusd: u64,
    risk_tier: RiskTier,
    reversible: bool,
    approval_required: bool,
    expected_artifact_type: String,
}

fn default_classification() -> String {
    "confidential".to_string()
}

const fn default_max_cost() -> i64 {
    DEFAULT_MAX_COST_MICROUSD
}

const fn default_max_input() -> i64 {
    DEFAULT_MAX_INPUT_TOKENS
}

const fn default_max_output() -> i64 {
    DEFAULT_MAX_OUTPUT_TOKENS
}

const fn default_true() -> bool {
    true
}

const fn default_proactive_max_attempts() -> i32 {
    3
}

async fn authenticate_principal(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    capability: &str,
    required_identity_type: &str,
) -> Result<
    (
        buzz_core::TenantContext,
        buzz_db::workforce_identity::WorkforcePrincipal,
    ),
    (StatusCode, Json<Value>),
> {
    if state.config.snowman_workforce.is_none() {
        return Err(api_error(StatusCode::NOT_FOUND, "not found"));
    }
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "not found"))?;
    let expected_url = bridge::nip98_expected_url(&state.config.relay_url, &tenant, path);
    let (pubkey, event_id) = bridge::verify_bridge_auth_with_options(
        headers,
        method,
        &expected_url,
        body,
        true,
        body.is_some(),
    )?;
    bridge::check_nip98_replay(state, &tenant, event_id).await?;
    relay_members::enforce_relay_membership(state, tenant.community(), pubkey.as_bytes(), None)
        .await?;
    let principal = authorization::require_workforce_capability(
        state,
        tenant.community(),
        &pubkey,
        capability,
        Some(required_identity_type),
    )
    .await
    .map_err(|error| {
        tracing::warn!(community = %tenant.community(), %error, "workforce API authorization denied");
        api_error(StatusCode::FORBIDDEN, "workforce operation is not authorized")
    })?;
    enforce_workforce_admission(state, &tenant, &pubkey, &principal.identity_type).await?;
    Ok((tenant, principal))
}

async fn enforce_workforce_admission(
    state: &AppState,
    tenant: &buzz_core::TenantContext,
    pubkey: &nostr::PublicKey,
    identity_type: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let limits = &state.auth.config().rate_limits;
    let limit = if identity_type == "service" {
        limits.agent_standard_api_calls_per_min
    } else {
        limits.human_api_calls_per_min
    };
    match crate::admission::check_principal(
        state.admission_rate_limiter.as_ref(),
        tenant,
        pubkey,
        LimitType::ApiCalls,
        60,
        limit,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(crate::admission::AdmissionError::Exceeded { reset_in_secs }) => Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("workforce API quota exceeded; retry in {reset_in_secs}s"),
        )),
        Err(crate::admission::AdmissionError::Unavailable) => Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "workforce admission control is unavailable",
        )),
    }
}

/// Accept one idempotent user objective and enqueue its governed planning task.
pub async fn create_work_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        CREATE_PATH,
        Some(&body),
        "workforce.requests.create",
        "human",
    )
    .await?;
    let mut input: CreateWorkRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid work request JSON"))?;
    validate_input(&input)?;
    input.context_references.sort();
    input.context_references.dedup();
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "a 1-256 character Idempotency-Key header is required",
            )
        })?;
    if !idempotency_key
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Idempotency-Key contains unsupported characters",
        ));
    }

    let workforce = state
        .config
        .snowman_workforce
        .as_ref()
        .expect("workforce presence checked during authentication");
    let lead_can_plan = state
        .db
        .active_service_identity_has_capability(
            tenant.community(),
            workforce.lead_service_identity_id,
            "workforce.plan",
        )
        .await
        .map_err(|_| internal_error("workforce lead identity verification failed"))?;
    let lead_can_execute = state
        .db
        .active_service_identity_has_capability(
            tenant.community(),
            workforce.lead_service_identity_id,
            "workforce.tasks.execute",
        )
        .await
        .map_err(|_| internal_error("workforce lead identity verification failed"))?;
    let model_routes = state
        .db
        .active_model_routes(tenant.community())
        .await
        .map_err(|_| internal_error("workforce planning model verification failed"))?;
    let planning_model_ready = model_routes.iter().any(|route| {
        route.model_id == workforce.planning_model_id
            && route.gateway_url == workforce.model_gateway_url
            && route.suited_roles.iter().any(|role| role == "lead")
            && route
                .allowed_classifications
                .iter()
                .any(|classification| classification == &input.classification)
    });
    if !lead_can_plan || !lead_can_execute || !planning_model_ready {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Snowman workforce planning identity or evaluated model route is not ready",
        ));
    }
    let objective = input.objective.trim().to_string();
    let request_contract_sha256 = request_contract_digest(
        tenant.community().as_uuid(),
        principal.identity_id,
        &objective,
        &input,
    );
    let request_id = Uuid::new_v4();
    let task_id = Uuid::new_v4();
    let objective_sha256: [u8; 32] = Sha256::digest(objective.as_bytes()).into();
    let requester_identity = format!("snowman:{}", principal.identity_id);
    let snapshot_sha256 = planning_snapshot(
        tenant.community().as_uuid(),
        request_id,
        task_id,
        principal.identity_id,
        workforce.lead_service_identity_id,
        &objective_sha256,
        &request_contract_sha256,
        &workforce.model_gateway_url,
        &workforce.planning_model_id,
    );
    let task = NewWorkTask {
        task_id,
        parent_task_id: None,
        specialist_role: "lead".to_string(),
        service_identity_id: workforce.lead_service_identity_id,
        assigned_agent_pubkey: None,
        required_capabilities: vec!["workforce.plan".to_string()],
        model_gateway_route: workforce.model_gateway_url.clone(),
        model_id: workforce.planning_model_id.clone(),
        max_cost_microusd: input.max_cost_microusd.min(2_000_000),
        expected_input_tokens: input.max_input_tokens.min(100_000),
        max_output_tokens: input.max_output_tokens.min(20_000),
        execution_snapshot_sha256: snapshot_sha256,
        expected_artifact_contract: json!({
            "schema_version": "snowman.team_plan.v1",
            "objective_sha256": hex::encode(objective_sha256),
            "client_ready_delivery": input.client_ready_delivery,
            "context_references": input.context_references,
            "requirements": {
                "specialist_scopes_are_explicit": true,
                "model_is_selected_per_specialist": true,
                "independent_quality_review_for_client_ready_work": input.client_ready_delivery,
                "raw_client_data_remains_in_analyst360": true,
                "unsafe_or_irreversible_steps_require_approval": true
            }
        }),
        context_references: input.context_references.clone(),
        context_packet_id: None,
        risk_tier: "low".to_string(),
        reversible: true,
        approval_required: false,
        priority: 80,
        available_at: Utc::now(),
        deadline_at: input.deadline_at,
        max_attempts: 3,
    };
    let request = NewWorkRequest {
        request_id,
        idempotency_key: idempotency_key.to_string(),
        requester_identity,
        request_contract_sha256,
        objective,
        classification: input.classification.clone(),
        deadline_at: input.deadline_at,
        max_cost_microusd: input.max_cost_microusd,
        max_input_tokens: input.max_input_tokens,
        max_output_tokens: input.max_output_tokens,
        client_ready_delivery: input.client_ready_delivery,
        tasks: vec![task],
    };
    let accepted = state
        .db
        .enqueue_work_request(tenant.community(), &request)
        .await
        .map_err(|error| {
            tracing::warn!(community = %tenant.community(), %error, "workforce request rejected by persistence policy");
            match error {
                buzz_db::DbError::AccessDenied(_) | buzz_db::DbError::InvalidData(_) => {
                    api_error(StatusCode::CONFLICT, "work request conflicts with governed policy")
                }
                _ => internal_error("workforce request persistence failed"),
            }
        })?;
    metrics::counter!(
        "snowman_workforce_requests_total",
        "outcome" => if accepted.inserted { "accepted" } else { "idempotent_replay" }
    )
    .increment(1);
    Ok((
        if accepted.inserted {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        Json(json!({
            "schema_version": "snowman.work.request.accepted.v1",
            "request_id": accepted.request_id,
            "status": "planned",
            "inserted": accepted.inserted,
            "status_url": format!("{CREATE_PATH}/{}", accepted.request_id),
        })),
    ))
}

/// Return tenant-scoped lifecycle, budget, task, and evidence metadata.
pub async fn get_work_request(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let path = format!("{CREATE_PATH}/{request_id}");
    let (tenant, _) = authenticate_principal(
        &state,
        &headers,
        "GET",
        &path,
        None,
        "workforce.requests.read",
        "human",
    )
    .await?;
    let status = state
        .db
        .get_work_request_status(tenant.community(), request_id)
        .await
        .map_err(|_| internal_error("workforce status read failed"))?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "work request not found"))?;
    Ok(Json(json!({
        "schema_version": "snowman.work.request.status.v1",
        "request": status,
    })))
}

/// Atomically stop a request, cancel non-terminal tasks, and fence live workers.
pub async fn cancel_work_request(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<Uuid>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let path = format!("{CREATE_PATH}/{request_id}/cancel");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.requests.cancel",
        "human",
    )
    .await?;
    let input: CancelWorkRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid cancellation JSON"))?;
    if request_id.is_nil()
        || input.cancellation_id.is_nil()
        || !is_reason_code(&input.reason_code)
        || !is_recent_worker_time(input.occurred_at)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "cancellation has invalid identity, reason, or time fields",
        ));
    }
    let cancellation = WorkRequestCancellation {
        cancellation_id: input.cancellation_id,
        request_id,
        actor_identity: format!("snowman:{}", principal.identity_id),
        reason_code: input.reason_code,
        occurred_at: input.occurred_at,
    };
    let cancelled = state
        .db
        .cancel_work_request(tenant.community(), &cancellation)
        .await
        .map_err(|error| match error {
            buzz_db::DbError::AccessDenied(_) | buzz_db::DbError::InvalidData(_) => api_error(
                StatusCode::CONFLICT,
                "work request cannot be cancelled from its current state",
            ),
            _ => internal_error("workforce cancellation persistence failed"),
        })?
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "work request not found"))?;
    metrics::counter!(
        "snowman_workforce_cancellations_total",
        "outcome" => if cancelled.inserted { "cancelled" } else { "idempotent_replay" }
    )
    .increment(1);
    Ok(Json(json!({
        "schema_version": "snowman.work.request.cancelled.v1",
        "request_id": cancelled.request_id,
        "cancellation_id": cancellation.cancellation_id,
        "cancelled_task_count": cancelled.cancelled_task_count,
        "inserted": cancelled.inserted,
        "status": "cancelled",
    })))
}

/// Record a human decision bound to the task's exact execution snapshot.
pub async fn decide_work_task_approval(
    State(state): State<Arc<AppState>>,
    Path((request_id, task_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let path = format!("{CREATE_PATH}/{request_id}/tasks/{task_id}/approval");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.tasks.approve",
        "human",
    )
    .await?;
    let input: DecideWorkTaskApproval = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid approval JSON"))?;
    if request_id.is_nil()
        || task_id.is_nil()
        || input.approval_id.is_nil()
        || !matches!(input.decision.as_str(), "approved" | "denied" | "revoked")
        || !is_recent_worker_time(input.decided_at)
        || input.expires_at <= input.decided_at
        || input.expires_at - input.decided_at > Duration::hours(24)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "approval has invalid identity, decision, time, or expiry fields",
        ));
    }
    let approval = WorkApproval {
        approval_id: input.approval_id,
        request_id,
        task_id,
        task_snapshot_sha256: parse_sha256(&input.task_snapshot_sha256, "task_snapshot_sha256")?,
        decision: input.decision,
        approver_identity: format!("snowman:{}", principal.identity_id),
        rationale_sha256: parse_sha256(&input.rationale_sha256, "rationale_sha256")?,
        decided_at: input.decided_at,
        expires_at: input.expires_at,
    };
    let inserted = state
        .db
        .record_work_approval(tenant.community(), &approval)
        .await
        .map_err(|error| match error {
            buzz_db::DbError::AccessDenied(_) | buzz_db::DbError::InvalidData(_) => api_error(
                StatusCode::CONFLICT,
                "approval conflicts with the current task snapshot or lifecycle",
            ),
            _ => internal_error("workforce approval persistence failed"),
        })?;
    metrics::counter!(
        "snowman_workforce_approvals_total",
        "decision" => approval.decision.clone(),
        "outcome" => if inserted { "recorded" } else { "idempotent_replay" }
    )
    .increment(1);
    Ok(Json(json!({
        "schema_version": "snowman.work.task.approval.v1",
        "approval_id": approval.approval_id,
        "request_id": request_id,
        "task_id": task_id,
        "decision": approval.decision,
        "expires_at": approval.expires_at,
        "inserted": inserted,
    })))
}

/// Idempotently lease the next task assigned to the authenticated service identity.
pub async fn claim_work_task(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_worker_api(&state)?;
    let path = format!("{WORKER_PATH}/tasks/claim");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.tasks.execute",
        "service",
    )
    .await?;
    let input: ClaimWorkTask = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid task claim JSON"))?;
    if input.claim_id.is_nil() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "claim_id must be non-nil",
        ));
    }
    let lease_token = derive_lease_token(
        &state.relay_keypair,
        tenant.community().as_uuid(),
        principal.identity_id,
        input.claim_id,
    );
    let lease_token_sha256: [u8; 32] = Sha256::digest(lease_token).into();
    let task = state
        .db
        .claim_next_work_task(
            tenant.community(),
            principal.identity_id,
            input.claim_id,
            lease_token_sha256,
            Duration::seconds(LEASE_SECONDS),
        )
        .await
        .map_err(|_| internal_error("workforce task claim failed"))?;
    let Some(task) = task else {
        return Ok(Json(json!({
            "schema_version": "snowman.work.lease.v1",
            "task": null,
            "retry_after_seconds": 15,
        })));
    };
    metrics::counter!("snowman_workforce_task_claims_total", "outcome" => "leased").increment(1);
    Ok(Json(json!({
        "schema_version": "snowman.work.lease.v1",
        "lease_token": URL_SAFE_NO_PAD.encode(lease_token),
        "lease_generation": task.lease_generation,
        "lease_expires_at": task.lease_expires_at,
        "task": {
            "request_id": task.request_id,
            "task_id": task.task_id,
            "claim_id": task.claim_id,
            "objective": task.objective,
            "request_contract_sha256": hex::encode(task.request_contract_sha256),
            "classification": task.classification,
            "request_created_at": task.request_created_at,
            "request_deadline_at": task.request_deadline_at,
            "max_cost_microusd": task.max_cost_microusd,
            "max_input_tokens": task.max_input_tokens,
            "max_output_tokens": task.max_output_tokens,
            "specialist_role": task.specialist_role,
            "service_identity_id": task.service_identity_id,
            "required_capabilities": task.required_capabilities,
            "model_gateway_route": task.model_gateway_route,
            "model_id": task.model_id,
            "task_max_cost_microusd": task.task_max_cost_microusd,
            "expected_input_tokens": task.expected_input_tokens,
            "task_max_output_tokens": task.task_max_output_tokens,
            "execution_snapshot_sha256": hex::encode(task.execution_snapshot_sha256),
            "expected_artifact_contract": task.expected_artifact_contract,
            "context_references": task.context_references,
            "context_packet_id": task.context_packet_id,
            "risk_tier": task.risk_tier,
            "reversible": task.reversible,
            "approval_required": task.approval_required,
        }
    })))
}

/// Enforce tenant-local deadlines and recover expired task leases. This route
/// is intentionally separate from task execution: the scheduler identity has
/// no Analyst signing key and only the `workforce.maintenance` capability.
pub async fn tick_workforce_maintenance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_worker_api(&state)?;
    let path = format!("{WORKER_PATH}/maintenance/tick");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.maintenance",
        "service",
    )
    .await?;
    let input: MaintenanceTickRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid maintenance tick JSON"))?;
    if input.schema_version != "snowman.workforce.maintenance.tick.v1"
        || input.tick_id.is_nil()
        || !is_recent_maintenance_time(input.requested_at)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "maintenance tick has an invalid schema, identity, or time",
        ));
    }
    let result = state
        .db
        .maintain_workforce(
            tenant.community(),
            input.tick_id,
            principal.identity_id,
            input.requested_at,
        )
        .await
        .map_err(|error| match error {
            buzz_db::DbError::AccessDenied(_) | buzz_db::DbError::InvalidData(_) => api_error(
                StatusCode::CONFLICT,
                "maintenance tick conflicts with scheduler identity or prior evidence",
            ),
            _ => internal_error("workforce maintenance failed"),
        })?;
    metrics::counter!("snowman_workforce_maintenance_ticks_total").increment(1);
    metrics::counter!("snowman_workforce_maintenance_transitions_total", "outcome" => "request_expired")
        .increment(result.expired_requests);
    metrics::counter!("snowman_workforce_maintenance_transitions_total", "outcome" => "task_expired")
        .increment(result.expired_tasks);
    metrics::counter!("snowman_workforce_maintenance_transitions_total", "outcome" => "proactive_expired")
        .increment(result.expired_proactive_actions);
    metrics::counter!("snowman_workforce_maintenance_transitions_total", "outcome" => "task_requeued")
        .increment(result.requeued_tasks);
    metrics::counter!("snowman_workforce_maintenance_transitions_total", "outcome" => "task_dead_lettered")
        .increment(result.dead_lettered_tasks);
    Ok(Json(json!({
        "schema_version": "snowman.workforce.maintenance.result.v1",
        "tick_id": input.tick_id,
        "observed_at": result.observed_at,
        "expired_requests": result.expired_requests,
        "expired_tasks": result.expired_tasks,
        "expired_proactive_actions": result.expired_proactive_actions,
        "requeued_tasks": result.requeued_tasks,
        "dead_lettered_tasks": result.dead_lettered_tasks,
    })))
}

/// Publish one bounded metadata-only context handoff for this request.
pub async fn publish_context_packet(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<Uuid>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_worker_api(&state)?;
    let path = format!("{WORKER_PATH}/requests/{request_id}/context-packets");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.context.write",
        "service",
    )
    .await?;
    let input: PublishContextPacketRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid context packet JSON"))?;
    if input.schema_version != "snowman.workforce.context.publish.v1"
        || request_id.is_nil()
        || input.context_packet_id.is_nil()
        || input.source_task_id.is_nil()
        || input.generation <= 0
        || !is_recent_worker_time(input.occurred_at)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "context packet has an invalid schema, identity, or publication time",
        ));
    }
    let next_actions = input
        .next_actions
        .into_iter()
        .map(|action| {
            Ok(ContextNextAction {
                action_id: action.action_id,
                capability: action.capability,
                risk_tier: action.risk_tier,
                reversible: action.reversible,
                approval_required: action.approval_required,
                expected_cost_microusd: action.expected_cost_microusd,
                confidence_basis_points: action.confidence_basis_points,
                usefulness_sha256: parse_sha256(
                    &action.usefulness_sha256,
                    "next_actions[].usefulness_sha256",
                )?,
            })
        })
        .collect::<Result<Vec<_>, (StatusCode, Json<Value>)>>()?;
    let manifest = ContextPacketManifest {
        context_packet_id: input.context_packet_id,
        request_id,
        community_id: *tenant.community().as_uuid(),
        classification: input.classification,
        authority: input.authority,
        objective_sha256: parse_sha256(&input.objective_sha256, "objective_sha256")?,
        content_reference: input.content_reference,
        content_sha256: parse_sha256(&input.content_sha256, "content_sha256")?,
        source_event_sha256: parse_sha256(&input.source_event_sha256, "source_event_sha256")?,
        size_bytes: input.size_bytes,
        artifact_references: input.artifact_references,
        evidence_references: input.evidence_references,
        decision_digests: input.decision_digests,
        open_question_digests: input.open_question_digests,
        next_actions,
    };
    let packet = NewContextPacket {
        manifest,
        created_by_identity_id: principal.identity_id,
        source_task_id: input.source_task_id,
        lease_generation: input.generation,
        lease_token_sha256: decode_lease_token(&input.lease_token)?,
        artifact_id: input.artifact_id,
        artifact_version: input.artifact_version,
        artifact_type: input.artifact_type,
        expires_at: input.expires_at,
        created_at: input.occurred_at,
    };
    let published = state
        .db
        .publish_context_packet(tenant.community(), &packet)
        .await
        .map_err(|error| match error {
            buzz_db::DbError::AccessDenied(_) | buzz_db::DbError::InvalidData(_) => api_error(
                StatusCode::CONFLICT,
                "context packet conflicts with request, identity, or evidence policy",
            ),
            _ => internal_error("context packet persistence failed"),
        })?;
    metrics::counter!(
        "snowman_workforce_context_packets_total",
        "operation" => "publish",
        "outcome" => if published.inserted { "published" } else { "replayed" }
    )
    .increment(1);
    Ok((
        if published.inserted {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(json!({
            "schema_version": "snowman.workforce.context.published.v1",
            "request_id": published.request_id,
            "context_packet_id": published.context_packet_id,
            "inserted": published.inserted,
        })),
    ))
}

/// List non-expired handoff manifests for the caller's active assignment.
pub async fn list_context_packets(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_worker_api(&state)?;
    let path = format!("{WORKER_PATH}/requests/{request_id}/context-packets");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "GET",
        &path,
        None,
        "workforce.context.read",
        "service",
    )
    .await?;
    let packets = state
        .db
        .list_context_packets(tenant.community(), request_id, principal.identity_id)
        .await
        .map_err(|_| internal_error("context packet read failed"))?;
    metrics::counter!(
        "snowman_workforce_context_packets_total",
        "operation" => "list",
        "outcome" => "success"
    )
    .increment(1);
    Ok(Json(json!({
        "schema_version": "snowman.workforce.context.list.v1",
        "request_id": request_id,
        "packets": packets.iter().map(context_packet_json).collect::<Vec<_>>(),
    })))
}

/// Evaluate and persist one trigger-grounded proactive next-useful action.
pub async fn propose_proactive_action(
    State(state): State<Arc<AppState>>,
    Path(request_id): Path<Uuid>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_worker_api(&state)?;
    let path = format!("{WORKER_PATH}/requests/{request_id}/proactive-actions");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.proactive.propose",
        "service",
    )
    .await?;
    let input: ProposeProactiveActionRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid proactive action JSON"))?;
    let now = Utc::now();
    if input.schema_version != "snowman.proactive.proposal.v2"
        || request_id.is_nil()
        || input.action_id.is_nil()
        || !is_recent_worker_time(input.occurred_at)
        || input.scheduled_for < input.occurred_at
        || input.scheduled_for > now + Duration::days(365)
        || input.expires_at <= input.scheduled_for
        || input.expires_at > input.scheduled_for + Duration::days(30)
        || input.executor_identity_id.is_nil()
        || input.expected_input_tokens == 0
        || input.max_output_tokens == 0
        || !(1..=20).contains(&input.max_attempts)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "proactive action has an invalid schema, identity, schedule, or expiry",
        ));
    }
    let workforce = state
        .config
        .snowman_workforce
        .as_ref()
        .expect("workforce presence checked during authentication");
    let action = ProactiveAction {
        action_id: input.action_id,
        community_id: *tenant.community().as_uuid(),
        objective_id: request_id,
        trigger: input.trigger,
        capability: input.capability.clone(),
        risk_tier: input.risk_tier,
        reversible: input.reversible,
        expected_cost_microusd: input.expected_cost_microusd,
        usefulness_sha256: parse_sha256(&input.usefulness_sha256, "usefulness_sha256")?,
        confidence_basis_points: input.confidence_basis_points,
    };
    let decision = decide_proactive_action(&action, &workforce.proactive_policy);
    let execution_task = if decision == ProactiveDecision::Reject {
        None
    } else {
        if !valid_proactive_executor(input.specialist_role, &input.capability)
            || !is_context_reference(&input.instruction_reference)
            || input.context_references.len() >= MAX_CONTEXT_REFS
            || input
                .context_references
                .iter()
                .any(|reference| !is_context_reference(reference))
        {
            return Err(api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "proactive execution role, capability, or context is not supported",
            ));
        }
        let status = state
            .db
            .get_work_request_status(tenant.community(), request_id)
            .await
            .map_err(|_| internal_error("proactive request envelope read failed"))?
            .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "work request not found"))?;
        if matches!(
            status.status.as_str(),
            "completed" | "failed" | "cancelled" | "expired"
        ) {
            return Err(api_error(
                StatusCode::CONFLICT,
                "proactive action request is no longer active",
            ));
        }
        let classification = parse_classification(&status.classification).ok_or_else(|| {
            internal_error("workforce request contains an unsupported classification")
        })?;
        let catalog = state
            .db
            .active_model_routes(tenant.community())
            .await
            .map_err(|_| internal_error("workforce model catalog read failed"))?
            .into_iter()
            .map(model_route_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        if catalog.is_empty() {
            return Err(api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "no evaluated Snowman model routes are active for this workspace",
            ));
        }
        let mut context_references = input.context_references.clone();
        context_references.insert(input.instruction_reference.clone());
        let mut required_capabilities = BTreeSet::from([
            input.capability.clone(),
            "workforce.context.write".to_string(),
        ]);
        if input.specialist_role == SpecialistRole::QualityRiskReviewer {
            required_capabilities.insert("artifact.review".to_string());
        }
        let governed = govern_team_plan(
            GovernedTeamPlan {
                request_id,
                community_id: *tenant.community().as_uuid(),
                objective_sha256: parse_sha256(&status.objective_sha256, "objective_sha256")?,
                classification,
                client_ready_delivery: false,
                max_cost_microusd: nonnegative_u64(
                    status.max_cost_microusd.saturating_sub(status.used_cost_microusd),
                )?,
                max_input_tokens: nonnegative_u64(
                    status.max_input_tokens.saturating_sub(status.used_input_tokens),
                )?,
                max_output_tokens: nonnegative_u64(
                    status.max_output_tokens.saturating_sub(status.used_output_tokens),
                )?,
                tasks: vec![PlannedTask {
                    task_id: input.action_id,
                    service_identity_id: input.executor_identity_id,
                    specialist_role: input.specialist_role,
                    depends_on: BTreeSet::new(),
                    required_capabilities,
                    context_packet_refs: context_references.clone(),
                    requested_model_id: input.requested_model_id.clone(),
                    selected_model_id: None,
                    selected_gateway_url: None,
                    expected_input_tokens: input.expected_input_tokens,
                    max_output_tokens: input.max_output_tokens,
                    max_cost_microusd: input.expected_cost_microusd,
                    risk_tier: input.risk_tier,
                    reversible: input.reversible,
                    approval_required: decision != ProactiveDecision::ExecuteAutomatically,
                    expected_artifact_type: input.expected_artifact_type.clone(),
                }],
            },
            &catalog,
        )
        .map_err(|error| {
            tracing::warn!(community = %tenant.community(), %error, "proactive execution contract rejected");
            api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "proactive execution contract violates workforce policy",
            )
        })?;
        let governed_task = governed
            .tasks
            .into_iter()
            .next()
            .expect("single proactive task remains present after governance");
        let canonical =
            serde_json::to_vec(&(&action, &governed_task, &input.instruction_reference))
                .map_err(|_| internal_error("proactive task canonicalization failed"))?;
        let execution_snapshot_sha256 = domain_digest(
            b"snowman.proactive-task-snapshot.v1\0",
            &[
                tenant.community().as_uuid().as_bytes(),
                request_id.as_bytes(),
                input.action_id.as_bytes(),
                canonical.as_slice(),
            ],
        );
        Some(NewWorkTask {
            task_id: input.action_id,
            parent_task_id: None,
            specialist_role: specialist_role_name(governed_task.specialist_role).to_string(),
            service_identity_id: governed_task.service_identity_id,
            assigned_agent_pubkey: None,
            required_capabilities: governed_task.required_capabilities.into_iter().collect(),
            model_gateway_route: governed_task
                .selected_gateway_url
                .expect("governed proactive task has a gateway"),
            model_id: governed_task
                .selected_model_id
                .expect("governed proactive task has a model"),
            max_cost_microusd: bounded_i64(governed_task.max_cost_microusd, "max_cost_microusd")?,
            expected_input_tokens: bounded_i64(
                governed_task.expected_input_tokens,
                "expected_input_tokens",
            )?,
            max_output_tokens: bounded_i64(governed_task.max_output_tokens, "max_output_tokens")?,
            execution_snapshot_sha256,
            expected_artifact_contract: json!({
                "schema_version": "snowman.proactive.artifact-contract.v1",
                "artifact_type": governed_task.expected_artifact_type,
                "instruction_reference": input.instruction_reference,
                "proactive_action_id": input.action_id,
            }),
            context_references: context_references.into_iter().collect(),
            context_packet_id: None,
            risk_tier: risk_tier_name(governed_task.risk_tier).to_string(),
            reversible: governed_task.reversible,
            approval_required: governed_task.approval_required,
            priority: 60,
            available_at: input.scheduled_for,
            deadline_at: Some(input.expires_at),
            max_attempts: input.max_attempts,
        })
    };
    let execution_receipt = execution_task.as_ref().map(|task| {
        json!({
            "task_id": task.task_id,
            "executor_identity_id": task.service_identity_id,
            "specialist_role": task.specialist_role,
            "model_id": task.model_id,
            "execution_snapshot_sha256": hex::encode(task.execution_snapshot_sha256),
            "approval_required": task.approval_required,
        })
    });
    let proposal = NewProactiveAction {
        action,
        proposed_by_identity_id: principal.identity_id,
        policy: workforce.proactive_policy.clone(),
        source_event_sha256: parse_sha256(&input.source_event_sha256, "source_event_sha256")?,
        scheduled_for: input.scheduled_for,
        expires_at: input.expires_at,
        created_at: input.occurred_at,
        execution_task,
    };
    let scheduled = state
        .db
        .schedule_proactive_action(tenant.community(), &proposal)
        .await
        .map_err(|error| match error {
            buzz_db::DbError::AccessDenied(_) | buzz_db::DbError::InvalidData(_) => api_error(
                StatusCode::CONFLICT,
                "proactive action conflicts with identity, lifecycle, policy, or budget",
            ),
            _ => internal_error("proactive action persistence failed"),
        })?;
    let outcome = proactive_decision_name(scheduled.decision);
    metrics::counter!(
        "snowman_workforce_proactive_actions_total",
        "decision" => outcome,
        "outcome" => if scheduled.inserted { "evaluated" } else { "replayed" }
    )
    .increment(1);
    Ok((
        if scheduled.inserted {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(json!({
            "schema_version": "snowman.proactive.decision.v2",
            "action_id": scheduled.action_id,
            "request_id": scheduled.request_id,
            "decision": outcome,
            "inserted": scheduled.inserted,
            "execution": execution_receipt,
        })),
    ))
}

/// Validate a lead planner proposal, choose approved best-fit models, and
/// atomically replace the lead task with a durable specialist DAG.
pub async fn commit_team_plan(
    State(state): State<Arc<AppState>>,
    Path(lead_task_id): Path<Uuid>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_worker_api(&state)?;
    let path = format!("{WORKER_PATH}/tasks/{lead_task_id}/plan");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.plan",
        "service",
    )
    .await?;
    let input: CommitTeamPlanRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid team plan JSON"))?;
    if input.schema_version != "snowman.team_plan.proposal.v1"
        || input.plan_id.is_nil()
        || input.request_id.is_nil()
        || lead_task_id.is_nil()
        || input.generation <= 0
        || input.tasks.is_empty()
        || input.tasks.len() > 64
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "team plan has an invalid schema, identity, generation, or task count",
        ));
    }
    let lease_token_sha256 = decode_lease_token(&input.lease_token)?;
    let envelope = state
        .db
        .work_plan_envelope(tenant.community(), input.request_id, lead_task_id)
        .await
        .map_err(|_| internal_error("workforce plan envelope read failed"))?
        .ok_or_else(|| {
            api_error(
                StatusCode::CONFLICT,
                "work request or lead planning task is not active",
            )
        })?;
    let classification = parse_classification(&envelope.classification).ok_or_else(|| {
        internal_error("workforce request contains an unsupported classification")
    })?;
    let catalog_rows = state
        .db
        .active_model_routes(tenant.community())
        .await
        .map_err(|_| internal_error("workforce model catalog read failed"))?;
    let catalog = catalog_rows
        .into_iter()
        .map(model_route_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    if catalog.is_empty() {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "no evaluated Snowman model routes are active for this workspace",
        ));
    }
    let proposed_tasks = input
        .tasks
        .into_iter()
        .map(|task| PlannedTask {
            task_id: task.task_id,
            service_identity_id: task.service_identity_id,
            specialist_role: task.specialist_role,
            depends_on: task.depends_on,
            required_capabilities: task.required_capabilities,
            context_packet_refs: task.context_references,
            requested_model_id: task.requested_model_id,
            selected_model_id: None,
            selected_gateway_url: None,
            expected_input_tokens: task.expected_input_tokens,
            max_output_tokens: task.max_output_tokens,
            max_cost_microusd: task.max_cost_microusd,
            risk_tier: task.risk_tier,
            reversible: task.reversible,
            approval_required: task.approval_required,
            expected_artifact_type: task.expected_artifact_type,
        })
        .collect();
    let governed = govern_team_plan(
        GovernedTeamPlan {
            request_id: envelope.request_id,
            community_id: *tenant.community().as_uuid(),
            objective_sha256: envelope.objective_sha256,
            classification,
            client_ready_delivery: envelope.client_ready_delivery,
            max_cost_microusd: nonnegative_u64(envelope.max_cost_microusd)?,
            max_input_tokens: nonnegative_u64(envelope.max_input_tokens)?,
            max_output_tokens: nonnegative_u64(envelope.max_output_tokens)?,
            tasks: proposed_tasks,
        },
        &catalog,
    )
    .map_err(|error| {
        tracing::warn!(community = %tenant.community(), %error, "team plan rejected by policy");
        api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "team plan violates workforce policy",
        )
    })?;
    let plan_sha256 = governed_plan_digest(
        input.plan_id,
        lead_task_id,
        principal.identity_id,
        input.generation,
        &governed,
    )?;
    let committed_at = Utc::now();
    let mut tasks = Vec::with_capacity(governed.tasks.len());
    for task in &governed.tasks {
        let model_id = task
            .selected_model_id
            .clone()
            .ok_or_else(|| internal_error("governed task is missing a selected model"))?;
        let model_gateway_route = task
            .selected_gateway_url
            .clone()
            .ok_or_else(|| internal_error("governed task is missing a selected gateway"))?;
        let snapshot = specialist_snapshot(
            tenant.community().as_uuid(),
            input.plan_id,
            lead_task_id,
            &plan_sha256,
            task,
        )?;
        let context_references: Vec<_> = task.context_packet_refs.iter().cloned().collect();
        tasks.push(NewPlannedTask {
            depends_on: task.depends_on.iter().copied().collect(),
            task: NewWorkTask {
                task_id: task.task_id,
                parent_task_id: Some(lead_task_id),
                specialist_role: specialist_role_name(task.specialist_role).to_string(),
                service_identity_id: task.service_identity_id,
                assigned_agent_pubkey: None,
                required_capabilities: task.required_capabilities.iter().cloned().collect(),
                model_gateway_route,
                model_id,
                max_cost_microusd: bounded_i64(task.max_cost_microusd, "task cost ceiling")?,
                expected_input_tokens: bounded_i64(
                    task.expected_input_tokens,
                    "task input-token reservation",
                )?,
                max_output_tokens: bounded_i64(
                    task.max_output_tokens,
                    "task output-token ceiling",
                )?,
                execution_snapshot_sha256: snapshot,
                expected_artifact_contract: json!({
                    "schema_version": "snowman.artifact.contract.v1",
                    "artifact_type": task.expected_artifact_type,
                    "plan_sha256": hex::encode(plan_sha256),
                    "context_references": context_references,
                    "dependency_task_ids": task.depends_on,
                    "selected_model_id": task.selected_model_id,
                    "client_ready_delivery": envelope.client_ready_delivery,
                }),
                context_references,
                context_packet_id: None,
                risk_tier: risk_tier_name(task.risk_tier).to_string(),
                reversible: task.reversible,
                approval_required: task.approval_required,
                priority: if task.specialist_role == SpecialistRole::QualityRiskReviewer {
                    40
                } else {
                    60
                },
                available_at: committed_at,
                deadline_at: envelope.deadline_at,
                max_attempts: 3,
            },
        });
    }
    let plan = NewWorkPlan {
        plan_id: input.plan_id,
        request_id: input.request_id,
        lead_task_id,
        planner_identity_id: principal.identity_id,
        lease_generation: input.generation,
        lease_token_sha256,
        plan_sha256,
        tasks,
        committed_at,
    };
    let result = state
        .db
        .commit_work_plan(tenant.community(), &plan)
        .await
        .map_err(|error| match error {
            buzz_db::DbError::AccessDenied(_) | buzz_db::DbError::InvalidData(_) => api_error(
                StatusCode::CONFLICT,
                "team plan conflicts with current lease, identity, capability, or budget state",
            ),
            _ => internal_error("workforce team plan persistence failed"),
        })?;
    metrics::counter!(
        "snowman_workforce_team_plans_total",
        "outcome" => if result.inserted { "committed" } else { "replayed" }
    )
    .increment(1);
    Ok((
        if result.inserted {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(json!({
            "schema_version": "snowman.team_plan.committed.v1",
            "plan_id": result.plan_id,
            "request_id": result.request_id,
            "plan_sha256": hex::encode(plan_sha256),
            "specialist_task_count": result.task_count,
            "inserted": result.inserted,
        })),
    ))
}

/// Renew one live lease without changing its fencing generation.
pub async fn heartbeat_work_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<Uuid>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_worker_api(&state)?;
    let path = format!("{WORKER_PATH}/tasks/{task_id}/heartbeat");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.tasks.execute",
        "service",
    )
    .await?;
    let proof: LeaseProof = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid lease heartbeat JSON"))?;
    let token_sha256 = decode_lease_token(&proof.lease_token)?;
    let renewed = state
        .db
        .heartbeat_work_task(
            tenant.community(),
            task_id,
            principal.identity_id,
            proof.generation,
            token_sha256,
            Duration::seconds(LEASE_SECONDS),
        )
        .await
        .map_err(|_| internal_error("workforce heartbeat failed"))?;
    if !renewed {
        return Err(api_error(
            StatusCode::CONFLICT,
            "task lease is stale, expired, or owned by another worker",
        ));
    }
    Ok(Json(json!({
        "schema_version": "snowman.work.heartbeat.v1",
        "task_id": task_id,
        "lease_generation": proof.generation,
        "lease_expires_in_seconds": LEASE_SECONDS,
    })))
}

/// Charge one idempotent model operation to the request's hard spend ledger.
pub async fn record_work_spend(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<Uuid>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_worker_api(&state)?;
    let path = format!("{WORKER_PATH}/tasks/{task_id}/spend");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.tasks.execute",
        "service",
    )
    .await?;
    let input: RecordSpendRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid spend receipt JSON"))?;
    if input.generation <= 0
        || input.ledger_entry_id.is_nil()
        || input.request_id.is_nil()
        || input.model_id.trim().is_empty()
        || input.model_id.len() > 256
        || input.input_tokens < 0
        || input.output_tokens < 0
        || input.cost_microusd < 0
        || !is_recent_worker_time(input.recorded_at)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "spend receipt has invalid identity, usage, model, or time fields",
        ));
    }
    let token_sha256 = decode_lease_token(&input.lease_token)?;
    let receipt = parse_sha256(&input.provider_receipt_sha256, "provider_receipt_sha256")?;
    let entry = SpendEntry {
        ledger_entry_id: input.ledger_entry_id,
        request_id: input.request_id,
        task_id,
        worker_identity_id: principal.identity_id,
        lease_generation: input.generation,
        lease_token_sha256: token_sha256,
        model_id: input.model_id,
        input_tokens: input.input_tokens,
        output_tokens: input.output_tokens,
        cost_microusd: input.cost_microusd,
        provider_receipt_sha256: receipt,
        recorded_at: input.recorded_at,
    };
    state
        .db
        .record_work_spend(tenant.community(), &entry)
        .await
        .map_err(|error| match error {
            buzz_db::DbError::AccessDenied(_) | buzz_db::DbError::InvalidData(_) => api_error(
                StatusCode::CONFLICT,
                "spend receipt violates task or budget policy",
            ),
            _ => internal_error("workforce spend persistence failed"),
        })?;
    Ok(Json(json!({
        "schema_version": "snowman.work.spend-recorded.v1",
        "ledger_entry_id": entry.ledger_entry_id,
        "task_id": task_id,
    })))
}

/// Atomically finish a task and append its terminal hash-chain evidence event.
pub async fn finish_work_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<Uuid>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_worker_api(&state)?;
    let path = format!("{WORKER_PATH}/tasks/{task_id}/finish");
    let (tenant, principal) = authenticate_principal(
        &state,
        &headers,
        "POST",
        &path,
        Some(&body),
        "workforce.tasks.execute",
        "service",
    )
    .await?;
    let input: FinishWorkTaskRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid task completion JSON"))?;
    if task_id.is_nil()
        || input.completion_id.is_nil()
        || input.generation <= 0
        || !is_recent_worker_time(input.occurred_at)
        || input.artifact_references.len() > MAX_CONTEXT_REFS
        || input
            .artifact_references
            .iter()
            .any(|reference| !is_context_reference(reference))
        || input.failure_code.as_ref().is_some_and(|code| {
            code.is_empty()
                || code.len() > 128
                || !code.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
                })
        })
        || (input.succeeded && input.failure_code.is_some())
        || (input.succeeded && input.artifact_references.is_empty())
        || (!input.succeeded && input.failure_code.is_none())
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "task result contains invalid evidence references or failure code",
        ));
    }
    let completion = WorkTaskCompletion {
        completion_id: input.completion_id,
        task_id,
        worker_identity_id: principal.identity_id,
        generation: input.generation,
        lease_token_sha256: decode_lease_token(&input.lease_token)?,
        succeeded: input.succeeded,
        result_payload: json!({
            "result_sha256": hex::encode(parse_sha256(&input.result_sha256, "result_sha256")?),
            "artifact_references": input.artifact_references,
            "failure_code": input.failure_code,
        }),
        occurred_at: input.occurred_at,
    };
    let finished = state
        .db
        .finish_work_task(tenant.community(), &completion)
        .await
        .map_err(|error| match error {
            buzz_db::DbError::AccessDenied(_) | buzz_db::DbError::InvalidData(_) => api_error(
                StatusCode::CONFLICT,
                "task completion violates evidence policy",
            ),
            _ => internal_error("workforce completion persistence failed"),
        })?;
    if !finished {
        return Err(api_error(
            StatusCode::CONFLICT,
            "task lease is stale, expired, or owned by another worker",
        ));
    }
    Ok(Json(json!({
        "schema_version": "snowman.work.completed.v1",
        "task_id": task_id,
        "completion_id": completion.completion_id,
        "status": if completion.succeeded { "succeeded" } else { "failed" },
    })))
}

fn parse_classification(value: &str) -> Option<Classification> {
    match value {
        "internal" => Some(Classification::Internal),
        "confidential" => Some(Classification::Confidential),
        "restricted" => Some(Classification::Restricted),
        _ => None,
    }
}

fn is_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_' | '-')
        })
}

fn parse_specialist_role(value: &str) -> Option<SpecialistRole> {
    match value {
        "lead" => Some(SpecialistRole::Lead),
        "client_delivery" => Some(SpecialistRole::ClientDelivery),
        "research_evidence" => Some(SpecialistRole::ResearchEvidence),
        "governed_analyst" => Some(SpecialistRole::GovernedAnalyst),
        "quality_risk_reviewer" => Some(SpecialistRole::QualityRiskReviewer),
        "deadline_operations" => Some(SpecialistRole::DeadlineOperations),
        _ => None,
    }
}

fn valid_proactive_executor(role: SpecialistRole, capability: &str) -> bool {
    matches!(
        (role, capability),
        (SpecialistRole::GovernedAnalyst, "analytics.query")
            | (SpecialistRole::ClientDelivery, "artifact.build")
            | (SpecialistRole::QualityRiskReviewer, "artifact.build")
            | (SpecialistRole::ResearchEvidence, "evidence.manifest.read")
    )
}

const fn specialist_role_name(value: SpecialistRole) -> &'static str {
    match value {
        SpecialistRole::Lead => "lead",
        SpecialistRole::ClientDelivery => "client_delivery",
        SpecialistRole::ResearchEvidence => "research_evidence",
        SpecialistRole::GovernedAnalyst => "governed_analyst",
        SpecialistRole::QualityRiskReviewer => "quality_risk_reviewer",
        SpecialistRole::DeadlineOperations => "deadline_operations",
    }
}

const fn risk_tier_name(value: RiskTier) -> &'static str {
    match value {
        RiskTier::Low => "low",
        RiskTier::Moderate => "moderate",
        RiskTier::High => "high",
        RiskTier::Prohibited => "prohibited",
    }
}

fn model_route_from_row(row: StoredModelRoute) -> Result<ModelRoute, (StatusCode, Json<Value>)> {
    let suited_roles = row
        .suited_roles
        .iter()
        .map(|role| parse_specialist_role(role))
        .collect::<Option<BTreeSet<_>>>()
        .ok_or_else(|| internal_error("model catalog contains an unsupported specialist role"))?;
    let allowed_classifications = row
        .allowed_classifications
        .iter()
        .map(|classification| parse_classification(classification))
        .collect::<Option<BTreeSet<_>>>()
        .ok_or_else(|| internal_error("model catalog contains an unsupported classification"))?;
    Ok(ModelRoute {
        model_id: row.model_id,
        gateway_url: row.gateway_url,
        suited_roles,
        allowed_classifications,
        quality_score: u16::try_from(row.quality_score)
            .map_err(|_| internal_error("model catalog quality score is invalid"))?,
        latency_score: u16::try_from(row.latency_score)
            .map_err(|_| internal_error("model catalog latency score is invalid"))?,
        max_cost_microusd_per_million_tokens: u64::try_from(
            row.max_cost_microusd_per_million_tokens,
        )
        .map_err(|_| internal_error("model catalog cost ceiling is invalid"))?,
        max_context_tokens: u64::try_from(row.max_context_tokens)
            .map_err(|_| internal_error("model catalog context ceiling is invalid"))?,
    })
}

fn nonnegative_u64(value: i64) -> Result<u64, (StatusCode, Json<Value>)> {
    u64::try_from(value).map_err(|_| internal_error("work request budget is invalid"))
}

fn bounded_i64(value: u64, field: &str) -> Result<i64, (StatusCode, Json<Value>)> {
    i64::try_from(value).map_err(|_| {
        api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("{field} exceeds the supported bound"),
        )
    })
}

fn governed_plan_digest(
    plan_id: Uuid,
    lead_task_id: Uuid,
    planner_identity_id: Uuid,
    generation: i64,
    plan: &GovernedTeamPlan,
) -> Result<[u8; 32], (StatusCode, Json<Value>)> {
    let canonical = serde_json::to_vec(plan)
        .map_err(|_| internal_error("governed team plan canonicalization failed"))?;
    let generation = generation.to_be_bytes();
    Ok(domain_digest(
        b"snowman.team-plan.v1\0",
        &[
            plan_id.as_bytes(),
            lead_task_id.as_bytes(),
            planner_identity_id.as_bytes(),
            generation.as_slice(),
            canonical.as_slice(),
        ],
    ))
}

fn specialist_snapshot(
    community_id: &Uuid,
    plan_id: Uuid,
    lead_task_id: Uuid,
    plan_sha256: &[u8; 32],
    task: &PlannedTask,
) -> Result<[u8; 32], (StatusCode, Json<Value>)> {
    let canonical = serde_json::to_vec(task)
        .map_err(|_| internal_error("specialist task canonicalization failed"))?;
    Ok(domain_digest(
        b"snowman.specialist-task-snapshot.v1\0",
        &[
            community_id.as_bytes(),
            plan_id.as_bytes(),
            lead_task_id.as_bytes(),
            plan_sha256,
            canonical.as_slice(),
        ],
    ))
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn require_worker_api(state: &AppState) -> Result<(), (StatusCode, Json<Value>)> {
    if state.config.snowman_workforce_worker_api_enabled {
        Ok(())
    } else {
        Err(api_error(StatusCode::NOT_FOUND, "not found"))
    }
}

fn derive_lease_token(
    relay_keys: &nostr::Keys,
    community_id: &Uuid,
    worker_identity_id: Uuid,
    claim_id: Uuid,
) -> [u8; 32] {
    let mut key_hasher = Sha256::new();
    key_hasher.update(relay_keys.secret_key().as_secret_bytes());
    key_hasher.update(b"snowman.work.lease-key.v1\0");
    let key: [u8; 32] = key_hasher.finalize().into();
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts a 32-byte key");
    mac.update(b"snowman.work.lease-token.v1\0");
    mac.update(community_id.as_bytes());
    mac.update(worker_identity_id.as_bytes());
    mac.update(claim_id.as_bytes());
    mac.finalize().into_bytes().into()
}

fn decode_lease_token(token: &str) -> Result<[u8; 32], (StatusCode, Json<Value>)> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid lease token"))?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid lease token"))?;
    Ok(Sha256::digest(raw).into())
}

fn parse_sha256(value: &str, field: &str) -> Result<[u8; 32], (StatusCode, Json<Value>)> {
    if value.len() != 64
        || !value
            .chars()
            .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            &format!("{field} must be a lowercase SHA-256 digest"),
        ));
    }
    let bytes = hex::decode(value)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid SHA-256 digest"))?;
    bytes
        .try_into()
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid SHA-256 digest"))
}

fn context_packet_json(packet: &StoredContextPacket) -> Value {
    let manifest = &packet.manifest;
    json!({
        "context_packet_id": manifest.context_packet_id,
        "request_id": manifest.request_id,
        "classification": classification_name(manifest.classification),
        "authority": context_authority_name(manifest.authority),
        "objective_sha256": hex::encode(manifest.objective_sha256),
        "content_reference": manifest.content_reference,
        "content_sha256": hex::encode(manifest.content_sha256),
        "source_event_sha256": hex::encode(manifest.source_event_sha256),
        "manifest_sha256": hex::encode(packet.manifest_sha256),
        "size_bytes": manifest.size_bytes,
        "artifact_id": packet.artifact_id,
        "artifact_version": packet.artifact_version,
        "artifact_type": packet.artifact_type,
        "artifact_references": manifest.artifact_references,
        "evidence_references": manifest.evidence_references,
        "decision_digests": manifest.decision_digests,
        "open_question_digests": manifest.open_question_digests,
        "next_actions": manifest.next_actions.iter().map(|action| json!({
            "action_id": action.action_id,
            "capability": action.capability,
            "risk_tier": risk_tier_name(action.risk_tier),
            "reversible": action.reversible,
            "approval_required": action.approval_required,
            "expected_cost_microusd": action.expected_cost_microusd,
            "confidence_basis_points": action.confidence_basis_points,
            "usefulness_sha256": hex::encode(action.usefulness_sha256),
        })).collect::<Vec<_>>(),
        "created_by_identity_id": packet.created_by_identity_id,
        "expires_at": packet.expires_at,
        "created_at": packet.created_at,
    })
}

const fn classification_name(value: Classification) -> &'static str {
    match value {
        Classification::Internal => "internal",
        Classification::Confidential => "confidential",
        Classification::Restricted => "restricted",
    }
}

const fn context_authority_name(value: ContextAuthority) -> &'static str {
    match value {
        ContextAuthority::Analyst360 => "analyst360",
        ContextAuthority::SnowmanCommandCenter => "snowman-command-center",
    }
}

const fn proactive_decision_name(value: ProactiveDecision) -> &'static str {
    match value {
        ProactiveDecision::ExecuteAutomatically => "execute_automatically",
        ProactiveDecision::AwaitHumanApproval => "await_human_approval",
        ProactiveDecision::Reject => "reject",
    }
}

fn is_recent_worker_time(value: DateTime<Utc>) -> bool {
    let now = Utc::now();
    value >= now - Duration::days(30) && value <= now + Duration::minutes(5)
}

fn is_recent_maintenance_time(value: DateTime<Utc>) -> bool {
    let now = Utc::now();
    value >= now - Duration::hours(24) && value <= now + Duration::minutes(5)
}

fn validate_input(input: &CreateWorkRequest) -> Result<(), (StatusCode, Json<Value>)> {
    let objective = input.objective.trim();
    if objective.is_empty()
        || objective.len() > MAX_OBJECTIVE_BYTES
        || objective
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "objective must contain 1-8000 safe text bytes",
        ));
    }
    if !matches!(
        input.classification.as_str(),
        "internal" | "confidential" | "restricted"
    ) {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid classification"));
    }
    if !(1..=MAX_COST_MICROUSD).contains(&input.max_cost_microusd)
        || !(1..=MAX_INPUT_TOKENS).contains(&input.max_input_tokens)
        || !(1..=MAX_OUTPUT_TOKENS).contains(&input.max_output_tokens)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "work request budget is outside policy bounds",
        ));
    }
    if input.context_references.len() > MAX_CONTEXT_REFS
        || input
            .context_references
            .iter()
            .any(|reference| !is_context_reference(reference))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "context references must be immutable Analyst 360 or Snowman SHA-256 coordinates",
        ));
    }
    if let Some(deadline) = input.deadline_at {
        let now = Utc::now();
        if deadline <= now || deadline > now + Duration::days(365) {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "deadline must be within the next 365 days",
            ));
        }
    }
    Ok(())
}

fn is_context_reference(reference: &str) -> bool {
    let digest = reference
        .strip_prefix("analyst360:sha256:")
        .or_else(|| reference.strip_prefix("snowman:sha256:"));
    digest.is_some_and(|value| {
        value.len() == 64
            && value
                .chars()
                .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
    })
}

#[allow(clippy::too_many_arguments)]
fn planning_snapshot(
    community_id: &Uuid,
    request_id: Uuid,
    task_id: Uuid,
    requester_identity_id: Uuid,
    lead_service_identity_id: Uuid,
    objective_sha256: &[u8; 32],
    request_contract_sha256: &[u8; 32],
    gateway_url: &str,
    model_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.work.planning-snapshot.v1\0");
    for field in [
        community_id.as_bytes().as_slice(),
        request_id.as_bytes(),
        task_id.as_bytes(),
        requester_identity_id.as_bytes(),
        lead_service_identity_id.as_bytes(),
        objective_sha256,
        request_contract_sha256,
        b"lead".as_slice(),
        b"workforce.plan".as_slice(),
        b"low:reversible:no-approval".as_slice(),
        gateway_url.as_bytes(),
        model_id.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

fn request_contract_digest(
    community_id: &Uuid,
    requester_identity_id: Uuid,
    objective: &str,
    input: &CreateWorkRequest,
) -> [u8; 32] {
    let deadline = input
        .deadline_at
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        .unwrap_or_default();
    let client_ready = [u8::from(input.client_ready_delivery)];
    let cost = input.max_cost_microusd.to_be_bytes();
    let input_tokens = input.max_input_tokens.to_be_bytes();
    let output_tokens = input.max_output_tokens.to_be_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.work.request-contract.v1\0");
    for field in [
        community_id.as_bytes().as_slice(),
        requester_identity_id.as_bytes(),
        objective.as_bytes(),
        input.classification.as_bytes(),
        deadline.as_bytes(),
        cost.as_slice(),
        input_tokens.as_slice(),
        output_tokens.as_slice(),
        client_ready.as_slice(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    for reference in &input.context_references {
        hasher.update((reference.len() as u64).to_be_bytes());
        hasher.update(reference.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_references_are_content_addressed() {
        assert!(is_context_reference(&format!(
            "analyst360:sha256:{}",
            "a".repeat(64)
        )));
        assert!(!is_context_reference("https://example.com/raw.csv"));
        assert!(!is_context_reference("analyst360:sha256:not-a-digest"));
    }

    #[test]
    fn planning_snapshot_binds_tenant_actor_budget_and_route() {
        let input = CreateWorkRequest {
            objective: "Produce an evidence-backed launch brief".to_string(),
            classification: "confidential".to_string(),
            deadline_at: None,
            max_cost_microusd: 1_000_000,
            max_input_tokens: 100_000,
            max_output_tokens: 20_000,
            client_ready_delivery: true,
            context_references: Vec::new(),
        };
        let objective: [u8; 32] = Sha256::digest(input.objective.as_bytes()).into();
        let tenant = Uuid::new_v4();
        let request = Uuid::new_v4();
        let task = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let lead = Uuid::new_v4();
        let contract = request_contract_digest(&tenant, actor, &input.objective, &input);
        let first = planning_snapshot(
            &tenant,
            request,
            task,
            actor,
            lead,
            &objective,
            &contract,
            "https://models.snowmanai.org/v1",
            "planner-v1",
        );
        let mut changed = input;
        changed.max_cost_microusd += 1;
        let changed_contract =
            request_contract_digest(&tenant, actor, &changed.objective, &changed);
        let second = planning_snapshot(
            &tenant,
            request,
            task,
            actor,
            lead,
            &objective,
            &changed_contract,
            "https://models.snowmanai.org/v1",
            "planner-v1",
        );
        assert_ne!(first, second);
    }

    #[test]
    fn lease_tokens_are_deterministic_and_claim_bound() {
        let keys = nostr::Keys::generate();
        let tenant = Uuid::new_v4();
        let worker = Uuid::new_v4();
        let claim = Uuid::new_v4();
        let first = derive_lease_token(&keys, &tenant, worker, claim);
        let replay = derive_lease_token(&keys, &tenant, worker, claim);
        let different = derive_lease_token(&keys, &tenant, worker, Uuid::new_v4());
        assert_eq!(first, replay);
        assert_ne!(first, different);
    }

    #[test]
    fn evidence_digests_are_canonical_lowercase() {
        assert!(parse_sha256(&"a".repeat(64), "digest").is_ok());
        assert!(parse_sha256(&"A".repeat(64), "digest").is_err());
    }

    #[test]
    fn context_response_is_metadata_only_and_hex_encoded() {
        let digest = [0xab; 32];
        let packet = StoredContextPacket {
            manifest: ContextPacketManifest {
                context_packet_id: Uuid::new_v4(),
                request_id: Uuid::new_v4(),
                community_id: Uuid::new_v4(),
                classification: Classification::Restricted,
                authority: ContextAuthority::Analyst360,
                objective_sha256: digest,
                content_reference: format!("analyst360:sha256:{}", "a".repeat(64)),
                content_sha256: digest,
                source_event_sha256: digest,
                size_bytes: 128,
                artifact_references: BTreeSet::new(),
                evidence_references: BTreeSet::new(),
                decision_digests: BTreeSet::new(),
                open_question_digests: BTreeSet::new(),
                next_actions: vec![ContextNextAction {
                    action_id: Uuid::new_v4(),
                    capability: "analyst.jobs.read".into(),
                    risk_tier: RiskTier::Low,
                    reversible: true,
                    approval_required: false,
                    expected_cost_microusd: 1_000,
                    confidence_basis_points: 9_000,
                    usefulness_sha256: digest,
                }],
            },
            artifact_id: "artifact-1".into(),
            artifact_version: "v1".into(),
            expires_at: None,
            created_by_identity_id: Uuid::new_v4(),
            manifest_sha256: digest,
            created_at: Utc::now(),
        };
        let value = context_packet_json(&packet);
        assert_eq!(value["classification"], "restricted");
        assert_eq!(value["authority"], "analyst360");
        assert_eq!(value["content_sha256"], "ab".repeat(32));
        assert_eq!(
            value["next_actions"][0]["usefulness_sha256"],
            "ab".repeat(32)
        );
        assert!(value.get("content").is_none());
        assert!(value.get("artifact_body").is_none());
    }

    #[test]
    fn cancellation_reason_is_bounded_and_not_free_form() {
        assert!(is_reason_code("user.requested"));
        assert!(is_reason_code("objective_superseded-2"));
        assert!(!is_reason_code(""));
        assert!(!is_reason_code("contains client details"));
        assert!(!is_reason_code("UPPERCASE"));
        assert!(!is_reason_code(&"a".repeat(129)));
    }

    #[test]
    fn proactive_execution_reuses_only_supported_specialist_boundaries() {
        assert!(valid_proactive_executor(
            SpecialistRole::GovernedAnalyst,
            "analytics.query"
        ));
        assert!(valid_proactive_executor(
            SpecialistRole::ClientDelivery,
            "artifact.build"
        ));
        assert!(!valid_proactive_executor(
            SpecialistRole::GovernedAnalyst,
            "artifact.build"
        ));
        assert!(!valid_proactive_executor(
            SpecialistRole::DeadlineOperations,
            "calendar.write"
        ));
    }
}
