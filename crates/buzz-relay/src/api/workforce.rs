//! Governed Snowman AI Workforce HTTP API.
//!
//! Human callers submit objectives through a live Snowman workforce session.
//! The relay derives tenant and actor identity server-side, creates only a
//! capability-bounded planning task, and returns a metadata-only status view.
//! Specialist execution remains behind the private worker plane.

use std::sync::Arc;

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
use buzz_db::workforce::{NewWorkRequest, NewWorkTask, SpendEntry, WorkTaskCompletion};

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
struct LeaseProof {
    generation: i64,
    lease_token: String,
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
    let lead_ready = state
        .db
        .active_service_identity_has_capability(
            tenant.community(),
            workforce.lead_service_identity_id,
            "workforce.plan",
        )
        .await
        .map_err(|_| internal_error("workforce lead identity verification failed"))?;
    if !lead_ready {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Snowman workforce planning service is not ready",
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
            "request_deadline_at": task.request_deadline_at,
            "max_cost_microusd": task.max_cost_microusd,
            "max_input_tokens": task.max_input_tokens,
            "max_output_tokens": task.max_output_tokens,
            "specialist_role": task.specialist_role,
            "required_capabilities": task.required_capabilities,
            "model_gateway_route": task.model_gateway_route,
            "model_id": task.model_id,
            "execution_snapshot_sha256": hex::encode(task.execution_snapshot_sha256),
            "expected_artifact_contract": task.expected_artifact_contract,
            "context_packet_id": task.context_packet_id,
            "risk_tier": task.risk_tier,
            "reversible": task.reversible,
            "approval_required": task.approval_required,
        }
    })))
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

fn is_recent_worker_time(value: DateTime<Utc>) -> bool {
    let now = Utc::now();
    value >= now - Duration::days(30) && value <= now + Duration::minutes(5)
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
}
