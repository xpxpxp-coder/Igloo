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
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use buzz_db::workforce::{NewWorkRequest, NewWorkTask};

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

async fn authenticate_human(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    capability: &str,
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
    bridge::enforce_http_admission(state, &tenant, &pubkey).await?;
    relay_members::enforce_relay_membership(state, tenant.community(), pubkey.as_bytes(), None)
        .await?;
    let principal = authorization::require_workforce_capability(
        state,
        tenant.community(),
        &pubkey,
        capability,
        true,
    )
    .await
    .map_err(|error| {
        tracing::warn!(community = %tenant.community(), %error, "workforce API authorization denied");
        api_error(StatusCode::FORBIDDEN, "workforce operation is not authorized")
    })?;
    Ok((tenant, principal))
}

/// Accept one idempotent user objective and enqueue its governed planning task.
pub async fn create_work_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let (tenant, principal) = authenticate_human(
        &state,
        &headers,
        "POST",
        CREATE_PATH,
        Some(&body),
        "workforce.requests.create",
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
    let (tenant, _) = authenticate_human(
        &state,
        &headers,
        "GET",
        &path,
        None,
        "workforce.requests.read",
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
}
