#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Private transactional API and deterministic timezone scheduler for Snowman orchestration.
//!
//! This service persists only governed metadata and immutable Analyst 360 references. It
//! authenticates every mutation with a freshly signed NIP-98 event, binds the signing key to
//! an active workforce identity and exact tenant/workspace capability, and uses serializable
//! transactions for plan generations, cancellation fences, budget reservations, and dispatch
//! outbox records. It never accepts raw client data, prompts, provider endpoints, or keys.

use std::{collections::BTreeSet, net::SocketAddr, str::FromStr, time::Duration};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{
    DateTime, Datelike, Duration as ChronoDuration, LocalResult, NaiveDate, NaiveDateTime,
    TimeZone, Timelike, Utc,
};
use chrono_tz::Tz;
use nostr::TagKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snowman_orchestration::{
    validate_plan, Classification, OrchestrationPlan, PlanState, WorkKind,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;
use uuid::Uuid;

/// Exact private plan-mutation request schema.
pub const COMMAND_SCHEMA: &str = "snowman.orchestration.command.v1";
/// Exact scheduler claim request schema.
pub const CLAIM_SCHEMA: &str = "snowman.orchestration.scheduler-claim.v1";
/// Exact API receipt schema.
pub const API_RECEIPT_SCHEMA: &str = "snowman.orchestration.api-receipt.v1";
/// Pinned timezone data release compiled into the scheduler binary.
/// Pinned scheduler timezone implementation. This identifies the compiled
/// crate release; it does not claim an independently verified IANA data tag.
pub const PINNED_TIMEZONE_IMPLEMENTATION: &str = "chrono-tz/0.10.4";

const MAX_REQUEST_BYTES: usize = 512 * 1024;
const AUTH_TTL_SECONDS: i64 = 60;
const MAX_CLAIMS: u16 = 32;

/// Stable service errors that never include request content.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Authentication, identity, scope, or capability is not live.
    #[error("orchestration request is not authorized")]
    Unauthorized,
    /// The exact bounded request or schedule is invalid.
    #[error("orchestration request is invalid")]
    Invalid,
    /// A cancellation, supersession, idempotency, or lease fence won.
    #[error("orchestration authority conflicts with durable state")]
    Conflict,
    /// The dedicated persistence boundary was unavailable.
    #[error("orchestration persistence failed")]
    Database,
    /// A configured timezone or local occurrence could not be resolved.
    #[error("orchestration schedule cannot be resolved")]
    Timezone,
}

/// DST gap behavior for a local wall-clock occurrence that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DstGapPolicy {
    /// Do not run the missing occurrence.
    Skip,
    /// Move to the first valid local minute after the gap.
    ShiftForward,
}

/// DST fold behavior for an ambiguous local wall-clock occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DstFoldPolicy {
    /// Use the earlier UTC instant.
    First,
    /// Use the later UTC instant.
    Second,
}

/// Restart/catch-up behavior when a scheduler wakes after an occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatchUpPolicy {
    /// Advance without dispatching a missed occurrence.
    Skip,
    /// Dispatch at most one recent missed occurrence.
    One,
}

/// Explicit local-time recurrence attached to a governed plan.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrencePolicy {
    /// Monotonic schedule generation, normally equal to the plan generation.
    pub schedule_generation: u64,
    /// IANA timezone name.
    pub timezone: String,
    /// Local minute after midnight.
    pub local_minute: u16,
    /// ISO weekdays, Monday=1 through Sunday=7.
    pub weekdays: BTreeSet<u8>,
    /// Missing local-time policy.
    pub dst_gap_policy: DstGapPolicy,
    /// Ambiguous local-time policy.
    pub dst_fold_policy: DstFoldPolicy,
    /// Restart catch-up policy.
    pub catch_up_policy: CatchUpPolicy,
    /// Oldest occurrence eligible for the one-occurrence catch-up.
    pub max_catch_up_seconds: u32,
    /// Default-off execution switch.
    pub enabled: bool,
}

impl RecurrencePolicy {
    /// Validate bounds and the pinned IANA timezone name.
    pub fn validate(&self) -> Result<Tz, Error> {
        let timezone = Tz::from_str(&self.timezone).map_err(|_| Error::Timezone)?;
        if self.schedule_generation == 0
            || self.local_minute >= 1_440
            || self.weekdays.is_empty()
            || self.weekdays.len() > 7
            || self.weekdays.iter().any(|day| !(1..=7).contains(day))
            || self.max_catch_up_seconds > 86_400
        {
            return Err(Error::Invalid);
        }
        Ok(timezone)
    }
}

/// One fully resolved recurrence instant and the local date that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedOccurrence {
    /// UTC occurrence used for durable comparison and dispatch.
    pub scheduled_at: DateTime<Utc>,
    /// Original candidate local date.
    pub local_date: NaiveDate,
    /// Whether a nonexistent local time was shifted through a DST gap.
    pub shifted_for_gap: bool,
    /// Whether an ambiguous local time selected one side of a DST fold.
    pub selected_fold: bool,
}

/// Catch-up decision for a persisted occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchUpDecision {
    /// Dispatch now using the original occurrence identity.
    Fire,
    /// Mark skipped and advance to the next occurrence.
    Skip,
    /// The occurrence is not due yet.
    NotDue,
}

/// Resolve the first policy occurrence strictly after `after`.
pub fn next_occurrence(
    policy: &RecurrencePolicy,
    after: DateTime<Utc>,
) -> Result<ResolvedOccurrence, Error> {
    let timezone = policy.validate()?;
    let local_start = after.with_timezone(&timezone).date_naive();
    for day_offset in 0..=370_i64 {
        let date = local_start
            .checked_add_signed(ChronoDuration::days(day_offset))
            .ok_or(Error::Timezone)?;
        if !policy
            .weekdays
            .contains(&(date.weekday().number_from_monday() as u8))
        {
            continue;
        }
        let candidate = date
            .and_hms_opt(
                u32::from(policy.local_minute / 60),
                u32::from(policy.local_minute % 60),
                0,
            )
            .ok_or(Error::Timezone)?;
        if let Some(occurrence) = resolve_local(policy, timezone, date, candidate)? {
            if occurrence.scheduled_at > after {
                return Ok(occurrence);
            }
        }
    }
    Err(Error::Timezone)
}

fn resolve_local(
    policy: &RecurrencePolicy,
    timezone: Tz,
    date: NaiveDate,
    candidate: NaiveDateTime,
) -> Result<Option<ResolvedOccurrence>, Error> {
    match timezone.from_local_datetime(&candidate) {
        LocalResult::Single(value) => Ok(Some(ResolvedOccurrence {
            scheduled_at: value.with_timezone(&Utc),
            local_date: date,
            shifted_for_gap: false,
            selected_fold: false,
        })),
        LocalResult::Ambiguous(first, second) => {
            let (earlier, later) = if first <= second {
                (first, second)
            } else {
                (second, first)
            };
            let selected = match policy.dst_fold_policy {
                DstFoldPolicy::First => earlier,
                DstFoldPolicy::Second => later,
            };
            Ok(Some(ResolvedOccurrence {
                scheduled_at: selected.with_timezone(&Utc),
                local_date: date,
                shifted_for_gap: false,
                selected_fold: true,
            }))
        }
        LocalResult::None if policy.dst_gap_policy == DstGapPolicy::Skip => Ok(None),
        LocalResult::None => {
            for minutes in 1..=180_i64 {
                let shifted = candidate
                    .checked_add_signed(ChronoDuration::minutes(minutes))
                    .ok_or(Error::Timezone)?;
                match timezone.from_local_datetime(&shifted) {
                    LocalResult::Single(value) => {
                        return Ok(Some(ResolvedOccurrence {
                            scheduled_at: value.with_timezone(&Utc),
                            local_date: date,
                            shifted_for_gap: true,
                            selected_fold: false,
                        }));
                    }
                    LocalResult::Ambiguous(first, second) => {
                        let value = if policy.dst_fold_policy == DstFoldPolicy::First {
                            first.min(second)
                        } else {
                            first.max(second)
                        };
                        return Ok(Some(ResolvedOccurrence {
                            scheduled_at: value.with_timezone(&Utc),
                            local_date: date,
                            shifted_for_gap: true,
                            selected_fold: true,
                        }));
                    }
                    LocalResult::None => {}
                }
            }
            Err(Error::Timezone)
        }
    }
}

/// Decide whether a persisted due occurrence may be caught up after downtime.
pub fn decide_catch_up(
    policy: &RecurrencePolicy,
    scheduled_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> CatchUpDecision {
    if now < scheduled_at {
        return CatchUpDecision::NotDue;
    }
    let age = now.signed_duration_since(scheduled_at).num_seconds();
    match policy.catch_up_policy {
        CatchUpPolicy::One if age <= i64::from(policy.max_catch_up_seconds) => {
            CatchUpDecision::Fire
        }
        CatchUpPolicy::Skip | CatchUpPolicy::One => CatchUpDecision::Skip,
    }
}

/// Resolve a trusted UTC instant to the plan's local wall-clock minute.
pub fn local_minute(timezone: &str, now: DateTime<Utc>) -> Result<u16, Error> {
    let timezone = Tz::from_str(timezone).map_err(|_| Error::Timezone)?;
    let local = now.with_timezone(&timezone);
    u16::try_from(local.hour() * 60 + local.minute()).map_err(|_| Error::Timezone)
}

/// Exact create-plan envelope. New plans must be draft and automation remains disabled.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePlanCommand {
    /// Contract schema.
    pub schema_version: String,
    /// Tenant-local idempotency key.
    pub command_id: Uuid,
    /// Bound caller identity.
    pub service_identity_id: Uuid,
    /// Operations-owned principal label.
    pub service_principal: String,
    /// Exact caller policy generation.
    pub policy_generation: u64,
    /// Validated orchestration contract.
    pub plan: OrchestrationPlan,
    /// Optional wall-clock recurrence; disabled at creation.
    pub recurrence: Option<RecurrencePolicy>,
}

/// Exact cancellation envelope. Cancellation removes dispatch authority before returning.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelPlanCommand {
    /// Contract schema.
    pub schema_version: String,
    /// Tenant-local idempotency key.
    pub command_id: Uuid,
    /// Bound caller identity.
    pub service_identity_id: Uuid,
    /// Operations-owned principal label.
    pub service_principal: String,
    /// Exact caller policy generation.
    pub policy_generation: u64,
    /// Generation being cancelled.
    pub plan_generation: u64,
    /// Digest of immutable cancellation evidence.
    pub cancellation_evidence_sha256: String,
}

/// Exact scheduler claim envelope.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerClaimRequest {
    /// Contract schema.
    pub schema_version: String,
    /// Replay-safe request identifier.
    pub request_id: Uuid,
    /// Dedicated scheduler service identity.
    pub service_identity_id: Uuid,
    /// Operations-owned principal label.
    pub service_principal: String,
    /// Exact caller policy generation.
    pub policy_generation: u64,
    /// Bounded number of dispatch records.
    pub max_claims: u16,
    /// Bounded crash lease duration.
    pub lease_seconds: u16,
}

/// Durable result of an API mutation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiReceipt {
    /// Receipt contract schema.
    pub schema_version: String,
    /// Request/command identity.
    pub command_id: Uuid,
    /// Exact tenant.
    pub community_id: Uuid,
    /// Exact workspace.
    pub workspace_id: Uuid,
    /// Exact plan.
    pub plan_id: Uuid,
    /// Exact generation.
    pub plan_generation: u64,
    /// Applied or duplicate.
    pub status: String,
    /// SHA-256 of the authenticated body.
    pub request_sha256: String,
    /// Trusted acceptance time.
    pub accepted_at: DateTime<Utc>,
}

/// Crash-fenced dispatch outbox lease returned only to the private scheduler worker.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchLease {
    /// Stable dispatch identity.
    pub dispatch_id: Uuid,
    /// Exact plan generation.
    pub plan_id: Uuid,
    /// Exact plan generation.
    pub plan_generation: u64,
    /// Existing workforce task.
    pub task_id: Uuid,
    /// Lease generation, incremented on every recovery claim.
    pub lease_generation: u64,
    /// Coordinator job coordinate.
    pub coordinator_job_reference: String,
    /// Exact model route coordinate.
    pub model_route_reference: String,
    /// Immutable Analyst context only.
    pub analyst_context_references: Vec<String>,
    /// Exact broker capabilities.
    pub required_capabilities: Vec<String>,
    /// Lease expiry.
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone)]
struct VerifiedAuth {
    pubkey: [u8; 32],
    event_id: [u8; 32],
    created_at: DateTime<Utc>,
}

/// Exact private-service configuration.
pub struct Config {
    bind_addr: SocketAddr,
    database_url: String,
    max_connections: u32,
    private_origin: Url,
}

/// Non-sensitive configuration failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A static or secret-backed setting failed closed.
    #[error("Snowman orchestration configuration is invalid: {0}")]
    Invalid(&'static str),
    /// Dedicated database initialization failed.
    #[error("Snowman orchestration database initialization failed")]
    Database,
}

impl Config {
    /// Load configuration without accepting ambient provider credentials or public origins.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = env_value("SNOWMAN_ORCHESTRATION_BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()
            .map_err(|_| ConfigError::Invalid("bind address"))?;
        let database_url = required("SNOWMAN_ORCHESTRATION_DATABASE_URL")?;
        let max_connections = env_value("SNOWMAN_ORCHESTRATION_MAX_CONNECTIONS")
            .unwrap_or_else(|| "8".into())
            .parse::<u32>()
            .map_err(|_| ConfigError::Invalid("connection limit"))?;
        let private_origin = parse_private_origin(&required("SNOWMAN_ORCHESTRATION_ORIGIN")?)?;
        if !(1..=16).contains(&max_connections)
            || !valid_database_url(&database_url)
            || env_value("SNOWMAN_ORCHESTRATION_NETWORK_POLICY").as_deref()
                != Some("private-snowman-only")
        {
            return Err(ConfigError::Invalid("private service boundary"));
        }
        Ok(Self {
            bind_addr,
            database_url,
            max_connections,
            private_origin,
        })
    }
}

/// Shared service state.
#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    bind_addr: SocketAddr,
    private_origin: Url,
}

impl AppState {
    /// Open the dedicated database pool.
    pub async fn new(config: Config) -> Result<Self, ConfigError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&config.database_url)
            .await
            .map_err(|_| ConfigError::Database)?;
        Ok(Self {
            pool,
            bind_addr: config.bind_addr,
            private_origin: config.private_origin,
        })
    }

    /// Private listener address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

/// Build health, plan, cancellation, and scheduler routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/_liveness", get(|| async { StatusCode::NO_CONTENT }))
        .route("/_readiness", get(readiness))
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans",
            post(post_plan),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans/{plan_id}/cancel",
            post(cancel_plan),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/scheduler/claims",
            post(claim_dispatches),
        )
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
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

async fn post_plan(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApiReceipt>, ApiError> {
    check_body(&body)?;
    let url = endpoint_url(
        &state.private_origin,
        &format!("v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans"),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let command: CreatePlanCommand =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    validate_create(&command, tenant_id, workspace_id)?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let receipt = persist_plan(&state.pool, &command, &auth, digest, Utc::now()).await?;
    Ok(Json(receipt))
}

async fn cancel_plan(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id, plan_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApiReceipt>, ApiError> {
    check_body(&body)?;
    let url = endpoint_url(
        &state.private_origin,
        &format!("v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans/{plan_id}/cancel"),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let command: CancelPlanCommand =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    validate_cancel(&command)?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let receipt = persist_cancellation(
        &state.pool,
        PlanScope {
            tenant_id,
            workspace_id,
            plan_id,
        },
        &command,
        &auth,
        digest,
        Utc::now(),
    )
    .await?;
    Ok(Json(receipt))
}

async fn claim_dispatches(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Vec<DispatchLease>>, ApiError> {
    check_body(&body)?;
    let url = endpoint_url(
        &state.private_origin,
        &format!("v1/tenants/{tenant_id}/workspaces/{workspace_id}/scheduler/claims"),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let request: SchedulerClaimRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    if request.schema_version != CLAIM_SCHEMA
        || request.request_id.is_nil()
        || request.service_identity_id.is_nil()
        || request.policy_generation == 0
        || !(1..=MAX_CLAIMS).contains(&request.max_claims)
        || !(30..=900).contains(&request.lease_seconds)
    {
        return Err(ApiError(Error::Invalid));
    }
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let leases = claim_ready_dispatches(
        &state.pool,
        tenant_id,
        workspace_id,
        &request,
        &auth,
        digest,
        Utc::now(),
    )
    .await?;
    Ok(Json(leases))
}

fn validate_create(
    command: &CreatePlanCommand,
    tenant_id: Uuid,
    workspace_id: Uuid,
) -> Result<(), ApiError> {
    validate_plan(&command.plan).map_err(|_| ApiError(Error::Invalid))?;
    if command.schema_version != COMMAND_SCHEMA
        || command.command_id.is_nil()
        || command.service_identity_id.is_nil()
        || command.policy_generation == 0
        || command.plan.community_id != tenant_id
        || command.plan.workspace_id != workspace_id
        || command.plan.state != PlanState::Draft
        || command.plan.automatic_execution.enabled
    {
        return Err(ApiError(Error::Invalid));
    }
    if let Some(recurrence) = &command.recurrence {
        recurrence.validate().map_err(ApiError)?;
        if recurrence.enabled
            || recurrence.schedule_generation != command.plan.generation
            || recurrence.timezone != command.plan.schedule.quiet_hours.timezone
            || command.plan.schedule.recurring_schedule_ref.is_none()
        {
            return Err(ApiError(Error::Invalid));
        }
    }
    Ok(())
}

fn validate_cancel(command: &CancelPlanCommand) -> Result<(), ApiError> {
    if command.schema_version != COMMAND_SCHEMA
        || command.command_id.is_nil()
        || command.service_identity_id.is_nil()
        || command.policy_generation == 0
        || command.plan_generation == 0
        || !valid_hex_digest(&command.cancellation_evidence_sha256)
    {
        return Err(ApiError(Error::Invalid));
    }
    Ok(())
}

async fn persist_plan(
    pool: &PgPool,
    command: &CreatePlanCommand,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ApiReceipt, ApiError> {
    let plan = &command.plan;
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id: plan.community_id,
            workspace_id: plan.workspace_id,
            identity_id: command.service_identity_id,
            principal: &command.service_principal,
            policy_generation: command.policy_generation,
            capability: "orchestration.plans.write",
        },
        auth,
        digest,
        now,
    )
    .await?;
    if let Some(receipt) = duplicate_receipt(
        &mut tx,
        plan.community_id,
        plan.workspace_id,
        command.command_id,
        digest,
        now,
    )
    .await?
    {
        tx.commit().await.map_err(|_| ApiError(Error::Database))?;
        return Ok(receipt);
    }
    let plan_sha256: [u8; 32] =
        Sha256::digest(serde_json::to_vec(plan).map_err(|_| ApiError(Error::Invalid))?).into();
    sqlx::query(
        "INSERT INTO snowman_orchestration_plans \
         (community_id,workspace_id,plan_id,request_id,project_id,work_kind,generation,\
          supersedes_plan_id,objective_sha256,classification,plan_sha256,max_cost_microusd,\
          automatic_execution_enabled,minimum_confidence_basis_points,minimum_value_basis_points,\
          maximum_risk_basis_points,max_automatic_task_cost_microusd,deadline_at,state,created_at,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,FALSE,$13,$14,$15,$16,$17,'draft',$18,$18)",
    )
    .bind(plan.community_id)
    .bind(plan.workspace_id)
    .bind(plan.plan_id)
    .bind(plan.request_id)
    .bind(plan.project_id)
    .bind(work_kind(plan.work_kind))
    .bind(plan.generation as i64)
    .bind(plan.supersedes_plan_id)
    .bind(plan.objective_sha256.as_slice())
    .bind(classification(plan.classification))
    .bind(plan_sha256.as_slice())
    .bind(plan.max_cost_microusd as i64)
    .bind(i32::from(plan.automatic_execution.minimum_confidence_basis_points))
    .bind(i32::from(plan.automatic_execution.minimum_value_basis_points))
    .bind(i32::from(plan.automatic_execution.maximum_risk_basis_points))
    .bind(plan.automatic_execution.max_task_cost_microusd as i64)
    .bind(plan.schedule.deadline_at)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(db_conflict)?;
    sqlx::query(
        "INSERT INTO snowman_orchestration_schedule_policies \
         (community_id,plan_id,recurring_schedule_reference,timezone,timezone_database_version,\
          quiet_start_local_minute,quiet_end_local_minute,allow_deadline_reminders,\
          reminder_offsets_seconds,policy_sha256) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(plan.community_id)
    .bind(plan.plan_id)
    .bind(&plan.schedule.recurring_schedule_ref)
    .bind(&plan.schedule.quiet_hours.timezone)
    .bind(PINNED_TIMEZONE_IMPLEMENTATION)
    .bind(i32::from(plan.schedule.quiet_hours.start_local_minute))
    .bind(i32::from(plan.schedule.quiet_hours.end_local_minute))
    .bind(plan.schedule.quiet_hours.allow_deadline_reminders)
    .bind(
        plan.schedule
            .reminder_offsets_seconds
            .iter()
            .map(|value| i32::try_from(*value).map_err(|_| ApiError(Error::Invalid)))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .bind(
        Sha256::digest(serde_json::to_vec(&plan.schedule).map_err(|_| ApiError(Error::Invalid))?)
            .as_slice(),
    )
    .execute(&mut *tx)
    .await
    .map_err(db_conflict)?;
    for capability in &plan.automatic_execution.allowed_capabilities {
        sqlx::query(
            "INSERT INTO snowman_orchestration_plan_automatic_capabilities \
             (community_id,plan_id,capability) VALUES ($1,$2,$3)",
        )
        .bind(plan.community_id)
        .bind(plan.plan_id)
        .bind(capability)
        .execute(&mut *tx)
        .await
        .map_err(db_conflict)?;
    }
    for persona in &plan.personas {
        sqlx::query(
            "INSERT INTO snowman_orchestration_personas \
             (community_id,plan_id,persona_id,persona_version_sha256,service_identity_id,\
              specialist_role,model_id,model_route_revision,maximum_classification,max_cost_microusd,\
              enabled,model_route_reference) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(plan.community_id)
        .bind(plan.plan_id)
        .bind(persona.persona_id)
        .bind(persona.persona_version_sha256.as_slice())
        .bind(persona.service_identity_id)
        .bind(&persona.specialist_role)
        .bind(&persona.model_id)
        .bind(model_route_revision(&persona.model_route_ref)? as i64)
        .bind(classification(persona.maximum_classification))
        .bind(persona.max_cost_microusd as i64)
        .bind(persona.enabled)
        .bind(&persona.model_route_ref)
        .execute(&mut *tx)
        .await
        .map_err(db_conflict)?;
        for capability in &persona.tool_capability_grants {
            sqlx::query(
                "INSERT INTO snowman_orchestration_persona_capabilities \
                 (community_id,plan_id,persona_id,capability,automatic_execution_allowed) \
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(plan.community_id)
            .bind(plan.plan_id)
            .bind(persona.persona_id)
            .bind(capability)
            .bind(
                plan.automatic_execution
                    .allowed_capabilities
                    .contains(capability),
            )
            .execute(&mut *tx)
            .await
            .map_err(db_conflict)?;
        }
    }
    for task in &plan.tasks {
        sqlx::query(
            "INSERT INTO snowman_orchestration_tasks \
             (community_id,plan_id,plan_generation,request_id,task_id,persona_id,usefulness_sha256,\
              confidence_basis_points,value_basis_points,risk_basis_points,reversible,approval_required,\
              automatic_execution_candidate,max_cost_microusd,deadline_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        )
        .bind(plan.community_id)
        .bind(plan.plan_id)
        .bind(plan.generation as i64)
        .bind(plan.request_id)
        .bind(task.task_id)
        .bind(task.persona_id)
        .bind(task.score.usefulness_sha256.as_slice())
        .bind(i32::from(task.score.confidence_basis_points))
        .bind(i32::from(task.score.value_basis_points))
        .bind(i32::from(task.score.risk_basis_points))
        .bind(task.reversible)
        .bind(task.approval_required)
        .bind(task.automatic_execution_candidate)
        .bind(task.max_cost_microusd as i64)
        .bind(task.deadline_at)
        .execute(&mut *tx)
        .await
        .map_err(db_conflict)?;
        for reference in &task.analyst_context_manifest_refs {
            sqlx::query(
                "INSERT INTO snowman_orchestration_task_context_refs \
                 (community_id,plan_id,task_id,context_manifest_reference) VALUES ($1,$2,$3,$4)",
            )
            .bind(plan.community_id)
            .bind(plan.plan_id)
            .bind(task.task_id)
            .bind(reference)
            .execute(&mut *tx)
            .await
            .map_err(db_conflict)?;
        }
    }
    // Insert dependency edges only after every task row exists. Plans may list a
    // dependent task before its prerequisite, and the database foreign keys are
    // intentionally immediate so invalid references fail inside this transaction.
    for task in &plan.tasks {
        for dependency in &task.depends_on {
            sqlx::query(
                "INSERT INTO snowman_orchestration_task_dependencies \
                 (community_id,plan_id,plan_generation,task_id,depends_on_task_id) \
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(plan.community_id)
            .bind(plan.plan_id)
            .bind(plan.generation as i64)
            .bind(task.task_id)
            .bind(dependency)
            .execute(&mut *tx)
            .await
            .map_err(db_conflict)?;
        }
    }
    if let Some(recurrence) = &command.recurrence {
        let first = next_occurrence(recurrence, now).map_err(ApiError)?;
        let schedule_digest: [u8; 32] =
            Sha256::digest(serde_json::to_vec(recurrence).map_err(|_| ApiError(Error::Invalid))?)
                .into();
        sqlx::query(
            "INSERT INTO snowman_orchestration_recurrences \
             (community_id,workspace_id,plan_id,schedule_generation,local_minute,weekdays,\
              dst_gap_policy,dst_fold_policy,catch_up_policy,max_catch_up_seconds,next_fire_at,\
              enabled,schedule_sha256,created_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,FALSE,$12,$13,$13)",
        )
        .bind(plan.community_id)
        .bind(plan.workspace_id)
        .bind(plan.plan_id)
        .bind(recurrence.schedule_generation as i64)
        .bind(i32::from(recurrence.local_minute))
        .bind(
            recurrence
                .weekdays
                .iter()
                .map(|v| i16::from(*v))
                .collect::<Vec<_>>(),
        )
        .bind(gap_policy(recurrence.dst_gap_policy))
        .bind(fold_policy(recurrence.dst_fold_policy))
        .bind(catch_up_policy(recurrence.catch_up_policy))
        .bind(i32::try_from(recurrence.max_catch_up_seconds).map_err(|_| ApiError(Error::Invalid))?)
        .bind(first.scheduled_at)
        .bind(schedule_digest.as_slice())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_conflict)?;
    }
    insert_command(
        &mut tx,
        plan.community_id,
        plan.workspace_id,
        command.command_id,
        "create_plan",
        plan.plan_id,
        plan.generation,
        digest,
        command.service_identity_id,
        now,
    )
    .await?;
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(receipt(command.command_id, plan, "applied", digest, now))
}

#[derive(Clone, Copy)]
struct PlanScope {
    tenant_id: Uuid,
    workspace_id: Uuid,
    plan_id: Uuid,
}

async fn persist_cancellation(
    pool: &PgPool,
    scope: PlanScope,
    command: &CancelPlanCommand,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ApiReceipt, ApiError> {
    let PlanScope {
        tenant_id,
        workspace_id,
        plan_id,
    } = scope;
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id,
            workspace_id,
            identity_id: command.service_identity_id,
            principal: &command.service_principal,
            policy_generation: command.policy_generation,
            capability: "orchestration.plans.cancel",
        },
        auth,
        digest,
        now,
    )
    .await?;
    if let Some(receipt) = duplicate_receipt(
        &mut tx,
        tenant_id,
        workspace_id,
        command.command_id,
        digest,
        now,
    )
    .await?
    {
        tx.commit().await.map_err(|_| ApiError(Error::Database))?;
        return Ok(receipt);
    }
    let row = sqlx::query(
        "SELECT state FROM snowman_orchestration_plans \
         WHERE community_id=$1 AND workspace_id=$2 AND plan_id=$3 AND generation=$4 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(plan_id)
    .bind(command.plan_generation as i64)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    .ok_or(ApiError(Error::Conflict))?;
    let state: String = row
        .try_get("state")
        .map_err(|_| ApiError(Error::Database))?;
    if matches!(state.as_str(), "completed" | "superseded") {
        return Err(ApiError(Error::Conflict));
    }
    sqlx::query(
        "UPDATE snowman_orchestration_plans SET state='cancelled',cancelled_at=$1,updated_at=$1 \
         WHERE community_id=$2 AND plan_id=$3 AND generation=$4",
    )
    .bind(now)
    .bind(tenant_id)
    .bind(plan_id)
    .bind(command.plan_generation as i64)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "UPDATE snowman_orchestration_recurrences SET enabled=FALSE,next_fire_at=NULL,updated_at=$1 \
         WHERE community_id=$2 AND plan_id=$3",
    )
    .bind(now)
    .bind(tenant_id)
    .bind(plan_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "UPDATE snowman_orchestration_dispatches SET status='cancelled',cancellation_generation=cancellation_generation+1,\
         lease_owner_identity_id=NULL,lease_expires_at=NULL,updated_at=$1 \
         WHERE community_id=$2 AND plan_id=$3 AND plan_generation=$4 \
           AND status IN ('pending','leased','failed')",
    )
    .bind(now)
    .bind(tenant_id)
    .bind(plan_id)
    .bind(command.plan_generation as i64)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "UPDATE snowman_orchestration_reminder_receipts SET status='cancelled' \
         WHERE community_id=$1 AND plan_id=$2 AND plan_generation=$3 AND status='pending'",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .bind(command.plan_generation as i64)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    insert_command(
        &mut tx,
        tenant_id,
        workspace_id,
        command.command_id,
        "cancel_plan",
        plan_id,
        command.plan_generation,
        digest,
        command.service_identity_id,
        now,
    )
    .await?;
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(ApiReceipt {
        schema_version: API_RECEIPT_SCHEMA.into(),
        command_id: command.command_id,
        community_id: tenant_id,
        workspace_id,
        plan_id,
        plan_generation: command.plan_generation,
        status: "applied".into(),
        request_sha256: hex::encode(digest),
        accepted_at: now,
    })
}

async fn claim_ready_dispatches(
    pool: &PgPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    request: &SchedulerClaimRequest,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<Vec<DispatchLease>, ApiError> {
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id,
            workspace_id,
            identity_id: request.service_identity_id,
            principal: &request.service_principal,
            policy_generation: request.policy_generation,
            capability: "orchestration.scheduler.dispatch",
        },
        auth,
        digest,
        now,
    )
    .await?;
    let rows = sqlx::query(
        "SELECT d.dispatch_id,d.plan_id,d.plan_generation,d.task_id,d.lease_generation,\
                d.coordinator_job_reference,d.model_route_reference,d.analyst_context_references,\
                d.required_capabilities,d.attempt_count,d.max_attempts,d.cancellation_generation \
         FROM snowman_orchestration_dispatches d \
         JOIN snowman_orchestration_plans p ON p.community_id=d.community_id AND p.plan_id=d.plan_id \
           AND p.generation=d.plan_generation \
         WHERE d.community_id=$1 AND d.workspace_id=$2 AND p.state='active' \
           AND p.automatic_execution_enabled AND d.status IN ('pending','failed') \
           AND d.next_attempt_at<=$3 AND d.attempt_count<d.max_attempts \
         ORDER BY d.next_attempt_at,d.dispatch_id FOR UPDATE OF d SKIP LOCKED LIMIT $4",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(now)
    .bind(i64::from(request.max_claims))
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let lease_expires_at = now + ChronoDuration::seconds(i64::from(request.lease_seconds));
    let mut leases = Vec::with_capacity(rows.len());
    for row in rows {
        let attempt_count: i32 = row
            .try_get("attempt_count")
            .map_err(|_| ApiError(Error::Database))?;
        let lease_generation: i64 = row
            .try_get("lease_generation")
            .map_err(|_| ApiError(Error::Database))?;
        let dispatch_id: Uuid = row
            .try_get("dispatch_id")
            .map_err(|_| ApiError(Error::Database))?;
        let next_generation = lease_generation
            .checked_add(1)
            .ok_or(ApiError(Error::Conflict))?;
        let updated = sqlx::query(
            "UPDATE snowman_orchestration_dispatches SET status='leased',lease_generation=$1,\
             lease_owner_identity_id=$2,lease_expires_at=$3,attempt_count=$4,updated_at=$5 \
             WHERE community_id=$6 AND dispatch_id=$7 AND cancellation_generation=$8 \
               AND status IN ('pending','failed')",
        )
        .bind(next_generation)
        .bind(request.service_identity_id)
        .bind(lease_expires_at)
        .bind(attempt_count + 1)
        .bind(now)
        .bind(tenant_id)
        .bind(dispatch_id)
        .bind(
            row.try_get::<i64, _>("cancellation_generation")
                .map_err(|_| ApiError(Error::Database))?,
        )
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
        if updated.rows_affected() != 1 {
            return Err(ApiError(Error::Conflict));
        }
        leases.push(DispatchLease {
            dispatch_id,
            plan_id: row
                .try_get("plan_id")
                .map_err(|_| ApiError(Error::Database))?,
            plan_generation: row
                .try_get::<i64, _>("plan_generation")
                .map_err(|_| ApiError(Error::Database))? as u64,
            task_id: row
                .try_get("task_id")
                .map_err(|_| ApiError(Error::Database))?,
            lease_generation: next_generation as u64,
            coordinator_job_reference: row
                .try_get("coordinator_job_reference")
                .map_err(|_| ApiError(Error::Database))?,
            model_route_reference: row
                .try_get("model_route_reference")
                .map_err(|_| ApiError(Error::Database))?,
            analyst_context_references: row
                .try_get("analyst_context_references")
                .map_err(|_| ApiError(Error::Database))?,
            required_capabilities: row
                .try_get("required_capabilities")
                .map_err(|_| ApiError(Error::Database))?,
            lease_expires_at,
        });
    }
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(leases)
}

struct Scope<'a> {
    tenant_id: Uuid,
    workspace_id: Uuid,
    identity_id: Uuid,
    principal: &'a str,
    policy_generation: u64,
    capability: &'a str,
}

async fn authorize_and_record(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope<'_>,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM snowman_orchestration_callers c \
         JOIN snowman_workforce_identities i ON i.community_id=c.community_id AND i.identity_id=c.service_identity_id \
         JOIN snowman_workforce_key_bindings k ON k.community_id=i.community_id AND k.identity_id=i.identity_id \
         JOIN snowman_workforce_capability_grants g ON g.community_id=i.community_id AND g.identity_id=i.identity_id \
         WHERE c.community_id=$1 AND c.workspace_id=$2 AND c.service_identity_id=$3 \
           AND c.service_principal=$4 AND c.policy_generation=$5 AND c.status='active' \
           AND i.identity_type='service' AND i.provider='snowman_service' AND i.status='active' \
           AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at>NOW()) \
           AND k.pubkey=$6 AND k.binding_type='service_runtime' AND k.revoked_at IS NULL \
           AND (k.expires_at IS NULL OR k.expires_at>NOW()) \
           AND g.capability=$7 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>NOW()))",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.identity_id)
    .bind(scope.principal)
    .bind(scope.policy_generation as i64)
    .bind(auth.pubkey.as_slice())
    .bind(scope.capability)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    if !authorized {
        return Err(ApiError(Error::Unauthorized));
    }
    let inserted = sqlx::query(
        "INSERT INTO snowman_orchestration_auth_events \
         (community_id,auth_event_id,request_sha256,requester_pubkey,service_identity_id,observed_at,expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
    )
    .bind(scope.tenant_id)
    .bind(auth.event_id.as_slice())
    .bind(digest.as_slice())
    .bind(auth.pubkey.as_slice())
    .bind(scope.identity_id)
    .bind(now)
    .bind(auth.created_at + ChronoDuration::seconds(AUTH_TTL_SECONDS))
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    if inserted.rows_affected() != 1 {
        return Err(ApiError(Error::Unauthorized));
    }
    Ok(())
}

async fn serializable(pool: &PgPool) -> Result<Transaction<'_, Postgres>, ApiError> {
    let mut tx = pool.begin().await.map_err(|_| ApiError(Error::Database))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
    Ok(tx)
}

async fn duplicate_receipt(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    command_id: Uuid,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<Option<ApiReceipt>, ApiError> {
    let Some(row) = sqlx::query(
        "SELECT workspace_id,plan_id,plan_generation,command_sha256 FROM snowman_orchestration_commands \
         WHERE community_id=$1 AND command_id=$2",
    )
    .bind(tenant_id)
    .bind(command_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    else {
        return Ok(None);
    };
    let prior: Vec<u8> = row
        .try_get("command_sha256")
        .map_err(|_| ApiError(Error::Database))?;
    let prior_workspace: Uuid = row
        .try_get("workspace_id")
        .map_err(|_| ApiError(Error::Database))?;
    if prior != digest || prior_workspace != workspace_id {
        return Err(ApiError(Error::Conflict));
    }
    Ok(Some(ApiReceipt {
        schema_version: API_RECEIPT_SCHEMA.into(),
        command_id,
        community_id: tenant_id,
        workspace_id,
        plan_id: row
            .try_get("plan_id")
            .map_err(|_| ApiError(Error::Database))?,
        plan_generation: row
            .try_get::<i64, _>("plan_generation")
            .map_err(|_| ApiError(Error::Database))? as u64,
        status: "duplicate".into(),
        request_sha256: hex::encode(digest),
        accepted_at: now,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn insert_command(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    command_id: Uuid,
    command_kind: &str,
    plan_id: Uuid,
    generation: u64,
    digest: [u8; 32],
    identity_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO snowman_orchestration_commands \
         (community_id,workspace_id,command_id,command_kind,plan_id,plan_generation,command_sha256,\
          service_identity_id,status,applied_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'applied',$9)",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(command_id)
    .bind(command_kind)
    .bind(plan_id)
    .bind(generation as i64)
    .bind(digest.as_slice())
    .bind(identity_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(db_conflict)?;
    Ok(())
}

fn receipt(
    command_id: Uuid,
    plan: &OrchestrationPlan,
    status: &str,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> ApiReceipt {
    ApiReceipt {
        schema_version: API_RECEIPT_SCHEMA.into(),
        command_id,
        community_id: plan.community_id,
        workspace_id: plan.workspace_id,
        plan_id: plan.plan_id,
        plan_generation: plan.generation,
        status: status.into(),
        request_sha256: hex::encode(digest),
        accepted_at: now,
    }
}

fn verify_auth(headers: &HeaderMap, url: &str, body: &[u8]) -> Result<VerifiedAuth, ApiError> {
    let encoded = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Nostr "))
        .ok_or(ApiError(Error::Unauthorized))?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| ApiError(Error::Unauthorized))?;
    if bytes.len() > 32 * 1024 {
        return Err(ApiError(Error::Unauthorized));
    }
    let event_json = String::from_utf8(bytes).map_err(|_| ApiError(Error::Unauthorized))?;
    let event: nostr::Event =
        serde_json::from_str(&event_json).map_err(|_| ApiError(Error::Unauthorized))?;
    if !event.tags.iter().any(|tag| tag.kind() == TagKind::Payload) {
        return Err(ApiError(Error::Unauthorized));
    }
    let pubkey = buzz_auth::verify_nip98_event(&event_json, url, "POST", Some(body))
        .map_err(|_| ApiError(Error::Unauthorized))?;
    let created_at = DateTime::from_timestamp(event.created_at.as_secs() as i64, 0)
        .ok_or(ApiError(Error::Unauthorized))?;
    let now = Utc::now();
    if created_at > now + ChronoDuration::seconds(30)
        || now > created_at + ChronoDuration::seconds(AUTH_TTL_SECONDS)
    {
        return Err(ApiError(Error::Unauthorized));
    }
    Ok(VerifiedAuth {
        pubkey: pubkey.to_bytes(),
        event_id: event.id.to_bytes(),
        created_at,
    })
}

fn check_body(body: &[u8]) -> Result<(), ApiError> {
    if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
        Err(ApiError(Error::Invalid))
    } else {
        Ok(())
    }
}

fn endpoint_url(origin: &Url, path: &str) -> Result<Url, ApiError> {
    origin.join(path).map_err(|_| ApiError(Error::Invalid))
}

fn work_kind(value: WorkKind) -> &'static str {
    match value {
        WorkKind::UserRequest => "user_request",
        WorkKind::Project => "project",
        WorkKind::Deadline => "deadline",
        WorkKind::RecurringAnalytics => "recurring_analytics",
        WorkKind::NextBestAction => "next_best_action",
    }
}

fn classification(value: Classification) -> &'static str {
    match value {
        Classification::Internal => "internal",
        Classification::Confidential => "confidential",
        Classification::Restricted => "restricted",
    }
}

fn gap_policy(value: DstGapPolicy) -> &'static str {
    match value {
        DstGapPolicy::Skip => "skip",
        DstGapPolicy::ShiftForward => "shift_forward",
    }
}

fn fold_policy(value: DstFoldPolicy) -> &'static str {
    match value {
        DstFoldPolicy::First => "first",
        DstFoldPolicy::Second => "second",
    }
}

fn catch_up_policy(value: CatchUpPolicy) -> &'static str {
    match value {
        CatchUpPolicy::Skip => "skip",
        CatchUpPolicy::One => "one",
    }
}

fn model_route_revision(reference: &str) -> Result<u64, ApiError> {
    reference
        .rsplit_once(":revision:")
        .and_then(|(_, value)| value.parse().ok())
        .filter(|value| *value > 0)
        .ok_or(ApiError(Error::Invalid))
}

fn valid_hex_digest(value: &str) -> bool {
    value.len() == 64 && hex::decode(value).is_ok()
}

fn parse_private_origin(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("origin"))?;
    let host = url.host_str().ok_or(ConfigError::Invalid("origin"))?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || !(host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
    {
        return Err(ConfigError::Invalid("private Snowman origin"));
    }
    Ok(url)
}

fn valid_database_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "postgres" | "postgresql")
            && !url.username().is_empty()
            && url.host_str().is_some()
            && url.path().len() > 1
    })
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env_value(name).ok_or(ConfigError::Invalid(name))
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn db_conflict(error: sqlx::Error) -> ApiError {
    if error
        .as_database_error()
        .and_then(|value| value.code())
        .is_some_and(|code| matches!(code.as_ref(), "23505" | "23503" | "23514"))
    {
        ApiError(Error::Conflict)
    } else {
        ApiError(Error::Database)
    }
}

struct ApiError(Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::Invalid | Error::Timezone => StatusCode::BAD_REQUEST,
            Error::Conflict => StatusCode::CONFLICT,
            Error::Database => StatusCode::SERVICE_UNAVAILABLE,
        };
        status.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(timezone: &str, minute: u16) -> RecurrencePolicy {
        RecurrencePolicy {
            schedule_generation: 1,
            timezone: timezone.into(),
            local_minute: minute,
            weekdays: BTreeSet::from([1, 2, 3, 4, 5, 6, 7]),
            dst_gap_policy: DstGapPolicy::ShiftForward,
            dst_fold_policy: DstFoldPolicy::First,
            catch_up_policy: CatchUpPolicy::One,
            max_catch_up_seconds: 3_600,
            enabled: false,
        }
    }

    fn utc(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(|error| panic!("test timestamp: {error}"))
    }

    #[test]
    fn spring_gap_shifts_to_first_valid_minute() {
        let occurrence = next_occurrence(
            &policy("America/Denver", 2 * 60 + 30),
            utc("2026-03-08T07:00:00Z"),
        )
        .unwrap_or_else(|error| panic!("resolve: {error}"));
        assert_eq!(occurrence.scheduled_at, utc("2026-03-08T09:00:00Z"));
        assert!(occurrence.shifted_for_gap);
    }

    #[test]
    fn spring_gap_skip_moves_to_next_day() {
        let mut value = policy("America/Denver", 2 * 60 + 30);
        value.dst_gap_policy = DstGapPolicy::Skip;
        let occurrence = next_occurrence(&value, utc("2026-03-08T07:00:00Z"))
            .unwrap_or_else(|error| panic!("resolve: {error}"));
        assert_eq!(occurrence.scheduled_at, utc("2026-03-09T08:30:00Z"));
        assert!(!occurrence.shifted_for_gap);
    }

    #[test]
    fn fall_fold_selects_exact_side() {
        let mut first = policy("America/Denver", 90);
        first.dst_fold_policy = DstFoldPolicy::First;
        let first_at = next_occurrence(&first, utc("2026-11-01T06:00:00Z"))
            .unwrap_or_else(|error| panic!("first fold: {error}"));
        let mut second = first.clone();
        second.dst_fold_policy = DstFoldPolicy::Second;
        let second_at = next_occurrence(&second, utc("2026-11-01T06:00:00Z"))
            .unwrap_or_else(|error| panic!("second fold: {error}"));
        assert_eq!(first_at.scheduled_at, utc("2026-11-01T07:30:00Z"));
        assert_eq!(second_at.scheduled_at, utc("2026-11-01T08:30:00Z"));
        assert!(first_at.selected_fold && second_at.selected_fold);
    }

    #[test]
    fn catch_up_is_bounded_to_one_recent_occurrence() {
        let value = policy("America/Denver", 9 * 60);
        let due = utc("2026-01-05T16:00:00Z");
        assert_eq!(
            decide_catch_up(&value, due, due - ChronoDuration::seconds(1)),
            CatchUpDecision::NotDue
        );
        assert_eq!(
            decide_catch_up(&value, due, due + ChronoDuration::minutes(30)),
            CatchUpDecision::Fire
        );
        assert_eq!(
            decide_catch_up(&value, due, due + ChronoDuration::hours(2)),
            CatchUpDecision::Skip
        );
    }

    #[test]
    fn weekday_schedule_never_selects_unlisted_day() {
        let mut value = policy("America/New_York", 9 * 60);
        value.weekdays = BTreeSet::from([1, 3, 5]);
        let mut after = utc("2026-01-01T00:00:00Z");
        for _ in 0..500 {
            let occurrence = next_occurrence(&value, after)
                .unwrap_or_else(|error| panic!("property occurrence: {error}"));
            assert!(value
                .weekdays
                .contains(&(occurrence.local_date.weekday().number_from_monday() as u8)));
            assert!(occurrence.scheduled_at > after);
            after = occurrence.scheduled_at;
        }
    }

    #[test]
    fn utc_occurrences_are_strictly_monotonic_across_dst_year() {
        for timezone in ["America/Denver", "America/New_York", "Europe/London"] {
            let value = policy(timezone, 90);
            let mut after = utc("2026-01-01T00:00:00Z");
            for _ in 0..370 {
                let next = next_occurrence(&value, after)
                    .unwrap_or_else(|error| panic!("monotonic {timezone}: {error}"));
                assert!(next.scheduled_at > after);
                after = next.scheduled_at;
            }
        }
    }

    #[test]
    fn local_minute_observes_dst_offsets() {
        assert_eq!(
            local_minute("America/Denver", utc("2026-01-15T16:00:00Z")).expect("winter time"),
            9 * 60
        );
        assert_eq!(
            local_minute("America/Denver", utc("2026-07-15T15:00:00Z")).expect("summer time"),
            9 * 60
        );
    }

    #[test]
    fn recurrence_is_default_off_and_rejects_unbounded_values() {
        let value = policy("America/Denver", 9 * 60);
        assert!(!value.enabled);
        assert!(value.validate().is_ok());
        let mut invalid = value.clone();
        invalid.weekdays.insert(8);
        assert!(matches!(invalid.validate(), Err(Error::Invalid)));
        invalid = value;
        invalid.timezone = "Etc/Not-A-Timezone".into();
        assert!(matches!(invalid.validate(), Err(Error::Timezone)));
    }

    #[test]
    fn private_origin_rejects_non_snowman_and_credentials() {
        assert!(parse_private_origin("https://orchestration.internal.snowmanai.org/").is_ok());
        assert!(parse_private_origin("https://block.xyz/").is_err());
        assert!(parse_private_origin("https://user:secret@snowmanai.org/").is_err());
        assert!(parse_private_origin("http://orchestration.snowmanai.org/").is_err());
    }

    #[test]
    fn cancellation_sql_removes_live_authority_before_return() {
        let source = include_str!("../../../migrations/0053_snowman_orchestration_service.sql");
        assert!(!source.contains("automatic_execution_enabled BOOLEAN NOT NULL DEFAULT FALSE"));
        assert!(source.contains("enabled BOOLEAN NOT NULL DEFAULT FALSE"));
        assert!(source.contains("cancellation_generation"));
        assert!(source
            .contains("UNIQUE (community_id, plan_id, plan_generation, task_id, occurrence_id)"));
        assert!(!source.contains("FOR UPDATE"));
    }

    #[test]
    fn migration_preserves_tenant_and_budget_boundaries() {
        let source = include_str!("../../../migrations/0053_snowman_orchestration_service.sql");
        for table in [
            "snowman_orchestration_callers",
            "snowman_orchestration_dispatches",
            "snowman_orchestration_dispatch_receipts",
            "snowman_orchestration_dead_letters",
        ] {
            let start = source
                .find(&format!("CREATE TABLE {table}"))
                .unwrap_or_else(|| panic!("{table}"));
            let tail = &source[start..];
            let end = tail.find(";").unwrap_or_else(|| panic!("{table} end"));
            assert!(tail[..end].contains("community_id UUID NOT NULL"));
        }
        assert!(source.contains("reserved_cost_microusd BIGINT NOT NULL"));
        assert!(source.contains("analyst_context_references TEXT[] NOT NULL"));
        assert!(!source.contains("provider_api_key"));
        assert!(!source.contains("raw_prompt"));
    }
}
