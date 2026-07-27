#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Private transactional API and deterministic timezone scheduler for Snowman orchestration.
//!
//! This service persists only governed metadata and immutable Analyst 360 references. It
//! authenticates every mutation with a freshly signed NIP-98 event, binds the signing key to
//! an active workforce identity and exact tenant/workspace capability, and uses serializable
//! transactions for plan generations, cancellation fences, budget reservations, and dispatch
//! outbox records. It never accepts raw client data, prompts, provider endpoints, or keys.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    str::FromStr,
    time::Duration,
};

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
/// Exact activation, pause, supersession, and scheduler-cycle request schema.
pub const LIFECYCLE_SCHEMA: &str = "snowman.orchestration.lifecycle.v1";
/// Exact coordinator delivery result schema.
pub const DELIVERY_SCHEMA: &str = "snowman.orchestration.delivery-result.v1";
/// Exact terminal execution receipt schema.
pub const TERMINAL_RECEIPT_SCHEMA: &str = "snowman.orchestration.terminal-receipt.v1";
/// Exact control-outbox claim request schema.
pub const CONTROL_CLAIM_SCHEMA: &str = "snowman.orchestration.control-claim.v1";
/// Exact control-outbox delivery result schema.
pub const CONTROL_DELIVERY_SCHEMA: &str = "snowman.orchestration.control-delivery.v1";
/// Pinned timezone data release compiled into the scheduler binary.
/// Pinned scheduler timezone implementation. This identifies the compiled
/// crate release; it does not claim an independently verified IANA data tag.
pub const PINNED_TIMEZONE_IMPLEMENTATION: &str = "chrono-tz/0.10.4";

const MAX_REQUEST_BYTES: usize = 512 * 1024;
const AUTH_TTL_SECONDS: i64 = 60;
const MAX_CLAIMS: u16 = 32;
const MAX_RETRY_SECONDS: u16 = 900;
const MAX_RECEIPT_REFS: usize = 128;

/// Stable service errors that never include request content.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Authentication, identity, scope, or capability is not live.
    #[error("orchestration request is not authorized")]
    Unauthorized,
    /// The exact bounded request or schedule is invalid.
    #[error("orchestration request is invalid")]
    Invalid,
    /// No governed orchestration plan exists in the exact tenant/workspace scope.
    #[error("orchestration plan was not found")]
    NotFound,
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

/// Exact activation or pause command. Activation may enable only the already-reviewed
/// automatic policy and recurrence stored with this plan generation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanLifecycleCommand {
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
    /// Exact plan generation.
    pub plan_generation: u64,
    /// Enable the persisted automatic policy; ignored and required false for pause.
    pub automatic_execution_enabled: bool,
    /// Enable the persisted recurrence; ignored and required false for pause.
    pub recurrence_enabled: bool,
    /// Digest of the reviewed activation or pause evidence.
    pub evidence_sha256: String,
}

/// Atomic old-generation revocation and new-generation activation command.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SupersedePlanCommand {
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
    /// Prior plan being revoked.
    pub superseded_plan_id: Uuid,
    /// Exact prior generation.
    pub superseded_plan_generation: u64,
    /// Exact replacement generation.
    pub replacement_plan_generation: u64,
    /// Whether the replacement may use its reviewed automatic policy.
    pub automatic_execution_enabled: bool,
    /// Whether the replacement recurrence becomes live.
    pub recurrence_enabled: bool,
    /// Digest of immutable supersession evidence.
    pub evidence_sha256: String,
}

/// Bounded scheduler cycle for recurrence, reminder, lease, and lost-response recovery.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerCycleRequest {
    /// Contract schema.
    pub schema_version: String,
    /// Replay-protected request identifier.
    pub request_id: Uuid,
    /// Bound scheduler identity.
    pub service_identity_id: Uuid,
    /// Operations-owned principal label.
    pub service_principal: String,
    /// Exact caller policy generation.
    pub policy_generation: u64,
    /// Maximum records processed in each bounded phase.
    pub max_records: u16,
    /// Submitted delivery age after which a stable coordinator request may be retried.
    pub submitted_timeout_seconds: u16,
}

/// Coordinator delivery result for one crash-fenced dispatch lease.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryResultCommand {
    /// Contract schema.
    pub schema_version: String,
    /// Bound scheduler identity.
    pub service_identity_id: Uuid,
    /// Operations-owned principal label.
    pub service_principal: String,
    /// Exact caller policy generation.
    pub policy_generation: u64,
    /// Claimed lease generation.
    pub lease_generation: u64,
    /// Cancellation fence observed before delivery.
    pub cancellation_generation: u64,
    /// Submitted or retryable failure.
    pub outcome: DeliveryOutcome,
    /// Stable coordinator job reference returned by the private coordinator.
    pub coordinator_receipt_reference: Option<String>,
    /// Digest of the coordinator response, never response content.
    pub response_sha256: Option<String>,
    /// Digest of a bounded failure classification when delivery did not complete.
    pub failure_sha256: Option<String>,
    /// Delay before the next retry, bounded by policy.
    pub retry_after_seconds: Option<u16>,
}

/// Delivery result without provider error content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
    /// The exact stable coordinator request was accepted.
    Submitted,
    /// No acceptance was observed and the same stable request may be retried.
    RetryableFailure,
}

/// Occurrence-scoped terminal receipt accepted from the private coordinator boundary.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalReceiptCommand {
    /// Contract schema.
    pub schema_version: String,
    /// Bound receipt-ingestion service identity.
    pub service_identity_id: Uuid,
    /// Operations-owned principal label.
    pub service_principal: String,
    /// Exact caller policy generation.
    pub policy_generation: u64,
    /// Dispatch lease generation that reached the coordinator.
    pub lease_generation: u64,
    /// Exact cancellation generation observed by the executor.
    pub cancellation_generation: u64,
    /// Digest of the immutable execution snapshot.
    pub execution_snapshot_sha256: String,
    /// Terminal bounded outcome.
    pub outcome: TerminalOutcome,
    /// Immutable Analyst handoff coordinate.
    pub handoff_manifest_reference: String,
    /// Digest of the handoff manifest.
    pub handoff_manifest_sha256: String,
    /// Immutable Analyst artifact references.
    pub artifact_references: BTreeSet<String>,
    /// Immutable Analyst evidence references.
    pub evidence_references: BTreeSet<String>,
    /// Coordinator/model/tool receipt coordinates.
    pub execution_receipt_references: BTreeSet<String>,
    /// Accounted cost, bounded by the reservation.
    pub actual_cost_microusd: u64,
    /// Trusted coordinator completion time.
    pub completed_at: DateTime<Utc>,
    /// Digest of the exact terminal receipt bytes.
    pub receipt_sha256: String,
}

/// Stable terminal outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    /// Required artifact and evidence manifests exist.
    Succeeded,
    /// The task needs a newly governed decision or dependency.
    Blocked,
    /// Execution reached a terminal failure.
    Failed,
    /// Execution observed cancellation before completion.
    Cancelled,
}

/// Counts emitted by one bounded scheduler cycle.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerCycleReceipt {
    /// Request identity.
    pub request_id: Uuid,
    /// Due recurrence rows advanced.
    pub recurrences_processed: u32,
    /// New occurrence graphs created.
    pub occurrences_materialized: u32,
    /// Expired or lost-response dispatch leases recovered.
    pub dispatches_recovered: u32,
    /// Dispatches moved to durable dead letter.
    pub dispatches_dead_lettered: u32,
    /// Due reminders appended to the control outbox.
    pub reminders_enqueued: u32,
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
    /// Parent governed request used by the coordinator snapshot.
    pub request_id: Uuid,
    /// Digest of the immutable minimized execution projection.
    pub execution_snapshot_sha256: String,
    /// Exact evaluated model catalog ID selected by the persona policy.
    pub model_id: String,
    /// Exact specialist role selected by the persona policy.
    pub specialist_role: String,
    /// Governed maximum data classification for this task.
    pub classification: Classification,
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
    /// Cancellation fence observed at claim time.
    pub cancellation_generation: u64,
    /// Worst-case reserved task cost for observability only.
    pub reserved_cost_microusd: u64,
    /// Hard task deadline, independent from the short delivery lease.
    pub deadline_at: DateTime<Utc>,
    /// Lease expiry.
    pub lease_expires_at: DateTime<Utc>,
}

/// Bounded command kinds that may leave the durable orchestration control outbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlCommandKind {
    /// Revoke the exact already-submitted coordinator job.
    CancelDispatch,
    /// Deliver one fixed, policy-created deadline reminder.
    DeliverReminder,
}

impl ControlCommandKind {
    /// Stable persisted and observability label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CancelDispatch => "cancel_dispatch",
            Self::DeliverReminder => "deliver_reminder",
        }
    }
}

/// Exact authenticated request for a bounded batch of due control commands.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlClaimRequest {
    /// Contract schema.
    pub schema_version: String,
    /// Replay-protected request identity.
    pub request_id: Uuid,
    /// Exact tenant-bound delivery service identity.
    pub service_identity_id: Uuid,
    /// Operations-owned service principal.
    pub service_principal: String,
    /// Exact caller-policy generation.
    pub policy_generation: u64,
    /// Explicit allowlist for this worker process.
    pub command_kinds: BTreeSet<ControlCommandKind>,
    /// Maximum rows returned by this claim.
    pub max_claims: u16,
    /// Crash lease duration.
    pub lease_seconds: u16,
}

/// One crash-fenced reminder or cancellation command. No destination body,
/// provider coordinate, client content, or credential is included.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlLease {
    /// Stable outbox identity.
    pub outbox_id: Uuid,
    /// Exact tenant.
    pub community_id: Uuid,
    /// Exact workspace.
    pub workspace_id: Uuid,
    /// Allowlisted command kind.
    pub command_kind: ControlCommandKind,
    /// Exact plan.
    pub plan_id: Uuid,
    /// Exact plan generation.
    pub plan_generation: u64,
    /// Dispatch coordinate for cancellations only.
    pub dispatch_id: Option<Uuid>,
    /// Stable occurrence coordinate.
    pub occurrence_id: Uuid,
    /// Digest of the deterministic command fields.
    pub command_sha256: String,
    /// Stable coordinator job reference for cancellation only.
    pub coordinator_job_reference: Option<String>,
    /// Monotonic claim fence.
    pub lease_generation: u64,
    /// Stable outbox creation time used to create replay-stable reminder events.
    pub command_created_at: DateTime<Utc>,
    /// Lease expiry.
    pub lease_expires_at: DateTime<Utc>,
}

/// Bounded control-delivery outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlDeliveryOutcome {
    /// The destination durably accepted the exact command.
    Delivered,
    /// No acceptance was observed; the same command may be retried.
    RetryableFailure,
}

/// Exact digest-only result for one control-outbox lease.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDeliveryResultCommand {
    /// Contract schema.
    pub schema_version: String,
    /// Exact delivery service identity.
    pub service_identity_id: Uuid,
    /// Operations-owned service principal.
    pub service_principal: String,
    /// Exact caller-policy generation.
    pub policy_generation: u64,
    /// Claimed lease generation.
    pub lease_generation: u64,
    /// Digest returned in the claim.
    pub command_sha256: String,
    /// Bounded result.
    pub outcome: ControlDeliveryOutcome,
    /// Immutable Snowman acceptance coordinate on success.
    pub delivery_reference: Option<String>,
    /// Digest of the bounded destination response on success.
    pub response_sha256: Option<String>,
    /// Digest of a bounded failure classification on failure.
    pub failure_sha256: Option<String>,
    /// Retry delay on retryable failure.
    pub retry_after_seconds: Option<u16>,
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
    database_role: String,
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
        let database_role = required("SNOWMAN_ORCHESTRATION_DATABASE_ROLE")?;
        buzz_db::runtime_security::validate_role_name(&database_role)
            .map_err(|_| ConfigError::Invalid("database role"))?;
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
            database_role,
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
        buzz_db::runtime_security::verify_orchestration_role(&pool, &config.database_role)
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
            get(get_team_operations).post(post_plan),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans/{plan_id}/cancel",
            post(cancel_plan),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans/{plan_id}/activate",
            post(activate_plan),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans/{plan_id}/pause",
            post(pause_plan),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans/{plan_id}/supersede",
            post(supersede_plan),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/scheduler/claims",
            post(claim_dispatches),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/scheduler/cycle",
            post(run_scheduler_cycle),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/scheduler/control-claims",
            post(claim_control_commands),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/control/{outbox_id}/delivery",
            post(record_control_delivery),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/dispatches/{dispatch_id}/delivery",
            post(record_delivery_result),
        )
        .route(
            "/v1/tenants/{tenant_id}/workspaces/{workspace_id}/dispatches/{dispatch_id}/terminal-receipt",
            post(ingest_terminal_receipt),
        )
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .with_state(state)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamOperationsProjection {
    schema_version: &'static str,
    generated_at: DateTime<Utc>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    authority: TeamOperationsAuthority,
    plan: TeamOperationsPlan,
    schedule: Option<TeamOperationsSchedule>,
    personas: Vec<TeamOperationsPersona>,
    tasks: Vec<TeamOperationsTask>,
    receipts: Vec<TeamOperationsReceipt>,
    reminders: Vec<TeamOperationsReminder>,
    commands: Vec<TeamOperationsCommandReceipt>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamOperationsAuthority {
    identity_id: Uuid,
    principal: String,
    policy_generation: u64,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamOperationsPlan {
    plan_id: Uuid,
    request_id: Uuid,
    work_kind: String,
    generation: u64,
    supersedes_plan_id: Option<Uuid>,
    state: String,
    classification: String,
    max_cost_microusd: u64,
    automatic_execution_enabled: bool,
    deadline_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamOperationsSchedule {
    timezone: String,
    quiet_start_local_minute: u16,
    quiet_end_local_minute: u16,
    allow_deadline_reminders: bool,
    reminder_offsets_seconds: Vec<i32>,
    recurrence_enabled: bool,
    recurrence_local_minute: Option<u16>,
    recurrence_weekdays: Vec<i16>,
    next_fire_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamOperationsPersona {
    persona_id: Uuid,
    specialist_role: String,
    model_id: String,
    model_route_reference: String,
    max_cost_microusd: u64,
    enabled: bool,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamOperationsTask {
    task_id: Uuid,
    persona_id: Uuid,
    depends_on: Vec<Uuid>,
    status: String,
    approval_required: bool,
    required_capabilities: Vec<String>,
    artifact_types: Vec<String>,
    max_cost_microusd: u64,
    deadline_at: DateTime<Utc>,
    dispatch_status: Option<String>,
    reserved_cost_microusd: u64,
    accounted_cost_microusd: u64,
    execution_snapshot_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamOperationsReceipt {
    task_id: Uuid,
    outcome: String,
    handoff_manifest_reference: String,
    receipt_sha256: String,
    artifact_references: Vec<String>,
    evidence_references: Vec<String>,
    actual_cost_microusd: u64,
    completed_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamOperationsReminder {
    occurrence_id: Uuid,
    due_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
    status: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamOperationsCommandReceipt {
    command_id: Uuid,
    command_kind: String,
    plan_generation: u64,
    command_sha256: String,
    status: String,
    applied_at: DateTime<Utc>,
}

async fn get_team_operations(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<TeamOperationsProjection>, ApiError> {
    let url = endpoint_url(
        &state.private_origin,
        &format!("v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans"),
    )?;
    let auth = verify_read_auth(&headers, url.as_str())?;
    let projection = read_team_operations(
        &state.pool,
        tenant_id,
        workspace_id,
        &auth,
        url.as_str(),
        Utc::now(),
    )
    .await?;
    Ok(Json(projection))
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

async fn activate_plan(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id, plan_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApiReceipt>, ApiError> {
    lifecycle_plan_handler(
        &state,
        PlanScope {
            tenant_id,
            workspace_id,
            plan_id,
        },
        headers,
        body,
        LifecycleAction::Activate,
    )
    .await
}

async fn pause_plan(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id, plan_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApiReceipt>, ApiError> {
    lifecycle_plan_handler(
        &state,
        PlanScope {
            tenant_id,
            workspace_id,
            plan_id,
        },
        headers,
        body,
        LifecycleAction::Pause,
    )
    .await
}

async fn lifecycle_plan_handler(
    state: &AppState,
    scope: PlanScope,
    headers: HeaderMap,
    body: Bytes,
    action: LifecycleAction,
) -> Result<Json<ApiReceipt>, ApiError> {
    check_body(&body)?;
    let action_name = action.as_str();
    let url = endpoint_url(
        &state.private_origin,
        &format!(
            "v1/tenants/{}/workspaces/{}/plans/{}/{action_name}",
            scope.tenant_id, scope.workspace_id, scope.plan_id
        ),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let command: PlanLifecycleCommand =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    validate_lifecycle(&command, action)?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let result = persist_lifecycle(
        &state.pool,
        scope,
        &command,
        action,
        &auth,
        digest,
        Utc::now(),
    )
    .await?;
    Ok(Json(result))
}

async fn supersede_plan(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id, replacement_plan_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApiReceipt>, ApiError> {
    check_body(&body)?;
    let url = endpoint_url(
        &state.private_origin,
        &format!(
            "v1/tenants/{tenant_id}/workspaces/{workspace_id}/plans/{replacement_plan_id}/supersede"
        ),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let command: SupersedePlanCommand =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    validate_supersession(&command, replacement_plan_id)?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let result = persist_supersession(
        &state.pool,
        PlanScope {
            tenant_id,
            workspace_id,
            plan_id: replacement_plan_id,
        },
        &command,
        &auth,
        digest,
        Utc::now(),
    )
    .await?;
    Ok(Json(result))
}

async fn run_scheduler_cycle(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SchedulerCycleReceipt>, ApiError> {
    check_body(&body)?;
    let url = endpoint_url(
        &state.private_origin,
        &format!("v1/tenants/{tenant_id}/workspaces/{workspace_id}/scheduler/cycle"),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let request: SchedulerCycleRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    validate_scheduler_cycle(&request)?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let result = scheduler_cycle(
        &state.pool,
        tenant_id,
        workspace_id,
        &request,
        &auth,
        digest,
        Utc::now(),
    )
    .await?;
    Ok(Json(result))
}

async fn claim_control_commands(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Vec<ControlLease>>, ApiError> {
    check_body(&body)?;
    let url = endpoint_url(
        &state.private_origin,
        &format!("v1/tenants/{tenant_id}/workspaces/{workspace_id}/scheduler/control-claims"),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let request: ControlClaimRequest =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    validate_control_claim(&request)?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let leases = claim_control_outbox(
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

async fn record_control_delivery(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id, outbox_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApiReceipt>, ApiError> {
    check_body(&body)?;
    let url = endpoint_url(
        &state.private_origin,
        &format!("v1/tenants/{tenant_id}/workspaces/{workspace_id}/control/{outbox_id}/delivery"),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let command: ControlDeliveryResultCommand =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    validate_control_delivery(&command)?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let result = persist_control_delivery(
        &state.pool,
        tenant_id,
        workspace_id,
        outbox_id,
        &command,
        &auth,
        digest,
        Utc::now(),
    )
    .await?;
    Ok(Json(result))
}

async fn record_delivery_result(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id, dispatch_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApiReceipt>, ApiError> {
    check_body(&body)?;
    let url = endpoint_url(
        &state.private_origin,
        &format!(
            "v1/tenants/{tenant_id}/workspaces/{workspace_id}/dispatches/{dispatch_id}/delivery"
        ),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let command: DeliveryResultCommand =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    validate_delivery_result(&command)?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let result = persist_delivery_result(
        &state.pool,
        tenant_id,
        workspace_id,
        dispatch_id,
        &command,
        &auth,
        digest,
        Utc::now(),
    )
    .await?;
    Ok(Json(result))
}

async fn ingest_terminal_receipt(
    State(state): State<AppState>,
    Path((tenant_id, workspace_id, dispatch_id)): Path<(Uuid, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApiReceipt>, ApiError> {
    check_body(&body)?;
    let url = endpoint_url(
        &state.private_origin,
        &format!(
            "v1/tenants/{tenant_id}/workspaces/{workspace_id}/dispatches/{dispatch_id}/terminal-receipt"
        ),
    )?;
    let auth = verify_auth(&headers, url.as_str(), &body)?;
    let command: TerminalReceiptCommand =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    validate_terminal_receipt(&command, Utc::now())?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let result = persist_terminal_receipt(
        &state.pool,
        tenant_id,
        workspace_id,
        dispatch_id,
        &command,
        &auth,
        digest,
        Utc::now(),
    )
    .await?;
    Ok(Json(result))
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum LifecycleAction {
    Activate,
    Pause,
}

impl LifecycleAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Activate => "activate",
            Self::Pause => "pause",
        }
    }

    fn command_kind(self) -> &'static str {
        match self {
            Self::Activate => "activate_plan",
            Self::Pause => "pause_plan",
        }
    }
}

fn validate_lifecycle(
    command: &PlanLifecycleCommand,
    action: LifecycleAction,
) -> Result<(), ApiError> {
    if command.schema_version != LIFECYCLE_SCHEMA
        || command.command_id.is_nil()
        || command.service_identity_id.is_nil()
        || command.policy_generation == 0
        || command.plan_generation == 0
        || !valid_hex_digest(&command.evidence_sha256)
        || (action == LifecycleAction::Pause
            && (command.automatic_execution_enabled || command.recurrence_enabled))
        || (command.recurrence_enabled && !command.automatic_execution_enabled)
    {
        return Err(ApiError(Error::Invalid));
    }
    Ok(())
}

fn validate_supersession(
    command: &SupersedePlanCommand,
    replacement_plan_id: Uuid,
) -> Result<(), ApiError> {
    if command.schema_version != LIFECYCLE_SCHEMA
        || command.command_id.is_nil()
        || command.service_identity_id.is_nil()
        || command.policy_generation == 0
        || command.superseded_plan_id.is_nil()
        || command.superseded_plan_id == replacement_plan_id
        || command.superseded_plan_generation == 0
        || command.replacement_plan_generation
            != command.superseded_plan_generation.saturating_add(1)
        || !valid_hex_digest(&command.evidence_sha256)
        || (command.recurrence_enabled && !command.automatic_execution_enabled)
    {
        return Err(ApiError(Error::Invalid));
    }
    Ok(())
}

fn validate_scheduler_cycle(request: &SchedulerCycleRequest) -> Result<(), ApiError> {
    if request.schema_version != LIFECYCLE_SCHEMA
        || request.request_id.is_nil()
        || request.service_identity_id.is_nil()
        || request.policy_generation == 0
        || !(1..=MAX_CLAIMS).contains(&request.max_records)
        || !(60..=3_600).contains(&request.submitted_timeout_seconds)
    {
        return Err(ApiError(Error::Invalid));
    }
    Ok(())
}

fn validate_control_claim(request: &ControlClaimRequest) -> Result<(), ApiError> {
    if request.schema_version != CONTROL_CLAIM_SCHEMA
        || request.request_id.is_nil()
        || request.service_identity_id.is_nil()
        || request.policy_generation == 0
        || request.command_kinds.is_empty()
        || request.command_kinds.len() > 2
        || !(1..=MAX_CLAIMS).contains(&request.max_claims)
        || !(30..=900).contains(&request.lease_seconds)
    {
        return Err(ApiError(Error::Invalid));
    }
    Ok(())
}

fn validate_control_delivery(command: &ControlDeliveryResultCommand) -> Result<(), ApiError> {
    let delivered = command.outcome == ControlDeliveryOutcome::Delivered;
    if command.schema_version != CONTROL_DELIVERY_SCHEMA
        || command.service_identity_id.is_nil()
        || command.policy_generation == 0
        || command.lease_generation == 0
        || !valid_hex_digest(&command.command_sha256)
        || delivered
            != (command
                .delivery_reference
                .as_deref()
                .is_some_and(valid_control_delivery_reference)
                && command
                    .response_sha256
                    .as_deref()
                    .is_some_and(valid_hex_digest))
        || delivered != command.failure_sha256.is_none()
        || delivered == command.retry_after_seconds.is_some()
        || (!delivered
            && command
                .failure_sha256
                .as_deref()
                .is_none_or(|value| !valid_hex_digest(value)))
        || command
            .retry_after_seconds
            .is_some_and(|seconds| !(1..=MAX_RETRY_SECONDS).contains(&seconds))
    {
        return Err(ApiError(Error::Invalid));
    }
    Ok(())
}

fn validate_delivery_result(command: &DeliveryResultCommand) -> Result<(), ApiError> {
    let submitted = command.outcome == DeliveryOutcome::Submitted;
    if command.schema_version != DELIVERY_SCHEMA
        || command.service_identity_id.is_nil()
        || command.policy_generation == 0
        || command.lease_generation == 0
        || command.coordinator_receipt_reference.is_some() != submitted
        || command.response_sha256.is_some() != submitted
        || command.failure_sha256.is_some() == submitted
        || command.retry_after_seconds.is_some() == submitted
        || command
            .response_sha256
            .as_deref()
            .is_some_and(|value| !valid_hex_digest(value))
        || command
            .failure_sha256
            .as_deref()
            .is_some_and(|value| !valid_hex_digest(value))
        || command
            .retry_after_seconds
            .is_some_and(|value| !(1..=MAX_RETRY_SECONDS).contains(&value))
        || command
            .coordinator_receipt_reference
            .as_deref()
            .is_some_and(|value| !valid_execution_ref(value, "snowman:agent-job:"))
    {
        return Err(ApiError(Error::Invalid));
    }
    Ok(())
}

fn validate_terminal_receipt(
    command: &TerminalReceiptCommand,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let succeeded = command.outcome == TerminalOutcome::Succeeded;
    if command.schema_version != TERMINAL_RECEIPT_SCHEMA
        || command.service_identity_id.is_nil()
        || command.policy_generation == 0
        || command.lease_generation == 0
        || !valid_hex_digest(&command.execution_snapshot_sha256)
        || !valid_hex_digest(&command.handoff_manifest_sha256)
        || !valid_hex_digest(&command.receipt_sha256)
        || !valid_analyst_reference(&command.handoff_manifest_reference)
        || command.artifact_references.len() > MAX_RECEIPT_REFS
        || command.evidence_references.len() > MAX_RECEIPT_REFS
        || command.execution_receipt_references.is_empty()
        || command.execution_receipt_references.len() > MAX_RECEIPT_REFS
        || command
            .artifact_references
            .iter()
            .chain(command.evidence_references.iter())
            .any(|value| !valid_analyst_reference(value))
        || command
            .execution_receipt_references
            .iter()
            .any(|value| !valid_any_execution_ref(value))
        || (succeeded
            && (command.artifact_references.is_empty() || command.evidence_references.is_empty()))
        || command.completed_at > now + ChronoDuration::minutes(5)
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
        for capability in &task.required_capabilities {
            sqlx::query(
                "INSERT INTO snowman_orchestration_task_required_capabilities \
                 (community_id,plan_id,plan_generation,task_id,capability) \
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(plan.community_id)
            .bind(plan.plan_id)
            .bind(plan.generation as i64)
            .bind(task.task_id)
            .bind(capability)
            .execute(&mut *tx)
            .await
            .map_err(db_conflict)?;
        }
        for artifact_type in &task.expected_artifact_types {
            sqlx::query(
                "INSERT INTO snowman_orchestration_task_artifact_contracts \
                 (community_id,plan_id,plan_generation,task_id,artifact_type) \
                 VALUES ($1,$2,$3,$4,$5)",
            )
            .bind(plan.community_id)
            .bind(plan.plan_id)
            .bind(plan.generation as i64)
            .bind(task.task_id)
            .bind(artifact_type)
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
    let submitted = sqlx::query(
        "SELECT dispatch_id,occurrence_id FROM snowman_orchestration_dispatches \
         WHERE community_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_generation=$4 \
           AND status='submitted' FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(plan_id)
    .bind(command.plan_generation as i64)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    for row in submitted {
        insert_control_outbox(
            &mut tx,
            PlanScope {
                tenant_id,
                workspace_id,
                plan_id,
            },
            command.plan_generation,
            row.try_get("occurrence_id")
                .map_err(|_| ApiError(Error::Database))?,
            Some(
                row.try_get("dispatch_id")
                    .map_err(|_| ApiError(Error::Database))?,
            ),
            "cancel_dispatch",
            now,
        )
        .await?;
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
         lease_owner_identity_id=NULL,lease_expires_at=NULL,\
         terminal_at=CASE WHEN status='submitted' THEN $1 ELSE terminal_at END,\
         terminal_outcome=CASE WHEN status='submitted' THEN 'cancelled' ELSE terminal_outcome END,updated_at=$1 \
         WHERE community_id=$2 AND plan_id=$3 AND plan_generation=$4 \
           AND status IN ('pending','leased','failed','submitted')",
    )
    .bind(now)
    .bind(tenant_id)
    .bind(plan_id)
    .bind(command.plan_generation as i64)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "UPDATE snowman_orchestration_occurrences SET status='cancelled',updated_at=$1 \
         WHERE community_id=$2 AND workspace_id=$3 AND plan_id=$4 AND plan_generation=$5 \
           AND status='materialized'",
    )
    .bind(now)
    .bind(tenant_id)
    .bind(workspace_id)
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

async fn persist_lifecycle(
    pool: &PgPool,
    scope: PlanScope,
    command: &PlanLifecycleCommand,
    action: LifecycleAction,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ApiReceipt, ApiError> {
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id: scope.tenant_id,
            workspace_id: scope.workspace_id,
            identity_id: command.service_identity_id,
            principal: &command.service_principal,
            policy_generation: command.policy_generation,
            capability: match action {
                LifecycleAction::Activate => "orchestration.plans.activate",
                LifecycleAction::Pause => "orchestration.plans.pause",
            },
        },
        auth,
        digest,
        now,
    )
    .await?;
    if let Some(receipt) = duplicate_receipt(
        &mut tx,
        scope.tenant_id,
        scope.workspace_id,
        command.command_id,
        digest,
        now,
    )
    .await?
    {
        tx.commit().await.map_err(|_| ApiError(Error::Database))?;
        return Ok(receipt);
    }
    match action {
        LifecycleAction::Activate => {
            activate_locked_plan(
                &mut tx,
                scope,
                command.plan_generation,
                command.command_id,
                command.automatic_execution_enabled,
                command.recurrence_enabled,
                now,
            )
            .await?;
        }
        LifecycleAction::Pause => {
            lock_plan_state(&mut tx, scope, command.plan_generation, &["active"]).await?;
            revoke_plan_authority(&mut tx, scope, command.plan_generation, "paused", now).await?;
        }
    }
    insert_command(
        &mut tx,
        scope.tenant_id,
        scope.workspace_id,
        command.command_id,
        action.command_kind(),
        scope.plan_id,
        command.plan_generation,
        digest,
        command.service_identity_id,
        now,
    )
    .await?;
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(scoped_receipt(
        command.command_id,
        scope,
        command.plan_generation,
        "applied",
        digest,
        now,
    ))
}

async fn persist_supersession(
    pool: &PgPool,
    replacement_scope: PlanScope,
    command: &SupersedePlanCommand,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ApiReceipt, ApiError> {
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id: replacement_scope.tenant_id,
            workspace_id: replacement_scope.workspace_id,
            identity_id: command.service_identity_id,
            principal: &command.service_principal,
            policy_generation: command.policy_generation,
            capability: "orchestration.plans.supersede",
        },
        auth,
        digest,
        now,
    )
    .await?;
    if let Some(receipt) = duplicate_receipt(
        &mut tx,
        replacement_scope.tenant_id,
        replacement_scope.workspace_id,
        command.command_id,
        digest,
        now,
    )
    .await?
    {
        tx.commit().await.map_err(|_| ApiError(Error::Database))?;
        return Ok(receipt);
    }
    let prior_scope = PlanScope {
        plan_id: command.superseded_plan_id,
        ..replacement_scope
    };
    let replacement = sqlx::query(
        "SELECT n.state,n.request_id,n.supersedes_plan_id,o.request_id AS old_request_id,o.state AS old_state \
         FROM snowman_orchestration_plans n \
         JOIN snowman_orchestration_plans o ON o.community_id=n.community_id \
           AND o.plan_id=$4 AND o.generation=$5 \
         WHERE n.community_id=$1 AND n.workspace_id=$2 AND n.plan_id=$3 AND n.generation=$6 \
         FOR UPDATE OF n,o",
    )
    .bind(replacement_scope.tenant_id)
    .bind(replacement_scope.workspace_id)
    .bind(replacement_scope.plan_id)
    .bind(command.superseded_plan_id)
    .bind(command.superseded_plan_generation as i64)
    .bind(command.replacement_plan_generation as i64)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    .ok_or(ApiError(Error::Conflict))?;
    let new_state: String = replacement
        .try_get("state")
        .map_err(|_| ApiError(Error::Database))?;
    let new_request: Uuid = replacement
        .try_get("request_id")
        .map_err(|_| ApiError(Error::Database))?;
    let old_request: Uuid = replacement
        .try_get("old_request_id")
        .map_err(|_| ApiError(Error::Database))?;
    let supersedes: Option<Uuid> = replacement
        .try_get("supersedes_plan_id")
        .map_err(|_| ApiError(Error::Database))?;
    let old_state: String = replacement
        .try_get("old_state")
        .map_err(|_| ApiError(Error::Database))?;
    if new_state != "draft"
        || new_request != old_request
        || supersedes != Some(prior_scope.plan_id)
        || !matches!(old_state.as_str(), "draft" | "active" | "paused")
    {
        return Err(ApiError(Error::Conflict));
    }
    revoke_plan_authority(
        &mut tx,
        prior_scope,
        command.superseded_plan_generation,
        "superseded",
        now,
    )
    .await?;
    sqlx::query(
        "UPDATE snowman_orchestration_plans SET superseded_by_plan_id=$1,updated_at=$2 \
         WHERE community_id=$3 AND plan_id=$4 AND generation=$5",
    )
    .bind(replacement_scope.plan_id)
    .bind(now)
    .bind(replacement_scope.tenant_id)
    .bind(prior_scope.plan_id)
    .bind(command.superseded_plan_generation as i64)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    activate_locked_plan(
        &mut tx,
        replacement_scope,
        command.replacement_plan_generation,
        command.command_id,
        command.automatic_execution_enabled,
        command.recurrence_enabled,
        now,
    )
    .await?;
    insert_command(
        &mut tx,
        replacement_scope.tenant_id,
        replacement_scope.workspace_id,
        command.command_id,
        "supersede_plan",
        replacement_scope.plan_id,
        command.replacement_plan_generation,
        digest,
        command.service_identity_id,
        now,
    )
    .await?;
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(scoped_receipt(
        command.command_id,
        replacement_scope,
        command.replacement_plan_generation,
        "applied",
        digest,
        now,
    ))
}

async fn lock_plan_state(
    tx: &mut Transaction<'_, Postgres>,
    scope: PlanScope,
    generation: u64,
    allowed: &[&str],
) -> Result<(), ApiError> {
    let state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM snowman_orchestration_plans \
         WHERE community_id=$1 AND workspace_id=$2 AND plan_id=$3 AND generation=$4 FOR UPDATE",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    if !state
        .as_deref()
        .is_some_and(|value| allowed.contains(&value))
    {
        return Err(ApiError(Error::Conflict));
    }
    Ok(())
}

async fn activate_locked_plan(
    tx: &mut Transaction<'_, Postgres>,
    scope: PlanScope,
    generation: u64,
    occurrence_id: Uuid,
    automatic_execution_enabled: bool,
    recurrence_enabled: bool,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    lock_plan_state(tx, scope, generation, &["draft", "paused"]).await?;
    if recurrence_enabled {
        let recurrence_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM snowman_orchestration_recurrences \
             WHERE community_id=$1 AND workspace_id=$2 AND plan_id=$3 \
               AND schedule_generation=$4)",
        )
        .bind(scope.tenant_id)
        .bind(scope.workspace_id)
        .bind(scope.plan_id)
        .bind(generation as i64)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
        if !recurrence_exists {
            return Err(ApiError(Error::Conflict));
        }
    }
    sqlx::query(
        "UPDATE snowman_orchestration_plans SET state='active',automatic_execution_enabled=$1,\
         activated_at=COALESCE(activated_at,$2),cancelled_at=NULL,updated_at=$2 \
         WHERE community_id=$3 AND workspace_id=$4 AND plan_id=$5 AND generation=$6",
    )
    .bind(automatic_execution_enabled)
    .bind(now)
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "UPDATE snowman_orchestration_recurrences SET enabled=$1,updated_at=$2 \
         WHERE community_id=$3 AND workspace_id=$4 AND plan_id=$5 AND schedule_generation=$6",
    )
    .bind(recurrence_enabled)
    .bind(now)
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    if !recurrence_enabled {
        create_occurrence(
            tx,
            scope,
            generation,
            occurrence_id,
            None,
            now,
            false,
            "materialized",
        )
        .await?;
        if automatic_execution_enabled {
            materialize_ready_dispatches(tx, scope, generation, occurrence_id, now).await?;
        }
        create_deadline_reminders(tx, scope, generation, occurrence_id, now).await?;
    }
    Ok(())
}

async fn revoke_plan_authority(
    tx: &mut Transaction<'_, Postgres>,
    scope: PlanScope,
    generation: u64,
    target_state: &str,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if !matches!(target_state, "paused" | "superseded") {
        return Err(ApiError(Error::Invalid));
    }
    let submitted = sqlx::query(
        "SELECT dispatch_id,occurrence_id FROM snowman_orchestration_dispatches \
         WHERE community_id=$1 AND workspace_id=$2 AND plan_id=$3 AND plan_generation=$4 \
           AND status='submitted' FOR UPDATE",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    for row in submitted {
        let dispatch_id: Uuid = row
            .try_get("dispatch_id")
            .map_err(|_| ApiError(Error::Database))?;
        let occurrence_id: Uuid = row
            .try_get("occurrence_id")
            .map_err(|_| ApiError(Error::Database))?;
        insert_control_outbox(
            tx,
            scope,
            generation,
            occurrence_id,
            Some(dispatch_id),
            "cancel_dispatch",
            now,
        )
        .await?;
    }
    sqlx::query(
        "UPDATE snowman_orchestration_plans SET state=$1,automatic_execution_enabled=FALSE,updated_at=$2 \
         WHERE community_id=$3 AND workspace_id=$4 AND plan_id=$5 AND generation=$6",
    )
    .bind(target_state)
    .bind(now)
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "UPDATE snowman_orchestration_recurrences SET enabled=FALSE,next_fire_at=NULL,updated_at=$1 \
         WHERE community_id=$2 AND workspace_id=$3 AND plan_id=$4",
    )
    .bind(now)
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "UPDATE snowman_orchestration_dispatches SET status='cancelled',\
         cancellation_generation=cancellation_generation+1,lease_owner_identity_id=NULL,\
         lease_expires_at=NULL,terminal_at=CASE WHEN status='submitted' THEN $1 ELSE terminal_at END,\
         terminal_outcome=CASE WHEN status='submitted' THEN 'cancelled' ELSE terminal_outcome END,updated_at=$1 \
         WHERE community_id=$2 AND workspace_id=$3 AND plan_id=$4 AND plan_generation=$5 \
           AND status IN ('pending','leased','failed','submitted')",
    )
    .bind(now)
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "UPDATE snowman_orchestration_occurrences SET status='cancelled',updated_at=$1 \
         WHERE community_id=$2 AND workspace_id=$3 AND plan_id=$4 AND plan_generation=$5 \
           AND status='materialized'",
    )
    .bind(now)
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "UPDATE snowman_orchestration_reminder_receipts SET status='cancelled' \
         WHERE community_id=$1 AND plan_id=$2 AND plan_generation=$3 AND status='pending'",
    )
    .bind(scope.tenant_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn create_occurrence(
    tx: &mut Transaction<'_, Postgres>,
    scope: PlanScope,
    generation: u64,
    occurrence_id: Uuid,
    schedule_generation: Option<u64>,
    scheduled_at: DateTime<Utc>,
    catch_up: bool,
    status: &str,
) -> Result<bool, ApiError> {
    let inserted = sqlx::query(
        "INSERT INTO snowman_orchestration_occurrences \
         (community_id,workspace_id,plan_id,plan_generation,occurrence_id,schedule_generation,\
          scheduled_at,catch_up,status,created_at,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10) ON CONFLICT DO NOTHING",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .bind(occurrence_id)
    .bind(schedule_generation.map(|value| value as i64))
    .bind(scheduled_at)
    .bind(catch_up)
    .bind(status)
    .bind(Utc::now())
    .execute(&mut **tx)
    .await
    .map_err(db_conflict)?;
    Ok(inserted.rows_affected() == 1)
}

async fn materialize_ready_dispatches(
    tx: &mut Transaction<'_, Postgres>,
    scope: PlanScope,
    generation: u64,
    occurrence_id: Uuid,
    now: DateTime<Utc>,
) -> Result<u32, ApiError> {
    let candidates = sqlx::query(
        "SELECT t.task_id,t.max_cost_microusd,pe.model_route_reference,wl.generation workforce_generation,\
          ARRAY(SELECT c.context_manifest_reference FROM snowman_orchestration_task_context_refs c \
                WHERE c.community_id=t.community_id AND c.plan_id=t.plan_id AND c.task_id=t.task_id \
                ORDER BY c.context_manifest_reference) AS context_refs,\
          ARRAY(SELECT c.capability FROM snowman_orchestration_task_required_capabilities c \
                WHERE c.community_id=t.community_id AND c.plan_id=t.plan_id \
                  AND c.plan_generation=t.plan_generation AND c.task_id=t.task_id ORDER BY c.capability) AS capabilities \
         FROM snowman_orchestration_tasks t \
         JOIN snowman_orchestration_plans p ON p.community_id=t.community_id AND p.plan_id=t.plan_id \
           AND p.generation=t.plan_generation \
         JOIN snowman_orchestration_personas pe ON pe.community_id=t.community_id \
           AND pe.plan_id=t.plan_id AND pe.persona_id=t.persona_id \
         JOIN snowman_work_tasks wt ON wt.community_id=t.community_id AND wt.task_id=t.task_id \
           AND wt.request_id=p.request_id AND wt.model_id=pe.model_id AND wt.specialist_role=pe.specialist_role \
         JOIN snowman_task_leases wl ON wl.community_id=wt.community_id AND wl.task_id=wt.task_id \
           AND wl.worker_identity_id=wt.service_identity_id \
         WHERE t.community_id=$1 AND p.workspace_id=$2 AND t.plan_id=$3 AND t.plan_generation=$4 \
           AND p.state='active' AND p.automatic_execution_enabled AND pe.enabled \
           AND t.automatic_execution_candidate AND t.reversible AND NOT t.approval_required \
           AND t.confidence_basis_points>=p.minimum_confidence_basis_points \
           AND t.value_basis_points>=p.minimum_value_basis_points \
           AND t.risk_basis_points<=p.maximum_risk_basis_points \
           AND t.max_cost_microusd<=p.max_automatic_task_cost_microusd \
           AND t.deadline_at>$5 AND p.deadline_at>$5 AND wl.expires_at>t.deadline_at \
           AND wt.status IN ('leased','running') \
           AND NOT EXISTS (SELECT 1 FROM snowman_orchestration_task_required_capabilities rc \
             WHERE rc.community_id=t.community_id AND rc.plan_id=t.plan_id \
               AND rc.plan_generation=t.plan_generation AND rc.task_id=t.task_id \
               AND NOT EXISTS (SELECT 1 FROM snowman_orchestration_plan_automatic_capabilities ac \
                 WHERE ac.community_id=rc.community_id AND ac.plan_id=rc.plan_id AND ac.capability=rc.capability)) \
           AND NOT EXISTS (SELECT 1 FROM snowman_orchestration_task_dependencies dep \
             WHERE dep.community_id=t.community_id AND dep.plan_id=t.plan_id \
               AND dep.plan_generation=t.plan_generation AND dep.task_id=t.task_id \
               AND NOT EXISTS (SELECT 1 FROM snowman_orchestration_terminal_receipts r \
                 WHERE r.community_id=dep.community_id AND r.occurrence_id=$6 \
                   AND r.task_id=dep.depends_on_task_id AND r.outcome='succeeded')) \
           AND NOT EXISTS (SELECT 1 FROM snowman_orchestration_dispatches d \
             WHERE d.community_id=t.community_id AND d.plan_id=t.plan_id \
               AND d.plan_generation=t.plan_generation AND d.task_id=t.task_id AND d.occurrence_id=$6) \
         ORDER BY t.task_id FOR UPDATE OF t",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .bind(now)
    .bind(occurrence_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let max_cost: i64 = sqlx::query_scalar(
        "SELECT max_cost_microusd FROM snowman_orchestration_plans \
         WHERE community_id=$1 AND workspace_id=$2 AND plan_id=$3 AND generation=$4 FOR UPDATE",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let mut committed: i64 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT SUM(actual_cost_microusd) FROM snowman_orchestration_terminal_receipts \
          WHERE community_id=$1 AND plan_id=$2 AND plan_generation=$3),0) + \
          COALESCE((SELECT SUM(reserved_cost_microusd) FROM snowman_orchestration_dispatches \
          WHERE community_id=$1 AND plan_id=$2 AND plan_generation=$3 \
            AND status IN ('pending','leased','submitted','failed')),0)",
    )
    .bind(scope.tenant_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let mut inserted_count = 0_u32;
    for row in candidates {
        let task_id: Uuid = row
            .try_get("task_id")
            .map_err(|_| ApiError(Error::Database))?;
        let reserved_cost: i64 = row
            .try_get("max_cost_microusd")
            .map_err(|_| ApiError(Error::Database))?;
        if !reservation_fits(committed, max_cost, reserved_cost) {
            continue;
        }
        let model_route_reference: String = row
            .try_get("model_route_reference")
            .map_err(|_| ApiError(Error::Database))?;
        let context_refs: Vec<String> = row
            .try_get("context_refs")
            .map_err(|_| ApiError(Error::Database))?;
        let capabilities: Vec<String> = row
            .try_get("capabilities")
            .map_err(|_| ApiError(Error::Database))?;
        if context_refs.is_empty() || capabilities.is_empty() {
            continue;
        }
        let dispatch_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        let workforce_generation: i64 = row
            .try_get("workforce_generation")
            .map_err(|_| ApiError(Error::Database))?;
        if workforce_generation <= 0 || workforce_generation > i64::from(u32::MAX) {
            return Err(ApiError(Error::Conflict));
        }
        let snapshot = dispatch_snapshot_digest(
            scope,
            generation,
            occurrence_id,
            task_id,
            &model_route_reference,
            &context_refs,
            &capabilities,
            reserved_cost,
        );
        let inserted = sqlx::query(
            "INSERT INTO snowman_orchestration_dispatches \
             (community_id,workspace_id,dispatch_id,plan_id,plan_generation,task_id,occurrence_id,\
              lease_generation,execution_snapshot_sha256,coordinator_job_reference,model_route_reference,\
              analyst_context_references,required_capabilities,reserved_cost_microusd,status,next_attempt_at,created_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12,$13,'pending',$14,$14,$14) \
             ON CONFLICT DO NOTHING",
        )
        .bind(scope.tenant_id)
        .bind(scope.workspace_id)
        .bind(dispatch_id)
        .bind(scope.plan_id)
        .bind(generation as i64)
        .bind(task_id)
        .bind(occurrence_id)
        .bind(snapshot.as_slice())
        .bind(format!(
            "snowman:agent-job:{job_id}:generation:{workforce_generation}"
        ))
        .bind(model_route_reference)
        .bind(context_refs)
        .bind(capabilities)
        .bind(reserved_cost)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(db_conflict)?;
        if inserted.rows_affected() == 1 {
            committed = committed.saturating_add(reserved_cost);
            inserted_count = inserted_count.saturating_add(1);
        }
    }
    Ok(inserted_count)
}

async fn create_deadline_reminders(
    tx: &mut Transaction<'_, Postgres>,
    scope: PlanScope,
    generation: u64,
    occurrence_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO snowman_orchestration_reminder_receipts \
         (community_id,plan_id,plan_generation,reminder_offset_seconds,occurrence_id,due_at,status) \
         SELECT p.community_id,p.plan_id,p.generation,o,$5,p.deadline_at-make_interval(secs=>o),'pending' \
         FROM snowman_orchestration_plans p \
         JOIN snowman_orchestration_schedule_policies s ON s.community_id=p.community_id AND s.plan_id=p.plan_id \
         CROSS JOIN unnest(s.reminder_offsets_seconds) AS o \
         WHERE p.community_id=$1 AND p.workspace_id=$2 AND p.plan_id=$3 AND p.generation=$4 \
           AND p.deadline_at-make_interval(secs=>o)>$6 ON CONFLICT DO NOTHING",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .bind(occurrence_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    Ok(())
}

async fn insert_control_outbox(
    tx: &mut Transaction<'_, Postgres>,
    scope: PlanScope,
    generation: u64,
    occurrence_id: Uuid,
    dispatch_id: Option<Uuid>,
    command_kind: &str,
    now: DateTime<Utc>,
) -> Result<bool, ApiError> {
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.orchestration.control-outbox.v1\0");
    hasher.update(scope.tenant_id.as_bytes());
    hasher.update(scope.workspace_id.as_bytes());
    hasher.update(scope.plan_id.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(occurrence_id.as_bytes());
    hasher.update(dispatch_id.unwrap_or(Uuid::nil()).as_bytes());
    hasher.update(command_kind.as_bytes());
    let command_sha256: [u8; 32] = hasher.finalize().into();
    let inserted = sqlx::query(
        "INSERT INTO snowman_orchestration_control_outbox \
         (community_id,workspace_id,outbox_id,command_kind,plan_id,plan_generation,dispatch_id,\
          occurrence_id,command_sha256,status,next_attempt_at,created_at,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$10,$10) ON CONFLICT DO NOTHING",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(Uuid::new_v4())
    .bind(command_kind)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .bind(dispatch_id)
    .bind(occurrence_id)
    .bind(command_sha256.as_slice())
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(db_conflict)?;
    Ok(inserted.rows_affected() == 1)
}

async fn scheduler_cycle(
    pool: &PgPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    request: &SchedulerCycleRequest,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<SchedulerCycleReceipt, ApiError> {
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id,
            workspace_id,
            identity_id: request.service_identity_id,
            principal: &request.service_principal,
            policy_generation: request.policy_generation,
            capability: "orchestration.scheduler.maintain",
        },
        auth,
        digest,
        now,
    )
    .await?;
    let due = sqlx::query(
        "SELECT r.plan_id,r.schedule_generation,r.local_minute,r.weekdays,r.dst_gap_policy,\
                r.dst_fold_policy,r.catch_up_policy,r.max_catch_up_seconds,r.next_fire_at,s.timezone \
         FROM snowman_orchestration_recurrences r \
         JOIN snowman_orchestration_plans p ON p.community_id=r.community_id AND p.plan_id=r.plan_id \
           AND p.generation=r.schedule_generation \
         JOIN snowman_orchestration_schedule_policies s ON s.community_id=r.community_id AND s.plan_id=r.plan_id \
         WHERE r.community_id=$1 AND r.workspace_id=$2 AND r.enabled AND r.next_fire_at<=$3 \
           AND p.state='active' AND p.automatic_execution_enabled \
         ORDER BY r.next_fire_at,r.plan_id FOR UPDATE OF r SKIP LOCKED LIMIT $4",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(now)
    .bind(i64::from(request.max_records))
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let mut recurrences_processed = 0_u32;
    let mut occurrences_materialized = 0_u32;
    for row in due {
        let plan_id: Uuid = row
            .try_get("plan_id")
            .map_err(|_| ApiError(Error::Database))?;
        let generation: i64 = row
            .try_get("schedule_generation")
            .map_err(|_| ApiError(Error::Database))?;
        let scheduled_at: DateTime<Utc> = row
            .try_get("next_fire_at")
            .map_err(|_| ApiError(Error::Database))?;
        let weekdays: Vec<i16> = row
            .try_get("weekdays")
            .map_err(|_| ApiError(Error::Database))?;
        let policy = RecurrencePolicy {
            schedule_generation: u64::try_from(generation)
                .map_err(|_| ApiError(Error::Database))?,
            timezone: row
                .try_get("timezone")
                .map_err(|_| ApiError(Error::Database))?,
            local_minute: u16::try_from(
                row.try_get::<i32, _>("local_minute")
                    .map_err(|_| ApiError(Error::Database))?,
            )
            .map_err(|_| ApiError(Error::Database))?,
            weekdays: weekdays
                .into_iter()
                .map(|value| u8::try_from(value).map_err(|_| ApiError(Error::Database)))
                .collect::<Result<_, _>>()?,
            dst_gap_policy: match row
                .try_get::<String, _>("dst_gap_policy")
                .map_err(|_| ApiError(Error::Database))?
                .as_str()
            {
                "skip" => DstGapPolicy::Skip,
                "shift_forward" => DstGapPolicy::ShiftForward,
                _ => return Err(ApiError(Error::Database)),
            },
            dst_fold_policy: match row
                .try_get::<String, _>("dst_fold_policy")
                .map_err(|_| ApiError(Error::Database))?
                .as_str()
            {
                "first" => DstFoldPolicy::First,
                "second" => DstFoldPolicy::Second,
                _ => return Err(ApiError(Error::Database)),
            },
            catch_up_policy: match row
                .try_get::<String, _>("catch_up_policy")
                .map_err(|_| ApiError(Error::Database))?
                .as_str()
            {
                "skip" => CatchUpPolicy::Skip,
                "one" => CatchUpPolicy::One,
                _ => return Err(ApiError(Error::Database)),
            },
            max_catch_up_seconds: u32::try_from(
                row.try_get::<i32, _>("max_catch_up_seconds")
                    .map_err(|_| ApiError(Error::Database))?,
            )
            .map_err(|_| ApiError(Error::Database))?,
            enabled: true,
        };
        let decision = decide_catch_up(&policy, scheduled_at, now);
        let next = next_occurrence(&policy, now).map_err(ApiError)?;
        let occurrence_id = Uuid::new_v4();
        let plan_scope = PlanScope {
            tenant_id,
            workspace_id,
            plan_id,
        };
        let status = if decision == CatchUpDecision::Fire {
            "materialized"
        } else {
            "skipped"
        };
        let inserted = create_occurrence(
            &mut tx,
            plan_scope,
            policy.schedule_generation,
            occurrence_id,
            Some(policy.schedule_generation),
            scheduled_at,
            now > scheduled_at,
            status,
        )
        .await?;
        if inserted && decision == CatchUpDecision::Fire {
            materialize_ready_dispatches(
                &mut tx,
                plan_scope,
                policy.schedule_generation,
                occurrence_id,
                now,
            )
            .await?;
            create_deadline_reminders(
                &mut tx,
                plan_scope,
                policy.schedule_generation,
                occurrence_id,
                now,
            )
            .await?;
            occurrences_materialized = occurrences_materialized.saturating_add(1);
        }
        sqlx::query(
            "UPDATE snowman_orchestration_recurrences SET last_fire_at=$1,next_fire_at=$2,updated_at=$3 \
             WHERE community_id=$4 AND workspace_id=$5 AND plan_id=$6 AND schedule_generation=$7 \
               AND next_fire_at=$1",
        )
        .bind(scheduled_at)
        .bind(next.scheduled_at)
        .bind(now)
        .bind(tenant_id)
        .bind(workspace_id)
        .bind(plan_id)
        .bind(generation)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
        recurrences_processed = recurrences_processed.saturating_add(1);
    }

    let reminder_rows = sqlx::query(
        "SELECT rr.plan_id,rr.plan_generation,rr.occurrence_id \
         FROM snowman_orchestration_reminder_receipts rr \
         JOIN snowman_orchestration_plans p ON p.community_id=rr.community_id AND p.plan_id=rr.plan_id \
           AND p.generation=rr.plan_generation \
         WHERE rr.community_id=$1 AND p.workspace_id=$2 AND rr.status='pending' AND rr.due_at<=$3 \
           AND p.state='active' ORDER BY rr.due_at,rr.plan_id FOR UPDATE OF rr SKIP LOCKED LIMIT $4",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(now)
    .bind(i64::from(request.max_records))
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let mut reminders_enqueued = 0_u32;
    for row in reminder_rows {
        let plan_id: Uuid = row
            .try_get("plan_id")
            .map_err(|_| ApiError(Error::Database))?;
        let generation = u64::try_from(
            row.try_get::<i64, _>("plan_generation")
                .map_err(|_| ApiError(Error::Database))?,
        )
        .map_err(|_| ApiError(Error::Database))?;
        let occurrence_id: Uuid = row
            .try_get("occurrence_id")
            .map_err(|_| ApiError(Error::Database))?;
        if insert_control_outbox(
            &mut tx,
            PlanScope {
                tenant_id,
                workspace_id,
                plan_id,
            },
            generation,
            occurrence_id,
            None,
            "deliver_reminder",
            now,
        )
        .await?
        {
            reminders_enqueued = reminders_enqueued.saturating_add(1);
        }
    }

    let recovery = recover_dispatches(
        &mut tx,
        tenant_id,
        workspace_id,
        request.max_records,
        request.submitted_timeout_seconds,
        now,
    )
    .await?;
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(SchedulerCycleReceipt {
        request_id: request.request_id,
        recurrences_processed,
        occurrences_materialized,
        dispatches_recovered: recovery.recovered,
        dispatches_dead_lettered: recovery.dead_lettered,
        reminders_enqueued,
    })
}

struct RecoveryCounts {
    recovered: u32,
    dead_lettered: u32,
}

async fn recover_dispatches(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    max_records: u16,
    submitted_timeout_seconds: u16,
    now: DateTime<Utc>,
) -> Result<RecoveryCounts, ApiError> {
    let rows = sqlx::query(
        "SELECT d.dispatch_id,d.plan_id,d.plan_generation,d.task_id,d.occurrence_id,d.attempt_count,\
                d.max_attempts,p.state \
         FROM snowman_orchestration_dispatches d \
         JOIN snowman_orchestration_plans p ON p.community_id=d.community_id AND p.plan_id=d.plan_id \
           AND p.generation=d.plan_generation \
         WHERE d.community_id=$1 AND d.workspace_id=$2 AND \
           ((d.status='leased' AND d.lease_expires_at<=$3) OR \
            (d.status='submitted' AND d.submitted_at<=($3-make_interval(secs=>$4)))) \
         ORDER BY COALESCE(d.lease_expires_at,d.submitted_at),d.dispatch_id \
         FOR UPDATE OF d SKIP LOCKED LIMIT $5",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(now)
    .bind(i32::from(submitted_timeout_seconds))
    .bind(i64::from(max_records))
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let mut counts = RecoveryCounts {
        recovered: 0,
        dead_lettered: 0,
    };
    for row in rows {
        let dispatch_id: Uuid = row
            .try_get("dispatch_id")
            .map_err(|_| ApiError(Error::Database))?;
        let plan_id: Uuid = row
            .try_get("plan_id")
            .map_err(|_| ApiError(Error::Database))?;
        let generation: i64 = row
            .try_get("plan_generation")
            .map_err(|_| ApiError(Error::Database))?;
        let task_id: Uuid = row
            .try_get("task_id")
            .map_err(|_| ApiError(Error::Database))?;
        let occurrence_id: Uuid = row
            .try_get("occurrence_id")
            .map_err(|_| ApiError(Error::Database))?;
        let attempt_count: i32 = row
            .try_get("attempt_count")
            .map_err(|_| ApiError(Error::Database))?;
        let max_attempts: i32 = row
            .try_get("max_attempts")
            .map_err(|_| ApiError(Error::Database))?;
        let plan_state: String = row
            .try_get("state")
            .map_err(|_| ApiError(Error::Database))?;
        if recovery_disposition(&plan_state, attempt_count, max_attempts)
            == RecoveryDisposition::Cancel
        {
            sqlx::query(
                "UPDATE snowman_orchestration_dispatches SET status='cancelled',\
                 cancellation_generation=cancellation_generation+1,lease_owner_identity_id=NULL,\
                 lease_expires_at=NULL,terminal_at=$1,terminal_outcome='cancelled',updated_at=$1 \
                 WHERE community_id=$2 AND dispatch_id=$3",
            )
            .bind(now)
            .bind(tenant_id)
            .bind(dispatch_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| ApiError(Error::Database))?;
        } else if recovery_disposition(&plan_state, attempt_count, max_attempts)
            == RecoveryDisposition::Retry
        {
            sqlx::query(
                "UPDATE snowman_orchestration_dispatches SET status='failed',lease_owner_identity_id=NULL,\
                 lease_expires_at=NULL,next_attempt_at=$1,updated_at=$1 WHERE community_id=$2 AND dispatch_id=$3",
            )
            .bind(now)
            .bind(tenant_id)
            .bind(dispatch_id)
            .execute(&mut **tx)
            .await
            .map_err(|_| ApiError(Error::Database))?;
            counts.recovered = counts.recovered.saturating_add(1);
        } else {
            dead_letter_dispatch(
                tx,
                tenant_id,
                dispatch_id,
                plan_id,
                generation,
                task_id,
                occurrence_id,
                "delivery_failed",
                Sha256::digest(b"snowman.orchestration.delivery-timeout.v1").into(),
                now,
            )
            .await?;
            counts.dead_lettered = counts.dead_lettered.saturating_add(1);
        }
    }
    Ok(counts)
}

#[allow(clippy::too_many_arguments)]
async fn persist_delivery_result(
    pool: &PgPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    dispatch_id: Uuid,
    command: &DeliveryResultCommand,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ApiReceipt, ApiError> {
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id,
            workspace_id,
            identity_id: command.service_identity_id,
            principal: &command.service_principal,
            policy_generation: command.policy_generation,
            capability: "orchestration.scheduler.dispatch",
        },
        auth,
        digest,
        now,
    )
    .await?;
    if let Some(prior) = sqlx::query(
        "SELECT request_sha256 FROM snowman_orchestration_delivery_attempts \
         WHERE community_id=$1 AND dispatch_id=$2 AND lease_generation=$3",
    )
    .bind(tenant_id)
    .bind(dispatch_id)
    .bind(command.lease_generation as i64)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    {
        let prior_digest: Vec<u8> = prior
            .try_get("request_sha256")
            .map_err(|_| ApiError(Error::Database))?;
        if prior_digest != digest {
            return Err(ApiError(Error::Conflict));
        }
        let coordinate = dispatch_coordinate(&mut tx, tenant_id, workspace_id, dispatch_id).await?;
        tx.commit().await.map_err(|_| ApiError(Error::Database))?;
        return Ok(scoped_receipt(
            dispatch_id,
            PlanScope {
                tenant_id,
                workspace_id,
                plan_id: coordinate.plan_id,
            },
            coordinate.generation,
            "duplicate",
            digest,
            now,
        ));
    }
    let row = sqlx::query(
        "SELECT d.plan_id,d.plan_generation,d.task_id,d.occurrence_id,d.attempt_count,d.max_attempts,\
                d.coordinator_job_reference,d.cancellation_generation,d.lease_owner_identity_id,\
                d.lease_expires_at,p.state \
         FROM snowman_orchestration_dispatches d \
         JOIN snowman_orchestration_plans p ON p.community_id=d.community_id AND p.plan_id=d.plan_id \
           AND p.generation=d.plan_generation \
         WHERE d.community_id=$1 AND d.workspace_id=$2 AND d.dispatch_id=$3 AND d.status='leased' \
         FOR UPDATE OF d,p",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(dispatch_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    .ok_or(ApiError(Error::Conflict))?;
    let plan_id: Uuid = row
        .try_get("plan_id")
        .map_err(|_| ApiError(Error::Database))?;
    let generation: i64 = row
        .try_get("plan_generation")
        .map_err(|_| ApiError(Error::Database))?;
    let cancellation_generation: i64 = row
        .try_get("cancellation_generation")
        .map_err(|_| ApiError(Error::Database))?;
    let lease_owner: Option<Uuid> = row
        .try_get("lease_owner_identity_id")
        .map_err(|_| ApiError(Error::Database))?;
    let lease_expiry: Option<DateTime<Utc>> = row
        .try_get("lease_expires_at")
        .map_err(|_| ApiError(Error::Database))?;
    let coordinator_reference: String = row
        .try_get("coordinator_job_reference")
        .map_err(|_| ApiError(Error::Database))?;
    let state: String = row
        .try_get("state")
        .map_err(|_| ApiError(Error::Database))?;
    if state != "active"
        || lease_owner != Some(command.service_identity_id)
        || lease_expiry.is_none_or(|expires| expires <= now)
        || cancellation_generation != command.cancellation_generation as i64
        || command
            .coordinator_receipt_reference
            .as_deref()
            .is_some_and(|value| value != coordinator_reference)
    {
        return Err(ApiError(Error::Conflict));
    }
    let attempt_count: i32 = row
        .try_get("attempt_count")
        .map_err(|_| ApiError(Error::Database))?;
    let max_attempts: i32 = row
        .try_get("max_attempts")
        .map_err(|_| ApiError(Error::Database))?;
    let outcome = if command.outcome == DeliveryOutcome::Submitted {
        "submitted"
    } else if attempt_count >= max_attempts {
        "dead_letter"
    } else {
        "retryable_failure"
    };
    sqlx::query(
        "INSERT INTO snowman_orchestration_delivery_attempts \
         (community_id,dispatch_id,lease_generation,cancellation_generation,request_sha256,outcome,\
          coordinator_receipt_reference,response_sha256,accepted_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(tenant_id)
    .bind(dispatch_id)
    .bind(command.lease_generation as i64)
    .bind(command.cancellation_generation as i64)
    .bind(digest.as_slice())
    .bind(outcome)
    .bind(&command.coordinator_receipt_reference)
    .bind(
        command
            .response_sha256
            .as_deref()
            .map(decode_digest)
            .transpose()?,
    )
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(db_conflict)?;
    if command.outcome == DeliveryOutcome::Submitted {
        sqlx::query(
            "UPDATE snowman_orchestration_dispatches SET status='submitted',submitted_at=$1,\
             lease_owner_identity_id=NULL,lease_expires_at=NULL,updated_at=$1 \
             WHERE community_id=$2 AND dispatch_id=$3 AND lease_generation=$4 \
               AND cancellation_generation=$5 AND status='leased'",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(dispatch_id)
        .bind(command.lease_generation as i64)
        .bind(command.cancellation_generation as i64)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
    } else if outcome == "retryable_failure" {
        let failure = decode_digest(
            command
                .failure_sha256
                .as_deref()
                .ok_or(ApiError(Error::Invalid))?,
        )?;
        let retry_at = now
            + ChronoDuration::seconds(i64::from(
                command
                    .retry_after_seconds
                    .ok_or(ApiError(Error::Invalid))?,
            ));
        sqlx::query(
            "UPDATE snowman_orchestration_dispatches SET status='failed',lease_owner_identity_id=NULL,\
             lease_expires_at=NULL,next_attempt_at=$1,last_failure_sha256=$2,updated_at=$3 \
             WHERE community_id=$4 AND dispatch_id=$5 AND lease_generation=$6 \
               AND cancellation_generation=$7 AND status='leased'",
        )
        .bind(retry_at)
        .bind(failure)
        .bind(now)
        .bind(tenant_id)
        .bind(dispatch_id)
        .bind(command.lease_generation as i64)
        .bind(command.cancellation_generation as i64)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
    } else {
        dead_letter_dispatch(
            &mut tx,
            tenant_id,
            dispatch_id,
            plan_id,
            generation,
            row.try_get("task_id")
                .map_err(|_| ApiError(Error::Database))?,
            row.try_get("occurrence_id")
                .map_err(|_| ApiError(Error::Database))?,
            "delivery_failed",
            decode_digest(
                command
                    .failure_sha256
                    .as_deref()
                    .ok_or(ApiError(Error::Invalid))?,
            )?,
            now,
        )
        .await?;
    }
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(scoped_receipt(
        dispatch_id,
        PlanScope {
            tenant_id,
            workspace_id,
            plan_id,
        },
        u64::try_from(generation).map_err(|_| ApiError(Error::Database))?,
        outcome,
        digest,
        now,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn persist_terminal_receipt(
    pool: &PgPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    dispatch_id: Uuid,
    command: &TerminalReceiptCommand,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ApiReceipt, ApiError> {
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id,
            workspace_id,
            identity_id: command.service_identity_id,
            principal: &command.service_principal,
            policy_generation: command.policy_generation,
            capability: "orchestration.receipts.ingest",
        },
        auth,
        digest,
        now,
    )
    .await?;
    if let Some(row) = sqlx::query(
        "SELECT r.receipt_sha256,r.plan_id,r.plan_generation FROM snowman_orchestration_terminal_receipts r \
         WHERE r.community_id=$1 AND r.workspace_id=$2 AND r.dispatch_id=$3",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(dispatch_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    {
        let prior: Vec<u8> = row
            .try_get("receipt_sha256")
            .map_err(|_| ApiError(Error::Database))?;
        if prior != decode_digest(&command.receipt_sha256)? {
            return Err(ApiError(Error::Conflict));
        }
        let plan_id: Uuid = row.try_get("plan_id").map_err(|_| ApiError(Error::Database))?;
        let generation = u64::try_from(
            row.try_get::<i64, _>("plan_generation")
                .map_err(|_| ApiError(Error::Database))?,
        )
        .map_err(|_| ApiError(Error::Database))?;
        tx.commit().await.map_err(|_| ApiError(Error::Database))?;
        return Ok(scoped_receipt(
            dispatch_id,
            PlanScope {
                tenant_id,
                workspace_id,
                plan_id,
            },
            generation,
            "duplicate",
            digest,
            now,
        ));
    }
    let row = sqlx::query(
        "SELECT d.plan_id,d.plan_generation,d.task_id,d.occurrence_id,d.lease_generation,\
                d.cancellation_generation,d.execution_snapshot_sha256,d.reserved_cost_microusd,p.state,p.deadline_at \
         FROM snowman_orchestration_dispatches d \
         JOIN snowman_orchestration_plans p ON p.community_id=d.community_id AND p.plan_id=d.plan_id \
           AND p.generation=d.plan_generation \
         WHERE d.community_id=$1 AND d.workspace_id=$2 AND d.dispatch_id=$3 AND d.status='submitted' \
         FOR UPDATE OF d,p",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(dispatch_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    .ok_or(ApiError(Error::Conflict))?;
    let state: String = row
        .try_get("state")
        .map_err(|_| ApiError(Error::Database))?;
    let deadline: DateTime<Utc> = row
        .try_get("deadline_at")
        .map_err(|_| ApiError(Error::Database))?;
    let stored_snapshot: Vec<u8> = row
        .try_get("execution_snapshot_sha256")
        .map_err(|_| ApiError(Error::Database))?;
    let reserved: i64 = row
        .try_get("reserved_cost_microusd")
        .map_err(|_| ApiError(Error::Database))?;
    if state != "active"
        || row
            .try_get::<i64, _>("lease_generation")
            .map_err(|_| ApiError(Error::Database))?
            != command.lease_generation as i64
        || row
            .try_get::<i64, _>("cancellation_generation")
            .map_err(|_| ApiError(Error::Database))?
            != command.cancellation_generation as i64
        || stored_snapshot != decode_digest(&command.execution_snapshot_sha256)?
        || command.actual_cost_microusd
            > u64::try_from(reserved).map_err(|_| ApiError(Error::Database))?
        || command.completed_at > deadline + ChronoDuration::minutes(5)
    {
        return Err(ApiError(Error::Conflict));
    }
    let plan_id: Uuid = row
        .try_get("plan_id")
        .map_err(|_| ApiError(Error::Database))?;
    let generation: i64 = row
        .try_get("plan_generation")
        .map_err(|_| ApiError(Error::Database))?;
    let task_id: Uuid = row
        .try_get("task_id")
        .map_err(|_| ApiError(Error::Database))?;
    let occurrence_id: Uuid = row
        .try_get("occurrence_id")
        .map_err(|_| ApiError(Error::Database))?;
    let terminal_outcome = terminal_outcome(command.outcome);
    sqlx::query(
        "INSERT INTO snowman_orchestration_terminal_receipts \
         (community_id,workspace_id,dispatch_id,occurrence_id,plan_id,plan_generation,task_id,\
          lease_generation,cancellation_generation,execution_snapshot_sha256,outcome,\
          handoff_manifest_reference,handoff_manifest_sha256,artifact_references,evidence_references,\
          execution_receipt_references,actual_cost_microusd,receipt_sha256,completed_at,accepted_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(dispatch_id)
    .bind(occurrence_id)
    .bind(plan_id)
    .bind(generation)
    .bind(task_id)
    .bind(command.lease_generation as i64)
    .bind(command.cancellation_generation as i64)
    .bind(decode_digest(&command.execution_snapshot_sha256)?)
    .bind(terminal_outcome)
    .bind(&command.handoff_manifest_reference)
    .bind(decode_digest(&command.handoff_manifest_sha256)?)
    .bind(command.artifact_references.iter().cloned().collect::<Vec<_>>())
    .bind(command.evidence_references.iter().cloned().collect::<Vec<_>>())
    .bind(
        command
            .execution_receipt_references
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .bind(command.actual_cost_microusd as i64)
    .bind(decode_digest(&command.receipt_sha256)?)
    .bind(command.completed_at)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(db_conflict)?;
    let dispatch_status = match command.outcome {
        TerminalOutcome::Succeeded => "succeeded",
        TerminalOutcome::Cancelled => "cancelled",
        TerminalOutcome::Blocked | TerminalOutcome::Failed => "dead_letter",
    };
    sqlx::query(
        "UPDATE snowman_orchestration_dispatches SET status=$1,terminal_at=$2,terminal_outcome=$3,updated_at=$2 \
         WHERE community_id=$4 AND dispatch_id=$5 AND status='submitted' \
           AND lease_generation=$6 AND cancellation_generation=$7",
    )
    .bind(dispatch_status)
    .bind(now)
    .bind(terminal_outcome)
    .bind(tenant_id)
    .bind(dispatch_id)
    .bind(command.lease_generation as i64)
    .bind(command.cancellation_generation as i64)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    if matches!(
        command.outcome,
        TerminalOutcome::Blocked | TerminalOutcome::Failed
    ) {
        dead_letter_dispatch(
            &mut tx,
            tenant_id,
            dispatch_id,
            plan_id,
            generation,
            task_id,
            occurrence_id,
            "delivery_failed",
            decode_digest(&command.receipt_sha256)?,
            now,
        )
        .await?;
    }
    let scope = PlanScope {
        tenant_id,
        workspace_id,
        plan_id,
    };
    let progress = update_progress_digest(
        &mut tx,
        scope,
        u64::try_from(generation).map_err(|_| ApiError(Error::Database))?,
        occurrence_id,
        now,
    )
    .await?;
    if command.outcome == TerminalOutcome::Succeeded {
        materialize_ready_dispatches(
            &mut tx,
            scope,
            u64::try_from(generation).map_err(|_| ApiError(Error::Database))?,
            occurrence_id,
            now,
        )
        .await?;
    }
    finalize_occurrence_if_terminal(&mut tx, scope, generation, occurrence_id, &progress, now)
        .await?;
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(scoped_receipt(
        dispatch_id,
        scope,
        u64::try_from(generation).map_err(|_| ApiError(Error::Database))?,
        terminal_outcome,
        digest,
        now,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn dead_letter_dispatch(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    dispatch_id: Uuid,
    plan_id: Uuid,
    generation: i64,
    task_id: Uuid,
    occurrence_id: Uuid,
    failure_class: &str,
    failure_sha256: [u8; 32],
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE snowman_orchestration_dispatches SET status='dead_letter',lease_owner_identity_id=NULL,\
         lease_expires_at=NULL,last_failure_sha256=$1,terminal_at=COALESCE(terminal_at,$2),\
         terminal_outcome=COALESCE(terminal_outcome,'failed'),updated_at=$2 \
         WHERE community_id=$3 AND dispatch_id=$4",
    )
    .bind(failure_sha256.as_slice())
    .bind(now)
    .bind(tenant_id)
    .bind(dispatch_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "INSERT INTO snowman_orchestration_dead_letters \
         (community_id,dead_letter_id,dispatch_id,plan_id,plan_generation,task_id,failure_class,\
          failure_sha256,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(Uuid::new_v4())
    .bind(dispatch_id)
    .bind(plan_id)
    .bind(generation)
    .bind(task_id)
    .bind(failure_class)
    .bind(failure_sha256.as_slice())
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(db_conflict)?;
    sqlx::query(
        "UPDATE snowman_orchestration_occurrences SET status='failed',updated_at=$1 \
         WHERE community_id=$2 AND occurrence_id=$3 AND status='materialized'",
    )
    .bind(now)
    .bind(tenant_id)
    .bind(occurrence_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    Ok(())
}

struct DispatchCoordinate {
    plan_id: Uuid,
    generation: u64,
}

async fn dispatch_coordinate(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    dispatch_id: Uuid,
) -> Result<DispatchCoordinate, ApiError> {
    let row = sqlx::query(
        "SELECT plan_id,plan_generation FROM snowman_orchestration_dispatches \
         WHERE community_id=$1 AND workspace_id=$2 AND dispatch_id=$3",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(dispatch_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    .ok_or(ApiError(Error::Conflict))?;
    Ok(DispatchCoordinate {
        plan_id: row
            .try_get("plan_id")
            .map_err(|_| ApiError(Error::Database))?,
        generation: u64::try_from(
            row.try_get::<i64, _>("plan_generation")
                .map_err(|_| ApiError(Error::Database))?,
        )
        .map_err(|_| ApiError(Error::Database))?,
    })
}

struct ProgressState {
    digest: [u8; 32],
    completed_task_ids: Vec<Uuid>,
    accounted_cost_microusd: i64,
}

async fn update_progress_digest(
    tx: &mut Transaction<'_, Postgres>,
    scope: PlanScope,
    generation: u64,
    occurrence_id: Uuid,
    now: DateTime<Utc>,
) -> Result<ProgressState, ApiError> {
    let rows = sqlx::query(
        "SELECT task_id,outcome,lease_generation,receipt_sha256,handoff_manifest_sha256,actual_cost_microusd \
         FROM snowman_orchestration_terminal_receipts WHERE community_id=$1 AND workspace_id=$2 \
           AND plan_id=$3 AND plan_generation=$4 AND occurrence_id=$5 ORDER BY task_id",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .bind(occurrence_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.orchestration.progress.v1\0");
    hasher.update(scope.tenant_id.as_bytes());
    hasher.update(scope.workspace_id.as_bytes());
    hasher.update(scope.plan_id.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(occurrence_id.as_bytes());
    let mut completed = Vec::new();
    let mut terminal = BTreeMap::new();
    let mut cost = 0_i64;
    for row in rows {
        let task_id: Uuid = row
            .try_get("task_id")
            .map_err(|_| ApiError(Error::Database))?;
        let outcome: String = row
            .try_get("outcome")
            .map_err(|_| ApiError(Error::Database))?;
        let lease_generation: i64 = row
            .try_get("lease_generation")
            .map_err(|_| ApiError(Error::Database))?;
        let receipt_sha: Vec<u8> = row
            .try_get("receipt_sha256")
            .map_err(|_| ApiError(Error::Database))?;
        let handoff_sha: Vec<u8> = row
            .try_get("handoff_manifest_sha256")
            .map_err(|_| ApiError(Error::Database))?;
        let actual: i64 = row
            .try_get("actual_cost_microusd")
            .map_err(|_| ApiError(Error::Database))?;
        cost = cost.checked_add(actual).ok_or(ApiError(Error::Conflict))?;
        hasher.update(task_id.as_bytes());
        hasher.update(lease_generation.to_be_bytes());
        hasher.update(&receipt_sha);
        hasher.update(&handoff_sha);
        hasher.update(actual.to_be_bytes());
        hasher.update(outcome.as_bytes());
        if outcome == "succeeded" {
            completed.push(task_id);
        }
        terminal.insert(task_id, outcome);
    }
    let task_rows = sqlx::query(
        "SELECT task_id FROM snowman_orchestration_tasks WHERE community_id=$1 AND plan_id=$2 \
         AND plan_generation=$3 ORDER BY task_id",
    )
    .bind(scope.tenant_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let mut ready = Vec::new();
    for row in task_rows {
        let task_id: Uuid = row
            .try_get("task_id")
            .map_err(|_| ApiError(Error::Database))?;
        if terminal.contains_key(&task_id) {
            continue;
        }
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM snowman_orchestration_task_dependencies d \
             WHERE d.community_id=$1 AND d.plan_id=$2 AND d.plan_generation=$3 AND d.task_id=$4 \
               AND NOT EXISTS (SELECT 1 FROM snowman_orchestration_terminal_receipts r \
                 WHERE r.community_id=d.community_id AND r.occurrence_id=$5 \
                   AND r.task_id=d.depends_on_task_id AND r.outcome='succeeded'))",
        )
        .bind(scope.tenant_id)
        .bind(scope.plan_id)
        .bind(generation as i64)
        .bind(task_id)
        .bind(occurrence_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
        if !blocked {
            ready.push(task_id);
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let revision: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(revision),0)+1 FROM snowman_orchestration_progress_digests \
         WHERE community_id=$1 AND occurrence_id=$2",
    )
    .bind(scope.tenant_id)
    .bind(occurrence_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    sqlx::query(
        "INSERT INTO snowman_orchestration_progress_digests \
         (community_id,workspace_id,plan_id,plan_generation,occurrence_id,progress_sha256,\
          completed_task_ids,next_ready_task_ids,accounted_cost_microusd,revision,created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(scope.tenant_id)
    .bind(scope.workspace_id)
    .bind(scope.plan_id)
    .bind(generation as i64)
    .bind(occurrence_id)
    .bind(digest.as_slice())
    .bind(&completed)
    .bind(&ready)
    .bind(cost)
    .bind(revision)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(db_conflict)?;
    sqlx::query(
        "UPDATE snowman_orchestration_occurrences SET progress_sha256=$1,\
         accounted_cost_microusd=$2,updated_at=$3 WHERE community_id=$4 AND occurrence_id=$5",
    )
    .bind(digest.as_slice())
    .bind(cost)
    .bind(now)
    .bind(scope.tenant_id)
    .bind(occurrence_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    Ok(ProgressState {
        digest,
        completed_task_ids: completed,
        accounted_cost_microusd: cost,
    })
}

async fn finalize_occurrence_if_terminal(
    tx: &mut Transaction<'_, Postgres>,
    scope: PlanScope,
    generation: i64,
    occurrence_id: Uuid,
    progress: &ProgressState,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    let task_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM snowman_orchestration_tasks WHERE community_id=$1 AND plan_id=$2 \
         AND plan_generation=$3",
    )
    .bind(scope.tenant_id)
    .bind(scope.plan_id)
    .bind(generation)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let terminal_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM snowman_orchestration_terminal_receipts WHERE community_id=$1 \
         AND occurrence_id=$2",
    )
    .bind(scope.tenant_id)
    .bind(occurrence_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    if terminal_count != task_count {
        return Ok(());
    }
    let completed = i64::try_from(progress.completed_task_ids.len())
        .map_err(|_| ApiError(Error::Database))?
        == task_count;
    sqlx::query(
        "UPDATE snowman_orchestration_occurrences SET status=$1,progress_sha256=$2,\
         accounted_cost_microusd=$3,updated_at=$4 WHERE community_id=$5 AND occurrence_id=$6",
    )
    .bind(if completed { "completed" } else { "failed" })
    .bind(progress.digest.as_slice())
    .bind(progress.accounted_cost_microusd)
    .bind(now)
    .bind(scope.tenant_id)
    .bind(occurrence_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let recurring: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM snowman_orchestration_recurrences WHERE community_id=$1 \
         AND plan_id=$2 AND schedule_generation=$3)",
    )
    .bind(scope.tenant_id)
    .bind(scope.plan_id)
    .bind(generation)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    if completed && !recurring {
        sqlx::query(
            "UPDATE snowman_orchestration_plans SET state='completed',automatic_execution_enabled=FALSE,\
             updated_at=$1 WHERE community_id=$2 AND workspace_id=$3 AND plan_id=$4 \
               AND generation=$5 AND state='active'",
        )
        .bind(now)
        .bind(scope.tenant_id)
        .bind(scope.workspace_id)
        .bind(scope.plan_id)
        .bind(generation)
        .execute(&mut **tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
    }
    Ok(())
}

async fn claim_control_outbox(
    pool: &PgPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    request: &ControlClaimRequest,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<Vec<ControlLease>, ApiError> {
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id,
            workspace_id,
            identity_id: request.service_identity_id,
            principal: &request.service_principal,
            policy_generation: request.policy_generation,
            capability: "orchestration.scheduler.control",
        },
        auth,
        digest,
        now,
    )
    .await?;
    sqlx::query(
        "UPDATE snowman_orchestration_control_outbox o SET status='cancelled',updated_at=$1 \
         FROM snowman_orchestration_plans p WHERE o.community_id=$2 AND o.workspace_id=$3 \
           AND o.command_kind='deliver_reminder' AND o.status IN ('pending','leased') \
           AND p.community_id=o.community_id AND p.plan_id=o.plan_id \
           AND p.generation=o.plan_generation AND p.state<>'active'",
    )
    .bind(now)
    .bind(tenant_id)
    .bind(workspace_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let command_kinds = request
        .command_kinds
        .iter()
        .map(|kind| kind.as_str().to_owned())
        .collect::<Vec<_>>();
    let rows = sqlx::query(
        "SELECT o.outbox_id,o.command_kind,o.plan_id,o.plan_generation,o.dispatch_id,o.occurrence_id,\
                o.command_sha256,o.attempt_count,o.max_attempts,o.lease_generation,o.created_at,\
                d.coordinator_job_reference \
         FROM snowman_orchestration_control_outbox o \
         JOIN snowman_orchestration_plans p ON p.community_id=o.community_id \
           AND p.plan_id=o.plan_id AND p.generation=o.plan_generation \
         LEFT JOIN snowman_orchestration_dispatches d ON d.community_id=o.community_id \
           AND d.dispatch_id=o.dispatch_id \
         WHERE o.community_id=$1 AND o.workspace_id=$2 AND o.command_kind=ANY($3) \
           AND ((o.status='pending' AND o.next_attempt_at<=$4) \
             OR (o.status='leased' AND o.lease_expires_at<=$4)) \
           AND o.attempt_count<o.max_attempts \
           AND (o.command_kind='cancel_dispatch' OR p.state='active') \
         ORDER BY o.next_attempt_at,o.outbox_id FOR UPDATE OF o SKIP LOCKED LIMIT $5",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(command_kinds)
    .bind(now)
    .bind(i64::from(request.max_claims))
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let lease_expires_at = now + ChronoDuration::seconds(i64::from(request.lease_seconds));
    let mut leases = Vec::with_capacity(rows.len());
    for row in rows {
        let outbox_id: Uuid = row
            .try_get("outbox_id")
            .map_err(|_| ApiError(Error::Database))?;
        let prior_generation: i64 = row
            .try_get("lease_generation")
            .map_err(|_| ApiError(Error::Database))?;
        let next_generation = prior_generation
            .checked_add(1)
            .ok_or(ApiError(Error::Conflict))?;
        let attempt_count: i32 = row
            .try_get("attempt_count")
            .map_err(|_| ApiError(Error::Database))?;
        let updated = sqlx::query(
            "UPDATE snowman_orchestration_control_outbox SET status='leased',lease_generation=$1,\
             lease_owner_identity_id=$2,lease_expires_at=$3,attempt_count=$4,updated_at=$5 \
             WHERE community_id=$6 AND workspace_id=$7 AND outbox_id=$8 \
               AND status IN ('pending','leased') AND lease_generation=$9",
        )
        .bind(next_generation)
        .bind(request.service_identity_id)
        .bind(lease_expires_at)
        .bind(attempt_count + 1)
        .bind(now)
        .bind(tenant_id)
        .bind(workspace_id)
        .bind(outbox_id)
        .bind(prior_generation)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
        if updated.rows_affected() != 1 {
            return Err(ApiError(Error::Conflict));
        }
        let kind: String = row
            .try_get("command_kind")
            .map_err(|_| ApiError(Error::Database))?;
        let command_kind = match kind.as_str() {
            "cancel_dispatch" => ControlCommandKind::CancelDispatch,
            "deliver_reminder" => ControlCommandKind::DeliverReminder,
            _ => return Err(ApiError(Error::Database)),
        };
        let command_sha256: Vec<u8> = row
            .try_get("command_sha256")
            .map_err(|_| ApiError(Error::Database))?;
        if command_sha256.len() != 32 {
            return Err(ApiError(Error::Database));
        }
        leases.push(ControlLease {
            outbox_id,
            community_id: tenant_id,
            workspace_id,
            command_kind,
            plan_id: row
                .try_get("plan_id")
                .map_err(|_| ApiError(Error::Database))?,
            plan_generation: u64::try_from(
                row.try_get::<i64, _>("plan_generation")
                    .map_err(|_| ApiError(Error::Database))?,
            )
            .map_err(|_| ApiError(Error::Database))?,
            dispatch_id: row
                .try_get("dispatch_id")
                .map_err(|_| ApiError(Error::Database))?,
            occurrence_id: row
                .try_get("occurrence_id")
                .map_err(|_| ApiError(Error::Database))?,
            command_sha256: hex::encode(command_sha256),
            coordinator_job_reference: row
                .try_get("coordinator_job_reference")
                .map_err(|_| ApiError(Error::Database))?,
            lease_generation: u64::try_from(next_generation)
                .map_err(|_| ApiError(Error::Database))?,
            command_created_at: row
                .try_get("created_at")
                .map_err(|_| ApiError(Error::Database))?,
            lease_expires_at,
        });
    }
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(leases)
}

#[allow(clippy::too_many_arguments)]
async fn persist_control_delivery(
    pool: &PgPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    outbox_id: Uuid,
    command: &ControlDeliveryResultCommand,
    auth: &VerifiedAuth,
    request_digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ApiReceipt, ApiError> {
    let mut tx = serializable(pool).await?;
    authorize_and_record(
        &mut tx,
        Scope {
            tenant_id,
            workspace_id,
            identity_id: command.service_identity_id,
            principal: &command.service_principal,
            policy_generation: command.policy_generation,
            capability: "orchestration.scheduler.control",
        },
        auth,
        request_digest,
        now,
    )
    .await?;
    if let Some(prior) = sqlx::query(
        "SELECT r.request_sha256,o.plan_id,o.plan_generation \
         FROM snowman_orchestration_control_delivery_receipts r \
         JOIN snowman_orchestration_control_outbox o ON o.community_id=r.community_id \
           AND o.outbox_id=r.outbox_id \
         WHERE r.community_id=$1 AND r.outbox_id=$2 AND r.lease_generation=$3",
    )
    .bind(tenant_id)
    .bind(outbox_id)
    .bind(command.lease_generation as i64)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    {
        let prior_digest: Vec<u8> = prior
            .try_get("request_sha256")
            .map_err(|_| ApiError(Error::Database))?;
        if prior_digest != request_digest {
            return Err(ApiError(Error::Conflict));
        }
        let scope = PlanScope {
            tenant_id,
            workspace_id,
            plan_id: prior
                .try_get("plan_id")
                .map_err(|_| ApiError(Error::Database))?,
        };
        let generation = u64::try_from(
            prior
                .try_get::<i64, _>("plan_generation")
                .map_err(|_| ApiError(Error::Database))?,
        )
        .map_err(|_| ApiError(Error::Database))?;
        tx.commit().await.map_err(|_| ApiError(Error::Database))?;
        return Ok(scoped_receipt(
            outbox_id,
            scope,
            generation,
            "duplicate",
            request_digest,
            now,
        ));
    }
    let row = sqlx::query(
        "SELECT command_kind,plan_id,plan_generation,dispatch_id,occurrence_id,command_sha256,\
                attempt_count,max_attempts,lease_generation,lease_owner_identity_id,lease_expires_at \
         FROM snowman_orchestration_control_outbox WHERE community_id=$1 AND workspace_id=$2 \
           AND outbox_id=$3 AND status='leased' FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(outbox_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    .ok_or(ApiError(Error::Conflict))?;
    let stored_command_digest: Vec<u8> = row
        .try_get("command_sha256")
        .map_err(|_| ApiError(Error::Database))?;
    let lease_owner: Option<Uuid> = row
        .try_get("lease_owner_identity_id")
        .map_err(|_| ApiError(Error::Database))?;
    let lease_expiry: Option<DateTime<Utc>> = row
        .try_get("lease_expires_at")
        .map_err(|_| ApiError(Error::Database))?;
    if lease_owner != Some(command.service_identity_id)
        || row
            .try_get::<i64, _>("lease_generation")
            .map_err(|_| ApiError(Error::Database))?
            != command.lease_generation as i64
        || lease_expiry.is_none_or(|expiry| expiry <= now)
        || stored_command_digest != decode_digest(&command.command_sha256)?
    {
        return Err(ApiError(Error::Conflict));
    }
    let kind: String = row
        .try_get("command_kind")
        .map_err(|_| ApiError(Error::Database))?;
    let attempt_count: i32 = row
        .try_get("attempt_count")
        .map_err(|_| ApiError(Error::Database))?;
    let max_attempts: i32 = row
        .try_get("max_attempts")
        .map_err(|_| ApiError(Error::Database))?;
    let outcome = if command.outcome == ControlDeliveryOutcome::Delivered {
        "delivered"
    } else if attempt_count >= max_attempts {
        "dead_letter"
    } else {
        "retryable_failure"
    };
    sqlx::query(
        "INSERT INTO snowman_orchestration_control_delivery_receipts \
         (community_id,workspace_id,outbox_id,lease_generation,command_kind,command_sha256,\
          request_sha256,outcome,delivery_reference,response_sha256,failure_sha256,accepted_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(outbox_id)
    .bind(command.lease_generation as i64)
    .bind(&kind)
    .bind(&stored_command_digest)
    .bind(request_digest.as_slice())
    .bind(outcome)
    .bind(&command.delivery_reference)
    .bind(
        command
            .response_sha256
            .as_deref()
            .map(decode_digest)
            .transpose()?,
    )
    .bind(
        command
            .failure_sha256
            .as_deref()
            .map(decode_digest)
            .transpose()?,
    )
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(db_conflict)?;
    if outcome == "delivered" {
        sqlx::query(
            "UPDATE snowman_orchestration_control_outbox SET status='delivered',\
             lease_owner_identity_id=NULL,lease_expires_at=NULL,updated_at=$1 \
             WHERE community_id=$2 AND outbox_id=$3 AND lease_generation=$4 AND status='leased'",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(outbox_id)
        .bind(command.lease_generation as i64)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
        if kind == "deliver_reminder" {
            let plan_id: Uuid = row
                .try_get("plan_id")
                .map_err(|_| ApiError(Error::Database))?;
            let plan_generation: i64 = row
                .try_get("plan_generation")
                .map_err(|_| ApiError(Error::Database))?;
            let occurrence_id: Uuid = row
                .try_get("occurrence_id")
                .map_err(|_| ApiError(Error::Database))?;
            sqlx::query(
                "UPDATE snowman_orchestration_reminder_receipts SET status='delivered',delivered_at=$1 \
                 WHERE community_id=$2 AND plan_id=$3 AND plan_generation=$4 \
                   AND occurrence_id=$5 AND status='pending'",
            )
            .bind(now)
            .bind(tenant_id)
            .bind(plan_id)
            .bind(plan_generation)
            .bind(occurrence_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError(Error::Database))?;
        }
    } else if outcome == "retryable_failure" {
        let retry_at = now
            + ChronoDuration::seconds(i64::from(
                command
                    .retry_after_seconds
                    .ok_or(ApiError(Error::Invalid))?,
            ));
        sqlx::query(
            "UPDATE snowman_orchestration_control_outbox SET status='pending',\
             lease_owner_identity_id=NULL,lease_expires_at=NULL,next_attempt_at=$1,updated_at=$2 \
             WHERE community_id=$3 AND outbox_id=$4 AND lease_generation=$5 AND status='leased'",
        )
        .bind(retry_at)
        .bind(now)
        .bind(tenant_id)
        .bind(outbox_id)
        .bind(command.lease_generation as i64)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
    } else {
        sqlx::query(
            "UPDATE snowman_orchestration_control_outbox SET status='dead_letter',\
             lease_owner_identity_id=NULL,lease_expires_at=NULL,updated_at=$1 \
             WHERE community_id=$2 AND outbox_id=$3 AND lease_generation=$4 AND status='leased'",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(outbox_id)
        .bind(command.lease_generation as i64)
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError(Error::Database))?;
    }
    let scope = PlanScope {
        tenant_id,
        workspace_id,
        plan_id: row
            .try_get("plan_id")
            .map_err(|_| ApiError(Error::Database))?,
    };
    let generation = u64::try_from(
        row.try_get::<i64, _>("plan_generation")
            .map_err(|_| ApiError(Error::Database))?,
    )
    .map_err(|_| ApiError(Error::Database))?;
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(scoped_receipt(
        outbox_id,
        scope,
        generation,
        outcome,
        request_digest,
        now,
    ))
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
                d.required_capabilities,d.reserved_cost_microusd,d.attempt_count,d.max_attempts,\
                d.cancellation_generation,d.execution_snapshot_sha256,t.deadline_at,\
                p.request_id,p.classification,pe.model_id,pe.specialist_role \
         FROM snowman_orchestration_dispatches d \
         JOIN snowman_orchestration_plans p ON p.community_id=d.community_id AND p.plan_id=d.plan_id \
           AND p.generation=d.plan_generation \
         JOIN snowman_orchestration_tasks t ON t.community_id=d.community_id AND t.plan_id=d.plan_id \
           AND t.plan_generation=d.plan_generation AND t.task_id=d.task_id \
         JOIN snowman_orchestration_personas pe ON pe.community_id=t.community_id \
           AND pe.plan_id=t.plan_id AND pe.plan_generation=t.plan_generation AND pe.persona_id=t.persona_id \
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
            request_id: row
                .try_get("request_id")
                .map_err(|_| ApiError(Error::Database))?,
            execution_snapshot_sha256: hex::encode(
                row.try_get::<Vec<u8>, _>("execution_snapshot_sha256")
                    .map_err(|_| ApiError(Error::Database))?,
            ),
            model_id: row
                .try_get("model_id")
                .map_err(|_| ApiError(Error::Database))?,
            specialist_role: row
                .try_get("specialist_role")
                .map_err(|_| ApiError(Error::Database))?,
            classification: parse_classification(
                &row.try_get::<String, _>("classification")
                    .map_err(|_| ApiError(Error::Database))?,
            )?,
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
            cancellation_generation: u64::try_from(
                row.try_get::<i64, _>("cancellation_generation")
                    .map_err(|_| ApiError(Error::Database))?,
            )
            .map_err(|_| ApiError(Error::Database))?,
            reserved_cost_microusd: u64::try_from(
                row.try_get::<i64, _>("reserved_cost_microusd")
                    .map_err(|_| ApiError(Error::Database))?,
            )
            .map_err(|_| ApiError(Error::Database))?,
            deadline_at: row
                .try_get("deadline_at")
                .map_err(|_| ApiError(Error::Database))?,
            lease_expires_at,
        });
    }
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(leases)
}

async fn read_team_operations(
    pool: &PgPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    auth: &VerifiedAuth,
    request_url: &str,
    now: DateTime<Utc>,
) -> Result<TeamOperationsProjection, ApiError> {
    let mut tx = pool.begin().await.map_err(|_| ApiError(Error::Database))?;
    let request_digest: [u8; 32] =
        Sha256::digest([b"GET\0".as_slice(), request_url.as_bytes()].concat()).into();
    let authority =
        authorize_human_read(&mut tx, tenant_id, workspace_id, auth, request_digest, now).await?;

    let plan_row = sqlx::query(
        "SELECT plan_id,request_id,work_kind,generation,supersedes_plan_id,state,classification,\
         max_cost_microusd,automatic_execution_enabled,deadline_at,created_at,updated_at \
         FROM snowman_orchestration_plans WHERE community_id=$1 AND workspace_id=$2 \
         ORDER BY CASE WHEN state IN ('active','paused','draft') THEN 0 ELSE 1 END,updated_at DESC,plan_id \
         LIMIT 1",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    .ok_or(ApiError(Error::NotFound))?;
    let plan_id: Uuid = plan_row
        .try_get("plan_id")
        .map_err(|_| ApiError(Error::Database))?;
    let generation = positive_u64(
        plan_row
            .try_get("generation")
            .map_err(|_| ApiError(Error::Database))?,
    )?;
    let plan = TeamOperationsPlan {
        plan_id,
        request_id: plan_row
            .try_get("request_id")
            .map_err(|_| ApiError(Error::Database))?,
        work_kind: plan_row
            .try_get("work_kind")
            .map_err(|_| ApiError(Error::Database))?,
        generation,
        supersedes_plan_id: plan_row
            .try_get("supersedes_plan_id")
            .map_err(|_| ApiError(Error::Database))?,
        state: plan_row
            .try_get("state")
            .map_err(|_| ApiError(Error::Database))?,
        classification: plan_row
            .try_get("classification")
            .map_err(|_| ApiError(Error::Database))?,
        max_cost_microusd: nonnegative_u64_projection(
            plan_row
                .try_get("max_cost_microusd")
                .map_err(|_| ApiError(Error::Database))?,
        )?,
        automatic_execution_enabled: plan_row
            .try_get("automatic_execution_enabled")
            .map_err(|_| ApiError(Error::Database))?,
        deadline_at: plan_row
            .try_get("deadline_at")
            .map_err(|_| ApiError(Error::Database))?,
        created_at: plan_row
            .try_get("created_at")
            .map_err(|_| ApiError(Error::Database))?,
        updated_at: plan_row
            .try_get("updated_at")
            .map_err(|_| ApiError(Error::Database))?,
    };

    let schedule = sqlx::query(
        "SELECT s.timezone,s.quiet_start_local_minute,s.quiet_end_local_minute,\
         s.allow_deadline_reminders,s.reminder_offsets_seconds,r.enabled,\
         r.local_minute,r.weekdays,r.next_fire_at \
         FROM snowman_orchestration_schedule_policies s \
         LEFT JOIN snowman_orchestration_recurrences r \
           ON r.community_id=s.community_id AND r.plan_id=s.plan_id \
         WHERE s.community_id=$1 AND s.plan_id=$2",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    .map(|row| -> Result<TeamOperationsSchedule, ApiError> {
        let quiet_start: i32 = row
            .try_get("quiet_start_local_minute")
            .map_err(|_| ApiError(Error::Database))?;
        let quiet_end: i32 = row
            .try_get("quiet_end_local_minute")
            .map_err(|_| ApiError(Error::Database))?;
        let recurrence_minute: Option<i32> = row
            .try_get("local_minute")
            .map_err(|_| ApiError(Error::Database))?;
        Ok(TeamOperationsSchedule {
            timezone: row
                .try_get("timezone")
                .map_err(|_| ApiError(Error::Database))?,
            quiet_start_local_minute: u16::try_from(quiet_start)
                .map_err(|_| ApiError(Error::Database))?,
            quiet_end_local_minute: u16::try_from(quiet_end)
                .map_err(|_| ApiError(Error::Database))?,
            allow_deadline_reminders: row
                .try_get("allow_deadline_reminders")
                .map_err(|_| ApiError(Error::Database))?,
            reminder_offsets_seconds: row
                .try_get("reminder_offsets_seconds")
                .map_err(|_| ApiError(Error::Database))?,
            recurrence_enabled: row
                .try_get::<Option<bool>, _>("enabled")
                .map_err(|_| ApiError(Error::Database))?
                .unwrap_or(false),
            recurrence_local_minute: recurrence_minute
                .map(u16::try_from)
                .transpose()
                .map_err(|_| ApiError(Error::Database))?,
            recurrence_weekdays: row
                .try_get::<Option<Vec<i16>>, _>("weekdays")
                .map_err(|_| ApiError(Error::Database))?
                .unwrap_or_default(),
            next_fire_at: row
                .try_get("next_fire_at")
                .map_err(|_| ApiError(Error::Database))?,
        })
    })
    .transpose()?;

    let persona_rows = sqlx::query(
        "SELECT p.persona_id,p.specialist_role,p.model_id,p.model_route_reference,\
         p.max_cost_microusd,p.enabled,ARRAY(SELECT pc.capability \
           FROM snowman_orchestration_persona_capabilities pc \
           WHERE pc.community_id=p.community_id AND pc.plan_id=p.plan_id \
             AND pc.persona_id=p.persona_id ORDER BY pc.capability) AS capabilities \
         FROM snowman_orchestration_personas p WHERE p.community_id=$1 AND p.plan_id=$2 \
         ORDER BY p.specialist_role,p.persona_id",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let personas = persona_rows
        .into_iter()
        .map(|row| -> Result<TeamOperationsPersona, ApiError> {
            Ok(TeamOperationsPersona {
                persona_id: row
                    .try_get("persona_id")
                    .map_err(|_| ApiError(Error::Database))?,
                specialist_role: row
                    .try_get("specialist_role")
                    .map_err(|_| ApiError(Error::Database))?,
                model_id: row
                    .try_get("model_id")
                    .map_err(|_| ApiError(Error::Database))?,
                model_route_reference: row
                    .try_get::<Option<String>, _>("model_route_reference")
                    .map_err(|_| ApiError(Error::Database))?
                    .ok_or(ApiError(Error::Database))?,
                max_cost_microusd: nonnegative_u64_projection(
                    row.try_get("max_cost_microusd")
                        .map_err(|_| ApiError(Error::Database))?,
                )?,
                enabled: row
                    .try_get("enabled")
                    .map_err(|_| ApiError(Error::Database))?,
                capabilities: row
                    .try_get("capabilities")
                    .map_err(|_| ApiError(Error::Database))?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let task_rows = sqlx::query(
        "SELECT t.task_id,t.persona_id,w.status,t.approval_required,t.max_cost_microusd,\
         w.execution_snapshot_sha256,\
         t.deadline_at,ARRAY(SELECT d.depends_on_task_id FROM snowman_orchestration_task_dependencies d \
           WHERE d.community_id=t.community_id AND d.plan_id=t.plan_id AND d.task_id=t.task_id \
           ORDER BY d.depends_on_task_id) AS depends_on,\
         ARRAY(SELECT c.capability FROM snowman_orchestration_task_required_capabilities c \
           WHERE c.community_id=t.community_id AND c.plan_id=t.plan_id AND c.task_id=t.task_id \
           ORDER BY c.capability) AS required_capabilities,\
         ARRAY(SELECT a.artifact_type FROM snowman_orchestration_task_artifact_contracts a \
           WHERE a.community_id=t.community_id AND a.plan_id=t.plan_id AND a.task_id=t.task_id \
           ORDER BY a.artifact_type) AS artifact_types,\
         d.status AS dispatch_status,COALESCE(d.reserved_cost_microusd,0)::bigint AS reserved_cost_microusd,\
         COALESCE(r.actual_cost_microusd,0)::bigint AS accounted_cost_microusd \
         FROM snowman_orchestration_tasks t JOIN snowman_work_tasks w \
           ON w.community_id=t.community_id AND w.request_id=t.request_id AND w.task_id=t.task_id \
         LEFT JOIN LATERAL (SELECT status,reserved_cost_microusd FROM snowman_orchestration_dispatches x \
           WHERE x.community_id=t.community_id AND x.plan_id=t.plan_id AND x.task_id=t.task_id \
           ORDER BY x.updated_at DESC,x.dispatch_id LIMIT 1) d ON TRUE \
         LEFT JOIN snowman_orchestration_work_product_receipts r \
           ON r.community_id=t.community_id AND r.plan_id=t.plan_id AND r.task_id=t.task_id \
         WHERE t.community_id=$1 AND t.plan_id=$2 AND t.plan_generation=$3 \
         ORDER BY t.deadline_at,t.task_id",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .bind(i64::try_from(generation).map_err(|_| ApiError(Error::Database))?)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let tasks = task_rows
        .into_iter()
        .map(|row| -> Result<TeamOperationsTask, ApiError> {
            Ok(TeamOperationsTask {
                task_id: row
                    .try_get("task_id")
                    .map_err(|_| ApiError(Error::Database))?,
                persona_id: row
                    .try_get("persona_id")
                    .map_err(|_| ApiError(Error::Database))?,
                depends_on: row
                    .try_get("depends_on")
                    .map_err(|_| ApiError(Error::Database))?,
                status: row
                    .try_get("status")
                    .map_err(|_| ApiError(Error::Database))?,
                approval_required: row
                    .try_get("approval_required")
                    .map_err(|_| ApiError(Error::Database))?,
                required_capabilities: row
                    .try_get("required_capabilities")
                    .map_err(|_| ApiError(Error::Database))?,
                artifact_types: row
                    .try_get("artifact_types")
                    .map_err(|_| ApiError(Error::Database))?,
                max_cost_microusd: nonnegative_u64_projection(
                    row.try_get("max_cost_microusd")
                        .map_err(|_| ApiError(Error::Database))?,
                )?,
                deadline_at: row
                    .try_get("deadline_at")
                    .map_err(|_| ApiError(Error::Database))?,
                dispatch_status: row
                    .try_get("dispatch_status")
                    .map_err(|_| ApiError(Error::Database))?,
                reserved_cost_microusd: nonnegative_u64_projection(
                    row.try_get("reserved_cost_microusd")
                        .map_err(|_| ApiError(Error::Database))?,
                )?,
                accounted_cost_microusd: nonnegative_u64_projection(
                    row.try_get("accounted_cost_microusd")
                        .map_err(|_| ApiError(Error::Database))?,
                )?,
                execution_snapshot_sha256: hex::encode(
                    row.try_get::<Vec<u8>, _>("execution_snapshot_sha256")
                        .map_err(|_| ApiError(Error::Database))?,
                ),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let receipt_rows = sqlx::query(
        "SELECT r.task_id,r.outcome,r.handoff_manifest_reference,r.receipt_sha256,\
         r.actual_cost_microusd,r.completed_at,\
         ARRAY(SELECT x.immutable_reference FROM snowman_orchestration_receipt_refs x \
           WHERE x.community_id=r.community_id AND x.plan_id=r.plan_id AND x.task_id=r.task_id \
             AND x.reference_kind='artifact' ORDER BY x.immutable_reference) AS artifacts,\
         ARRAY(SELECT x.immutable_reference FROM snowman_orchestration_receipt_refs x \
           WHERE x.community_id=r.community_id AND x.plan_id=r.plan_id AND x.task_id=r.task_id \
             AND x.reference_kind='evidence' ORDER BY x.immutable_reference) AS evidence \
         FROM snowman_orchestration_work_product_receipts r \
         WHERE r.community_id=$1 AND r.plan_id=$2 AND r.plan_generation=$3 ORDER BY r.accepted_at,r.task_id",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .bind(i64::try_from(generation).map_err(|_| ApiError(Error::Database))?)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let receipts = receipt_rows
        .into_iter()
        .map(|row| -> Result<TeamOperationsReceipt, ApiError> {
            Ok(TeamOperationsReceipt {
                task_id: row
                    .try_get("task_id")
                    .map_err(|_| ApiError(Error::Database))?,
                outcome: row
                    .try_get("outcome")
                    .map_err(|_| ApiError(Error::Database))?,
                handoff_manifest_reference: row
                    .try_get("handoff_manifest_reference")
                    .map_err(|_| ApiError(Error::Database))?,
                receipt_sha256: hex::encode(
                    row.try_get::<Vec<u8>, _>("receipt_sha256")
                        .map_err(|_| ApiError(Error::Database))?,
                ),
                artifact_references: row
                    .try_get("artifacts")
                    .map_err(|_| ApiError(Error::Database))?,
                evidence_references: row
                    .try_get("evidence")
                    .map_err(|_| ApiError(Error::Database))?,
                actual_cost_microusd: nonnegative_u64_projection(
                    row.try_get("actual_cost_microusd")
                        .map_err(|_| ApiError(Error::Database))?,
                )?,
                completed_at: row
                    .try_get("completed_at")
                    .map_err(|_| ApiError(Error::Database))?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let reminder_rows = sqlx::query(
        "SELECT occurrence_id,due_at,delivered_at,status FROM snowman_orchestration_reminder_receipts \
         WHERE community_id=$1 AND plan_id=$2 AND plan_generation=$3 ORDER BY due_at,occurrence_id LIMIT 64",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .bind(i64::try_from(generation).map_err(|_| ApiError(Error::Database))?)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let reminders = reminder_rows
        .into_iter()
        .map(|row| -> Result<TeamOperationsReminder, ApiError> {
            Ok(TeamOperationsReminder {
                occurrence_id: row
                    .try_get("occurrence_id")
                    .map_err(|_| ApiError(Error::Database))?,
                due_at: row
                    .try_get("due_at")
                    .map_err(|_| ApiError(Error::Database))?,
                delivered_at: row
                    .try_get("delivered_at")
                    .map_err(|_| ApiError(Error::Database))?,
                status: row
                    .try_get("status")
                    .map_err(|_| ApiError(Error::Database))?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let command_rows = sqlx::query(
        "SELECT command_id,command_kind,plan_generation,command_sha256,status,applied_at \
         FROM snowman_orchestration_commands WHERE community_id=$1 AND workspace_id=$2 AND plan_id=$3 \
         ORDER BY applied_at DESC,command_id LIMIT 64",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(plan_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let commands = command_rows
        .into_iter()
        .map(|row| -> Result<TeamOperationsCommandReceipt, ApiError> {
            Ok(TeamOperationsCommandReceipt {
                command_id: row
                    .try_get("command_id")
                    .map_err(|_| ApiError(Error::Database))?,
                command_kind: row
                    .try_get("command_kind")
                    .map_err(|_| ApiError(Error::Database))?,
                plan_generation: positive_u64(
                    row.try_get("plan_generation")
                        .map_err(|_| ApiError(Error::Database))?,
                )?,
                command_sha256: hex::encode(
                    row.try_get::<Vec<u8>, _>("command_sha256")
                        .map_err(|_| ApiError(Error::Database))?,
                ),
                status: row
                    .try_get("status")
                    .map_err(|_| ApiError(Error::Database))?,
                applied_at: row
                    .try_get("applied_at")
                    .map_err(|_| ApiError(Error::Database))?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    tx.commit().await.map_err(|_| ApiError(Error::Database))?;
    Ok(TeamOperationsProjection {
        schema_version: "snowman.orchestration.team-operations.v1",
        generated_at: now,
        tenant_id,
        workspace_id,
        authority,
        plan,
        schedule,
        personas,
        tasks,
        receipts,
        reminders,
        commands,
    })
}

async fn authorize_human_read(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    workspace_id: Uuid,
    auth: &VerifiedAuth,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<TeamOperationsAuthority, ApiError> {
    let authority = sqlx::query(
        "SELECT i.identity_id,c.service_principal,c.policy_generation FROM snowman_orchestration_callers c \
         JOIN snowman_workforce_identities i ON i.community_id=c.community_id AND i.identity_id=c.service_identity_id \
         JOIN snowman_workforce_key_bindings k ON k.community_id=i.community_id AND k.identity_id=i.identity_id \
         JOIN snowman_workforce_sessions s ON s.community_id=i.community_id AND s.identity_id=i.identity_id \
           AND s.session_id=k.session_id \
         JOIN snowman_workforce_capability_grants g ON g.community_id=i.community_id AND g.identity_id=i.identity_id \
         WHERE c.community_id=$1 AND c.workspace_id=$2 AND c.status='active' \
           AND i.identity_type='human' AND i.status='active' AND i.revoked_at IS NULL \
           AND (i.expires_at IS NULL OR i.expires_at>NOW()) \
           AND k.pubkey=$3 AND k.binding_type='human_device' AND k.revoked_at IS NULL \
           AND (k.expires_at IS NULL OR k.expires_at>NOW()) \
           AND s.revoked_at IS NULL AND s.expires_at>NOW() \
           AND g.capability='workforce.requests.read' AND g.revoked_at IS NULL \
           AND (g.expires_at IS NULL OR g.expires_at>NOW()) LIMIT 1",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(auth.pubkey.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?
    .ok_or(ApiError(Error::Unauthorized))?;
    let identity_id: Uuid = authority
        .try_get("identity_id")
        .map_err(|_| ApiError(Error::Database))?;
    let principal: String = authority
        .try_get("service_principal")
        .map_err(|_| ApiError(Error::Database))?;
    let policy_generation = positive_u64(
        authority
            .try_get("policy_generation")
            .map_err(|_| ApiError(Error::Database))?,
    )?;
    let capabilities: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT capability FROM snowman_workforce_capability_grants \
         WHERE community_id=$1 AND identity_id=$2 AND revoked_at IS NULL \
           AND (expires_at IS NULL OR expires_at>NOW()) \
           AND capability IN ('orchestration.plans.activate','orchestration.plans.pause',\
             'orchestration.plans.cancel','orchestration.plans.supersede',\
             'workforce.tasks.approve') ORDER BY capability",
    )
    .bind(tenant_id)
    .bind(identity_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    let inserted = sqlx::query(
        "INSERT INTO snowman_orchestration_auth_events \
         (community_id,auth_event_id,request_sha256,requester_pubkey,service_identity_id,observed_at,expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(auth.event_id.as_slice())
    .bind(digest.as_slice())
    .bind(auth.pubkey.as_slice())
    .bind(identity_id)
    .bind(now)
    .bind(auth.created_at + ChronoDuration::seconds(AUTH_TTL_SECONDS))
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError(Error::Database))?;
    if inserted.rows_affected() != 1 {
        return Err(ApiError(Error::Unauthorized));
    }
    Ok(TeamOperationsAuthority {
        identity_id,
        principal,
        policy_generation,
        capabilities,
    })
}

fn positive_u64(value: i64) -> Result<u64, ApiError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ApiError(Error::Database))
}

fn nonnegative_u64_projection(value: i64) -> Result<u64, ApiError> {
    u64::try_from(value).map_err(|_| ApiError(Error::Database))
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
         LEFT JOIN snowman_workforce_sessions s ON s.community_id=i.community_id AND s.identity_id=i.identity_id \
           AND s.session_id=k.session_id \
         JOIN snowman_workforce_capability_grants g ON g.community_id=i.community_id AND g.identity_id=i.identity_id \
         WHERE c.community_id=$1 AND c.workspace_id=$2 AND c.service_identity_id=$3 \
           AND c.service_principal=$4 AND c.policy_generation=$5 AND c.status='active' \
           AND i.status='active' \
           AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at>NOW()) \
           AND k.pubkey=$6 AND k.revoked_at IS NULL \
           AND (k.expires_at IS NULL OR k.expires_at>NOW()) \
           AND ((i.identity_type='service' AND i.provider='snowman_service' \
                 AND k.binding_type='service_runtime' AND s.session_id IS NULL) \
             OR (i.identity_type='human' AND k.binding_type='human_device' \
                 AND s.revoked_at IS NULL AND s.expires_at>NOW())) \
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

fn verify_read_auth(headers: &HeaderMap, url: &str) -> Result<VerifiedAuth, ApiError> {
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
    if event.tags.iter().any(|tag| tag.kind() == TagKind::Payload) {
        return Err(ApiError(Error::Unauthorized));
    }
    let pubkey = buzz_auth::verify_nip98_event(&event_json, url, "GET", None)
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

fn parse_classification(value: &str) -> Result<Classification, ApiError> {
    match value {
        "internal" => Ok(Classification::Internal),
        "confidential" => Ok(Classification::Confidential),
        "restricted" => Ok(Classification::Restricted),
        _ => Err(ApiError(Error::Database)),
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

fn decode_digest(value: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(value).map_err(|_| ApiError(Error::Invalid))?;
    bytes.try_into().map_err(|_| ApiError(Error::Invalid))
}

fn valid_analyst_reference(value: &str) -> bool {
    value
        .strip_prefix("analyst360:sha256:")
        .is_some_and(valid_hex_digest)
}

fn valid_execution_ref(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|rest| {
        rest.split_once(":generation:")
            .is_some_and(|(id, generation)| {
                Uuid::parse_str(id).is_ok()
                    && generation
                        .parse::<u64>()
                        .is_ok_and(|generation| generation > 0)
            })
    })
}

fn valid_any_execution_ref(value: &str) -> bool {
    [
        "snowman:agent-job:",
        "snowman:model-generation:",
        "snowman:tool-action:",
    ]
    .iter()
    .any(|prefix| valid_execution_ref(value, prefix))
}

fn valid_control_delivery_reference(value: &str) -> bool {
    for prefix in ["snowman:agent-job:", "snowman:reminder-delivery:"] {
        if valid_execution_ref(value, prefix) {
            return true;
        }
    }
    false
}

fn terminal_outcome(value: TerminalOutcome) -> &'static str {
    match value {
        TerminalOutcome::Succeeded => "succeeded",
        TerminalOutcome::Blocked => "blocked",
        TerminalOutcome::Failed => "failed",
        TerminalOutcome::Cancelled => "cancelled",
    }
}

fn scoped_receipt(
    command_id: Uuid,
    scope: PlanScope,
    generation: u64,
    status: &str,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> ApiReceipt {
    ApiReceipt {
        schema_version: API_RECEIPT_SCHEMA.into(),
        command_id,
        community_id: scope.tenant_id,
        workspace_id: scope.workspace_id,
        plan_id: scope.plan_id,
        plan_generation: generation,
        status: status.into(),
        request_sha256: hex::encode(digest),
        accepted_at: now,
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_snapshot_digest(
    scope: PlanScope,
    generation: u64,
    occurrence_id: Uuid,
    task_id: Uuid,
    model_route_reference: &str,
    context_refs: &[String],
    capabilities: &[String],
    reserved_cost_microusd: i64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.orchestration.dispatch-snapshot.v1\0");
    hasher.update(scope.tenant_id.as_bytes());
    hasher.update(scope.workspace_id.as_bytes());
    hasher.update(scope.plan_id.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(occurrence_id.as_bytes());
    hasher.update(task_id.as_bytes());
    hasher.update(model_route_reference.as_bytes());
    for reference in context_refs {
        hasher.update(reference.as_bytes());
        hasher.update([0]);
    }
    for capability in capabilities {
        hasher.update(capability.as_bytes());
        hasher.update([0]);
    }
    hasher.update(reserved_cost_microusd.to_be_bytes());
    hasher.finalize().into()
}

fn reservation_fits(committed: i64, ceiling: i64, requested: i64) -> bool {
    committed >= 0
        && ceiling >= 0
        && requested >= 0
        && committed <= ceiling.saturating_sub(requested)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoveryDisposition {
    Cancel,
    Retry,
    DeadLetter,
}

fn recovery_disposition(
    plan_state: &str,
    attempt_count: i32,
    max_attempts: i32,
) -> RecoveryDisposition {
    if plan_state != "active" {
        RecoveryDisposition::Cancel
    } else if attempt_count < max_attempts {
        RecoveryDisposition::Retry
    } else {
        RecoveryDisposition::DeadLetter
    }
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
            Error::NotFound => StatusCode::NOT_FOUND,
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

    #[test]
    fn activation_and_supersession_remain_explicit_and_default_off() {
        let mut lifecycle = PlanLifecycleCommand {
            schema_version: LIFECYCLE_SCHEMA.into(),
            command_id: Uuid::from_u128(1),
            service_identity_id: Uuid::from_u128(2),
            service_principal: "snowman:orchestration-controller".into(),
            policy_generation: 1,
            plan_generation: 1,
            automatic_execution_enabled: false,
            recurrence_enabled: false,
            evidence_sha256: hex::encode([1_u8; 32]),
        };
        assert!(validate_lifecycle(&lifecycle, LifecycleAction::Activate).is_ok());
        lifecycle.recurrence_enabled = true;
        assert!(validate_lifecycle(&lifecycle, LifecycleAction::Activate).is_err());
        lifecycle.automatic_execution_enabled = true;
        assert!(validate_lifecycle(&lifecycle, LifecycleAction::Pause).is_err());

        let mut supersede = SupersedePlanCommand {
            schema_version: LIFECYCLE_SCHEMA.into(),
            command_id: Uuid::from_u128(3),
            service_identity_id: Uuid::from_u128(2),
            service_principal: "snowman:orchestration-controller".into(),
            policy_generation: 1,
            superseded_plan_id: Uuid::from_u128(4),
            superseded_plan_generation: 2,
            replacement_plan_generation: 3,
            automatic_execution_enabled: false,
            recurrence_enabled: false,
            evidence_sha256: hex::encode([2_u8; 32]),
        };
        assert!(validate_supersession(&supersede, Uuid::from_u128(5)).is_ok());
        supersede.replacement_plan_generation = 4;
        assert!(validate_supersession(&supersede, Uuid::from_u128(5)).is_err());
    }

    #[test]
    fn dispatch_snapshot_is_deterministic_and_scope_bound() {
        let scope = PlanScope {
            tenant_id: Uuid::from_u128(1),
            workspace_id: Uuid::from_u128(2),
            plan_id: Uuid::from_u128(3),
        };
        let context = vec![format!("analyst360:sha256:{}", hex::encode([4_u8; 32]))];
        let capabilities = vec!["analyst.query".into()];
        let first = dispatch_snapshot_digest(
            scope,
            1,
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            &format!("snowman:model-route:{}:revision:1", Uuid::from_u128(7)),
            &context,
            &capabilities,
            100,
        );
        let replay = dispatch_snapshot_digest(
            scope,
            1,
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            &format!("snowman:model-route:{}:revision:1", Uuid::from_u128(7)),
            &context,
            &capabilities,
            100,
        );
        let other_tenant = dispatch_snapshot_digest(
            PlanScope {
                tenant_id: Uuid::from_u128(8),
                ..scope
            },
            1,
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            &format!("snowman:model-route:{}:revision:1", Uuid::from_u128(7)),
            &context,
            &capabilities,
            100,
        );
        assert_eq!(first, replay);
        assert_ne!(first, other_tenant);
    }

    #[test]
    fn budget_and_recovery_decisions_fail_closed() {
        assert!(reservation_fits(50, 100, 50));
        assert!(!reservation_fits(51, 100, 50));
        assert!(!reservation_fits(-1, 100, 1));
        assert!(recovery_disposition("paused", 0, 3) == RecoveryDisposition::Cancel);
        assert!(recovery_disposition("active", 2, 3) == RecoveryDisposition::Retry);
        assert!(recovery_disposition("active", 3, 3) == RecoveryDisposition::DeadLetter);
    }

    #[test]
    fn lifecycle_migration_fences_duplicates_cancellation_and_occurrences() {
        let source =
            include_str!("../../../migrations/0055_snowman_orchestration_execution_lifecycle.sql");
        assert!(source.contains("PRIMARY KEY (community_id, dispatch_id, lease_generation)"));
        assert!(source.contains("UNIQUE (community_id, occurrence_id, task_id)"));
        assert!(source.contains("cancellation_generation BIGINT NOT NULL"));
        assert!(source.contains("command_kind IN ('cancel_dispatch','deliver_reminder')"));
        assert!(source.contains("handoff_manifest_reference ~ '^analyst360:sha256:"));
        assert!(!source.contains("provider_api_key"));
        assert!(!source.contains("raw_prompt"));
    }
}
