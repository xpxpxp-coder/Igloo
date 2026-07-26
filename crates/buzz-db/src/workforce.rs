//! Durable, tenant-scoped queue primitives for the Snowman AI Workforce.
//!
//! The queue stores coordination state and immutable context references. Raw
//! client datasets remain in Analyst 360. Claims use PostgreSQL row locking and
//! fenced, digest-bound leases so a stale worker cannot complete a task after a
//! replacement worker has acquired it.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use url::Url;
use uuid::Uuid;

use buzz_core::CommunityId;
use snowman_workforce::{
    decide_proactive_action, validate_context_packet, Classification, ContextAuthority,
    ContextPacketManifest, ProactiveAction, ProactiveDecision, ProactivePolicy, ProactiveTrigger,
};

use crate::{DbError, Result};

/// One specialist task created with a work request.
#[derive(Debug, Clone, Serialize)]
pub struct NewWorkTask {
    /// Stable task identifier supplied by the orchestrator.
    pub task_id: Uuid,
    /// Optional parent task for delegation lineage.
    pub parent_task_id: Option<Uuid>,
    /// Named specialist role, such as `research_evidence`.
    pub specialist_role: String,
    /// Unique tenant-bound service identity for this assignment.
    pub service_identity_id: Uuid,
    /// Optional Nostr public key bound to the service identity.
    pub assigned_agent_pubkey: Option<Vec<u8>>,
    /// Deny-by-default capabilities required by the task.
    pub required_capabilities: Vec<String>,
    /// Snowman gateway URL; the database rejects non-Snowman routes.
    pub model_gateway_route: String,
    /// Model selected for this specialist task.
    pub model_id: String,
    /// Hard task-level cost ceiling in millionths of a US dollar.
    pub max_cost_microusd: i64,
    /// Planned task input-token reservation.
    pub expected_input_tokens: i64,
    /// Hard task output-token ceiling.
    pub max_output_tokens: i64,
    /// Digest of the exact capability/model/context/action snapshot to approve.
    pub execution_snapshot_sha256: [u8; 32],
    /// Machine-readable artifact quality and output contract.
    pub expected_artifact_contract: Value,
    /// Bounded immutable context coordinates supplied to this specialist.
    pub context_references: Vec<String>,
    /// Optional immutable context packet reference.
    pub context_packet_id: Option<Uuid>,
    /// `low`, `moderate`, `high`, or `prohibited`.
    pub risk_tier: String,
    /// Whether the action can be safely undone.
    pub reversible: bool,
    /// Whether execution must stop for a human decision.
    pub approval_required: bool,
    /// Queue priority from 0 through 100.
    pub priority: i16,
    /// Earliest time a worker may claim the task.
    pub available_at: DateTime<Utc>,
    /// Optional task deadline.
    pub deadline_at: Option<DateTime<Utc>>,
    /// Maximum execution attempts before dead-lettering.
    pub max_attempts: i32,
}

/// One durable, idempotent user work request and its initial task graph.
#[derive(Debug, Clone)]
pub struct NewWorkRequest {
    /// Stable request identifier supplied by the command center.
    pub request_id: Uuid,
    /// Raw idempotency key; only its SHA-256 digest is persisted.
    pub idempotency_key: String,
    /// Authenticated Snowman human or service subject.
    pub requester_identity: String,
    /// Digest of the complete canonical intake contract used for exact replay.
    pub request_contract_sha256: [u8; 32],
    /// User objective. Client records must not be embedded here.
    pub objective: String,
    /// `internal`, `confidential`, or `restricted`.
    pub classification: String,
    /// Optional overall deadline.
    pub deadline_at: Option<DateTime<Utc>>,
    /// Hard cost ceiling in millionths of a US dollar.
    pub max_cost_microusd: i64,
    /// Hard aggregate input-token ceiling.
    pub max_input_tokens: i64,
    /// Hard aggregate output-token ceiling.
    pub max_output_tokens: i64,
    /// Whether the final product requires independent client-ready review.
    pub client_ready_delivery: bool,
    /// Initial specialist task graph.
    pub tasks: Vec<NewWorkTask>,
}

/// A task plus its current fenced lease.
#[derive(Debug, Clone)]
pub struct LeasedWorkTask {
    /// Tenant/community scope.
    pub community_id: Uuid,
    /// Work request identifier.
    pub request_id: Uuid,
    /// Task identifier.
    pub task_id: Uuid,
    /// Worker-generated idempotency coordinate for this lease acquisition.
    pub claim_id: Uuid,
    /// User objective available only to the assigned private worker plane.
    pub objective: String,
    /// Digest of the full canonical request contract.
    pub request_contract_sha256: [u8; 32],
    /// Request data classification.
    pub classification: String,
    /// Stable request creation time used for idempotent downstream commands.
    pub request_created_at: DateTime<Utc>,
    /// Request deadline.
    pub request_deadline_at: Option<DateTime<Utc>>,
    /// Hard request cost ceiling.
    pub max_cost_microusd: i64,
    /// Hard request input-token ceiling.
    pub max_input_tokens: i64,
    /// Hard request output-token ceiling.
    pub max_output_tokens: i64,
    /// Specialist role.
    pub specialist_role: String,
    /// Tenant-bound service identity.
    pub service_identity_id: Uuid,
    /// Required capability set.
    pub required_capabilities: Vec<String>,
    /// Snowman model gateway route.
    pub model_gateway_route: String,
    /// Selected model identifier.
    pub model_id: String,
    /// Hard task-level cost ceiling.
    pub task_max_cost_microusd: i64,
    /// Planned task input-token reservation.
    pub expected_input_tokens: i64,
    /// Hard task output-token ceiling.
    pub task_max_output_tokens: i64,
    /// Digest binding any approval to this exact execution snapshot.
    pub execution_snapshot_sha256: [u8; 32],
    /// Expected work-product contract.
    pub expected_artifact_contract: Value,
    /// Immutable bounded context coordinates for this task.
    pub context_references: Vec<String>,
    /// Optional immutable context packet reference.
    pub context_packet_id: Option<Uuid>,
    /// Risk tier.
    pub risk_tier: String,
    /// Whether the action is reversible.
    pub reversible: bool,
    /// Whether a human approval is required.
    pub approval_required: bool,
    /// Monotonic lease fencing generation.
    pub lease_generation: i64,
    /// Lease expiry.
    pub lease_expires_at: DateTime<Utc>,
}

/// Spend usage associated with one model call or bounded operation.
#[derive(Debug, Clone)]
pub struct SpendEntry {
    /// Unique ledger entry identifier.
    pub ledger_entry_id: Uuid,
    /// Work request identifier.
    pub request_id: Uuid,
    /// Task identifier.
    pub task_id: Uuid,
    /// Authenticated tenant-local worker service identity.
    pub worker_identity_id: Uuid,
    /// Current lease fencing generation for first-write authorization.
    pub lease_generation: i64,
    /// Digest of the bearer lease token for first-write authorization.
    pub lease_token_sha256: [u8; 32],
    /// Model charged for the operation.
    pub model_id: String,
    /// Provider-reported input tokens.
    pub input_tokens: i64,
    /// Provider-reported output tokens.
    pub output_tokens: i64,
    /// Cost in millionths of a US dollar.
    pub cost_microusd: i64,
    /// Digest of the gateway/provider receipt, never the raw credential.
    pub provider_receipt_sha256: [u8; 32],
    /// Receipt time.
    pub recorded_at: DateTime<Utc>,
}

/// Idempotent task completion bound to one current fenced lease.
#[derive(Debug, Clone)]
pub struct WorkTaskCompletion {
    /// Stable completion/event identifier generated by the worker.
    pub completion_id: Uuid,
    /// Task being completed.
    pub task_id: Uuid,
    /// Authenticated tenant-local worker service identity.
    pub worker_identity_id: Uuid,
    /// Current lease fencing generation.
    pub generation: i64,
    /// Digest of the deterministic bearer lease token.
    pub lease_token_sha256: [u8; 32],
    /// Terminal outcome.
    pub succeeded: bool,
    /// Secret-free bounded result metadata and immutable artifact references.
    pub result_payload: Value,
    /// Worker-observed completion time.
    pub occurred_at: DateTime<Utc>,
}

/// Stable server-derived recipient snapshot for one governed reminder task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWorkReminder {
    /// Idempotent delivery coordinate supplied by the assigned reminder worker.
    pub delivery_id: Uuid,
    /// Parent request whose owner receives the reminder.
    pub request_id: Uuid,
    /// Exact leased deadline task.
    pub task_id: Uuid,
    /// Active Snowman human device keys captured on the first authorized attempt.
    pub target_pubkeys: Vec<Vec<u8>>,
    /// Stable event time, derived from the task's governed availability time.
    pub event_created_at: DateTime<Utc>,
    /// Previously recorded Nostr event ID on an exact replay.
    pub nostr_event_id: Option<[u8; 32]>,
}

/// Idempotent human cancellation of an entire governed request.
#[derive(Debug, Clone)]
pub struct WorkRequestCancellation {
    /// Stable cancellation/event identifier supplied by the command center.
    pub cancellation_id: Uuid,
    /// Request being cancelled.
    pub request_id: Uuid,
    /// Authenticated Snowman workforce human identity.
    pub actor_identity: String,
    /// Bounded machine-readable reason, never free-form client content.
    pub reason_code: String,
    /// Human-observed cancellation time.
    pub occurred_at: DateTime<Utc>,
}

/// Result of an idempotent request cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelledWorkRequest {
    /// Stable request ID.
    pub request_id: Uuid,
    /// Number of non-terminal tasks fenced and cancelled by the first call.
    pub cancelled_task_count: u64,
    /// True only when this call performed the cancellation.
    pub inserted: bool,
}

/// A human decision bound to one exact task execution snapshot.
#[derive(Debug, Clone)]
pub struct WorkApproval {
    /// Unique approval record identifier.
    pub approval_id: Uuid,
    /// Work request identifier.
    pub request_id: Uuid,
    /// Task identifier.
    pub task_id: Uuid,
    /// Digest copied from the task's immutable execution snapshot.
    pub task_snapshot_sha256: [u8; 32],
    /// `approved`, `denied`, or `revoked`.
    pub decision: String,
    /// Authenticated Snowman workforce identity making the decision.
    pub approver_identity: String,
    /// Digest of rationale retained by the governed evidence authority.
    pub rationale_sha256: [u8; 32],
    /// Decision time.
    pub decided_at: DateTime<Utc>,
    /// Hard expiry after which approval cannot authorize a claim.
    pub expires_at: DateTime<Utc>,
}

/// One immutable workforce lifecycle event. Payloads are bounded metadata and
/// artifact references, never credentials or raw client datasets.
#[derive(Debug, Clone)]
pub struct NewWorkEvent {
    /// Stable event ID supplied by the producer for idempotent correlation.
    pub event_id: Uuid,
    /// Work request identifier.
    pub request_id: Uuid,
    /// Optional specialist task identifier.
    pub task_id: Option<Uuid>,
    /// Namespaced lifecycle type such as `task.claimed`.
    pub event_type: String,
    /// Authenticated workforce or service identity.
    pub actor_identity: String,
    /// Bounded, secret-free metadata and immutable references.
    pub payload: Value,
    /// Producer-observed event time.
    pub occurred_at: DateTime<Utc>,
}

/// Hash-chain coordinates returned after an event is durably appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendedWorkEvent {
    /// Monotonic request-local sequence number.
    pub sequence: i64,
    /// Previous hash, absent only for the first event.
    pub previous_event_sha256: Option<[u8; 32]>,
    /// Digest of the domain-separated canonical event fields.
    pub event_sha256: [u8; 32],
}

/// Idempotent result of one tenant-local scheduler maintenance tick.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkforceMaintenanceResult {
    /// Server-observed transaction time used for every state transition.
    pub observed_at: DateTime<Utc>,
    /// Requests closed because their overall deadline elapsed.
    pub expired_requests: u64,
    /// Tasks closed because their request or task deadline elapsed.
    pub expired_tasks: u64,
    /// Proactive proposals closed before execution because their expiry elapsed.
    pub expired_proactive_actions: u64,
    /// Abandoned leased tasks returned to the queue with bounded backoff.
    pub requeued_tasks: u64,
    /// Abandoned leased tasks closed after exhausting their attempt cap.
    pub dead_lettered_tasks: u64,
}

/// Result of idempotently accepting a Snowman work request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnqueuedWorkRequest {
    /// Stable request ID, including when the idempotency key already existed.
    pub request_id: Uuid,
    /// True only when this call inserted the request and its initial task graph.
    pub inserted: bool,
}

/// A governed context handoff to persist for replacement specialists.
#[derive(Debug, Clone)]
pub struct NewContextPacket {
    /// Fully policy-validated metadata-only manifest.
    pub manifest: ContextPacketManifest,
    /// Authenticated tenant-local service identity publishing the handoff.
    pub created_by_identity_id: Uuid,
    /// Task whose live fenced lease authorizes this publication.
    pub source_task_id: Uuid,
    /// Current lease generation for the source task.
    pub lease_generation: i64,
    /// SHA-256 of the source task's bearer lease token.
    pub lease_token_sha256: [u8; 32],
    /// Authority-local immutable artifact identifier.
    pub artifact_id: String,
    /// Immutable artifact version or generation.
    pub artifact_version: String,
    /// Authority-local machine-readable artifact contract.
    pub artifact_type: String,
    /// Optional hard expiry for the handoff.
    pub expires_at: Option<DateTime<Utc>>,
    /// Server-observed publication time.
    pub created_at: DateTime<Utc>,
}

/// Result of idempotently publishing a governed context handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedContextPacket {
    /// Stable context packet identifier.
    pub context_packet_id: Uuid,
    /// Work request receiving the handoff.
    pub request_id: Uuid,
    /// True only when this call inserted the packet and evidence event.
    pub inserted: bool,
}

/// A validated metadata-only context handoff visible to one assigned specialist.
#[derive(Debug, Clone)]
pub struct StoredContextPacket {
    /// Policy-validated manifest; it contains no raw artifact body.
    pub manifest: ContextPacketManifest,
    /// Authority-local immutable artifact identifier.
    pub artifact_id: String,
    /// Immutable artifact version or generation.
    pub artifact_version: String,
    /// Authority-local machine-readable artifact contract.
    pub artifact_type: String,
    /// Optional hard expiry for the handoff.
    pub expires_at: Option<DateTime<Utc>>,
    /// Tenant-local service identity that published the packet.
    pub created_by_identity_id: Uuid,
    /// Digest of the canonical manifest persisted with the packet.
    pub manifest_sha256: [u8; 32],
    /// Server-observed publication time.
    pub created_at: DateTime<Utc>,
}

/// One policy-evaluated proactive action proposed by a tenant-local scheduler.
#[derive(Debug, Clone)]
pub struct NewProactiveAction {
    /// Bounded action evaluated by the shared workforce policy kernel.
    pub action: ProactiveAction,
    /// Active tenant-local service identity proposing the action.
    pub proposed_by_identity_id: Uuid,
    /// Exact policy snapshot used for the decision.
    pub policy: ProactivePolicy,
    /// Digest of the authorized schedule, signal, objective, or review event.
    pub source_event_sha256: [u8; 32],
    /// Earliest time this action may execute or request approval.
    pub scheduled_for: DateTime<Utc>,
    /// Time after which the action must not execute.
    pub expires_at: DateTime<Utc>,
    /// Server-observed proposal time.
    pub created_at: DateTime<Utc>,
    /// Complete model-routed task contract, absent only for a rejected action.
    pub execution_task: Option<NewWorkTask>,
}

/// Result of durably evaluating one proactive action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledProactiveAction {
    /// Stable action identifier.
    pub action_id: Uuid,
    /// Request/objective this action advances.
    pub request_id: Uuid,
    /// Policy outcome controlling execution.
    pub decision: ProactiveDecision,
    /// True only when the action and evidence receipt were first inserted.
    pub inserted: bool,
}

/// Human-authorized recurring work template. It contains only bounded policy
/// metadata and immutable references; instruction and client-data bodies stay
/// in their Snowman authority.
#[derive(Debug, Clone, Serialize)]
pub struct NewWorkSchedule {
    /// Stable schedule identifier.
    pub schedule_id: Uuid,
    /// Long-running request/objective advanced by each occurrence.
    pub request_id: Uuid,
    /// Authenticated human authorizing the recurrence.
    pub created_by_identity_id: Uuid,
    /// Dedicated service identity allowed to claim this schedule.
    pub trigger_identity_id: Uuid,
    /// Specialist identity that may execute materialized tasks.
    pub executor_identity_id: Uuid,
    /// Supported specialist role.
    pub specialist_role: String,
    /// Exact action capability.
    pub capability: String,
    /// Content-addressed instruction contract.
    pub instruction_reference: String,
    /// Bounded content-addressed context references.
    pub context_references: Vec<String>,
    /// Optional preferred model, still evaluated server-side at occurrence time.
    pub requested_model_id: Option<String>,
    /// Input token reservation per occurrence.
    pub expected_input_tokens: i64,
    /// Output token ceiling per occurrence.
    pub max_output_tokens: i64,
    /// Cost ceiling per occurrence.
    pub max_cost_microusd: i64,
    /// Expected artifact type.
    pub expected_artifact_type: String,
    /// Low, moderate, or high.
    pub risk_tier: String,
    /// Whether each operation is reversible.
    pub reversible: bool,
    /// Confidence of the authorized usefulness basis.
    pub confidence_basis_points: i32,
    /// Digest of the human-reviewed usefulness basis.
    pub usefulness_sha256: [u8; 32],
    /// Fixed recurrence interval, bounded to 15 minutes through 30 days.
    pub cadence_seconds: i32,
    /// First due time.
    pub next_run_at: DateTime<Utc>,
    /// Hard schedule end.
    pub ends_at: DateTime<Utc>,
    /// Maximum number of occurrences.
    pub max_occurrences: i32,
    /// Per-task retry cap.
    pub max_attempts: i32,
    /// Server-observed creation time.
    pub created_at: DateTime<Utc>,
}

/// Retryable, identity-bound schedule occurrence. It is only a proposal input;
/// the proactive policy and ordinary task machinery remain execution authority.
#[derive(Debug, Clone)]
pub struct ClaimedWorkScheduleOccurrence {
    /// Stable schedule identifier.
    pub schedule_id: Uuid,
    /// Stable occurrence identifier.
    pub occurrence_id: Uuid,
    /// Existing long-running request/objective.
    pub request_id: Uuid,
    /// Deterministic proactive action/task identifier.
    pub action_id: Uuid,
    /// Trigger claim fencing generation.
    pub claim_generation: i64,
    /// Bound executor identity.
    pub executor_identity_id: Uuid,
    /// Specialist role.
    pub specialist_role: String,
    /// Exact execution capability.
    pub capability: String,
    /// Immutable instruction reference.
    pub instruction_reference: String,
    /// Immutable context references.
    pub context_references: Vec<String>,
    /// Optional model preference.
    pub requested_model_id: Option<String>,
    /// Per-occurrence input reservation.
    pub expected_input_tokens: i64,
    /// Per-occurrence output ceiling.
    pub max_output_tokens: i64,
    /// Per-occurrence cost ceiling.
    pub max_cost_microusd: i64,
    /// Expected artifact type.
    pub expected_artifact_type: String,
    /// Risk tier.
    pub risk_tier: String,
    /// Whether the action is reversible.
    pub reversible: bool,
    /// Confidence in the usefulness basis.
    pub confidence_basis_points: i32,
    /// Human-reviewed usefulness digest.
    pub usefulness_sha256: [u8; 32],
    /// Digest of the exact authorized occurrence.
    pub source_event_sha256: [u8; 32],
    /// Stable proposal time for this claim generation.
    pub proposed_at: DateTime<Utc>,
    /// Earliest task availability.
    pub scheduled_for: DateTime<Utc>,
    /// Hard occurrence expiry.
    pub expires_at: DateTime<Utc>,
    /// Per-task retry cap.
    pub max_attempts: i32,
}

/// Server-authoritative request envelope used to govern a planner proposal.
#[derive(Debug, Clone)]
pub struct WorkPlanEnvelope {
    /// Request being expanded.
    pub request_id: Uuid,
    /// Currently leased lead planning task.
    pub lead_task_id: Uuid,
    /// Digest of the private objective text.
    pub objective_sha256: [u8; 32],
    /// Server-owned data classification.
    pub classification: String,
    /// Whether independent downstream review is mandatory.
    pub client_ready_delivery: bool,
    /// Server-owned request deadline.
    pub deadline_at: Option<DateTime<Utc>>,
    /// Remaining request cost ceiling.
    pub max_cost_microusd: i64,
    /// Remaining request input-token ceiling.
    pub max_input_tokens: i64,
    /// Remaining request output-token ceiling.
    pub max_output_tokens: i64,
}

/// One evaluated model route provisioned for a tenant by Snowman operations.
#[derive(Debug, Clone)]
pub struct StoredModelRoute {
    /// Stable model identifier understood by the Snowman gateway.
    pub model_id: String,
    /// Snowman-controlled gateway URL.
    pub gateway_url: String,
    /// Specialist roles evaluated for this route.
    pub suited_roles: Vec<String>,
    /// Data classifications the route may process.
    pub allowed_classifications: Vec<String>,
    /// Controlled-evaluation quality score.
    pub quality_score: i32,
    /// Controlled-evaluation latency score.
    pub latency_score: i32,
    /// Conservative blended cost ceiling.
    pub max_cost_microusd_per_million_tokens: i64,
    /// Maximum accepted context size.
    pub max_context_tokens: i64,
}

/// One specialist task plus its complete DAG and context coordinates.
#[derive(Debug, Clone)]
pub struct NewPlannedTask {
    /// Fully governed task record.
    pub task: NewWorkTask,
    /// In-plan prerequisites that must succeed first.
    pub depends_on: Vec<Uuid>,
}

/// Exact governed plan committed by the currently leased lead task.
#[derive(Debug, Clone)]
pub struct NewWorkPlan {
    /// Idempotent plan identifier.
    pub plan_id: Uuid,
    /// Request being expanded.
    pub request_id: Uuid,
    /// Lead planning task consumed by the expansion.
    pub lead_task_id: Uuid,
    /// Authenticated lead service identity.
    pub planner_identity_id: Uuid,
    /// Current lease fencing generation.
    pub lease_generation: i64,
    /// Digest of the current bearer lease token.
    pub lease_token_sha256: [u8; 32],
    /// Canonical digest of the governed plan and authority coordinates.
    pub plan_sha256: [u8; 32],
    /// Specialist DAG to persist.
    pub tasks: Vec<NewPlannedTask>,
    /// Server-observed commit time.
    pub committed_at: DateTime<Utc>,
}

/// Idempotent result of a governed specialist plan commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedWorkPlan {
    /// Stable committed plan identifier.
    pub plan_id: Uuid,
    /// Stable request identifier.
    pub request_id: Uuid,
    /// Specialist task count in the plan.
    pub task_count: usize,
    /// True for the first commit and false for an exact replay.
    pub inserted: bool,
}

/// Governed request status returned to authorized command-center callers.
#[derive(Debug, Clone, Serialize)]
pub struct WorkRequestStatus {
    /// Stable request ID.
    pub request_id: Uuid,
    /// Digest of the objective retained for evidence correlation.
    pub objective_sha256: String,
    /// Digest of the complete canonical intake contract.
    pub request_contract_sha256: String,
    /// Data classification applied to this request.
    pub classification: String,
    /// Whether an independent client-ready review is required.
    pub client_ready_delivery: bool,
    /// Aggregate lifecycle status.
    pub status: String,
    /// Optional user deadline.
    pub deadline_at: Option<DateTime<Utc>>,
    /// Hard request budget in millionths of a US dollar.
    pub max_cost_microusd: i64,
    /// Spend recorded so far.
    pub used_cost_microusd: i64,
    /// Hard input-token ceiling.
    pub max_input_tokens: i64,
    /// Input tokens recorded so far.
    pub used_input_tokens: i64,
    /// Hard output-token ceiling.
    pub max_output_tokens: i64,
    /// Output tokens recorded so far.
    pub used_output_tokens: i64,
    /// Current specialist task state.
    pub tasks: Vec<WorkTaskStatus>,
    /// Bounded lifecycle evidence, ordered by request-local sequence.
    pub events: Vec<WorkEventStatus>,
    /// Total event count. The response carries at most the newest 200 events.
    pub event_count: i64,
    /// Request creation time.
    pub created_at: DateTime<Utc>,
    /// Last aggregate status change.
    pub updated_at: DateTime<Utc>,
}

/// One specialist task in an authorized status response.
#[derive(Debug, Clone, Serialize)]
pub struct WorkTaskStatus {
    /// Stable task ID.
    pub task_id: Uuid,
    /// Delegation parent, when present.
    pub parent_task_id: Option<Uuid>,
    /// Named specialist role.
    pub specialist_role: String,
    /// Selected model, invoked only through the Snowman model gateway.
    pub model_id: String,
    /// Hard task-level cost ceiling in millionths of a US dollar.
    pub max_cost_microusd: i64,
    /// Planned task input-token reservation.
    pub expected_input_tokens: i64,
    /// Hard task output-token ceiling.
    pub max_output_tokens: i64,
    /// Deny-by-default task capability set.
    pub required_capabilities: Vec<String>,
    /// Machine-readable expected work product.
    pub expected_artifact_contract: Value,
    /// Immutable context coordinates available to the specialist.
    pub context_references: Vec<String>,
    /// Immutable Analyst 360 or Snowman context packet reference.
    pub context_packet_id: Option<Uuid>,
    /// Risk classification.
    pub risk_tier: String,
    /// Whether work can be undone safely.
    pub reversible: bool,
    /// Whether execution is stopped at a human gate.
    pub approval_required: bool,
    /// Current task lifecycle status.
    pub status: String,
    /// Execution attempts consumed.
    pub attempt_count: i32,
    /// Maximum execution attempts.
    pub max_attempts: i32,
    /// Optional task deadline.
    pub deadline_at: Option<DateTime<Utc>>,
    /// Immutable execution snapshot digest.
    pub execution_snapshot_sha256: String,
}

/// One hash-chained lifecycle event safe for the command-center response.
#[derive(Debug, Clone, Serialize)]
pub struct WorkEventStatus {
    /// Stable event ID.
    pub event_id: Uuid,
    /// Optional task ID.
    pub task_id: Option<Uuid>,
    /// Monotonic request-local sequence.
    pub sequence: i64,
    /// Namespaced lifecycle event type.
    pub event_type: String,
    /// Stable Snowman workforce actor identifier.
    pub actor_identity: String,
    /// Bounded metadata and immutable artifact references.
    pub payload: Value,
    /// Previous event digest, absent for the genesis event.
    pub previous_event_sha256: Option<String>,
    /// This event's evidence digest.
    pub event_sha256: String,
    /// Producer-observed event time.
    pub occurred_at: DateTime<Utc>,
}

/// Insert a work request and its initial task graph exactly once.
///
/// Reusing an idempotency key with the same objective returns the original
/// request ID. Reusing it with different content fails closed.
pub async fn enqueue_work_request(
    pool: &PgPool,
    community_id: CommunityId,
    request: &NewWorkRequest,
) -> Result<EnqueuedWorkRequest> {
    validate_new_request(request)?;
    let community_id = *community_id.as_uuid();
    let idempotency_digest = sha256(request.idempotency_key.as_bytes());
    let objective_digest = sha256(request.objective.as_bytes());
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query(
        r#"
        INSERT INTO snowman_work_requests
          (community_id, request_id, idempotency_key_sha256, requester_identity,
           objective, objective_sha256, request_contract_sha256, classification,
           status, deadline_at, max_cost_microusd, max_input_tokens, max_output_tokens,
           client_ready_delivery)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'requested',$9,$10,$11,$12,$13)
        ON CONFLICT (community_id, idempotency_key_sha256) DO NOTHING
        RETURNING request_id
        "#,
    )
    .bind(community_id)
    .bind(request.request_id)
    .bind(idempotency_digest.as_slice())
    .bind(&request.requester_identity)
    .bind(&request.objective)
    .bind(objective_digest.as_slice())
    .bind(request.request_contract_sha256.as_slice())
    .bind(&request.classification)
    .bind(request.deadline_at)
    .bind(request.max_cost_microusd)
    .bind(request.max_input_tokens)
    .bind(request.max_output_tokens)
    .bind(request.client_ready_delivery)
    .fetch_optional(&mut *tx)
    .await?;

    if inserted.is_none() {
        let existing = sqlx::query(
            "SELECT request_id, objective_sha256, request_contract_sha256, requester_identity, classification, deadline_at, \
                    max_cost_microusd, max_input_tokens, max_output_tokens, client_ready_delivery \
             FROM snowman_work_requests \
             WHERE community_id=$1 AND idempotency_key_sha256=$2",
        )
        .bind(community_id)
        .bind(idempotency_digest.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        let existing_digest: Vec<u8> = existing.try_get("objective_sha256")?;
        let exact_replay = existing_digest.as_slice() == objective_digest.as_slice()
            && existing
                .try_get::<Vec<u8>, _>("request_contract_sha256")?
                .as_slice()
                == request.request_contract_sha256.as_slice()
            && existing.try_get::<String, _>("requester_identity")? == request.requester_identity
            && existing.try_get::<String, _>("classification")? == request.classification
            && existing.try_get::<Option<DateTime<Utc>>, _>("deadline_at")? == request.deadline_at
            && existing.try_get::<i64, _>("max_cost_microusd")? == request.max_cost_microusd
            && existing.try_get::<i64, _>("max_input_tokens")? == request.max_input_tokens
            && existing.try_get::<i64, _>("max_output_tokens")? == request.max_output_tokens;
        let exact_replay = exact_replay
            && existing.try_get::<bool, _>("client_ready_delivery")?
                == request.client_ready_delivery;
        if !exact_replay {
            return Err(DbError::AccessDenied(
                "Snowman workforce idempotency key was reused for a different request".into(),
            ));
        }
        let existing_id: Uuid = existing.try_get("request_id")?;
        tx.commit().await?;
        return Ok(EnqueuedWorkRequest {
            request_id: existing_id,
            inserted: false,
        });
    }

    for task in &request.tasks {
        insert_task(&mut tx, community_id, request.request_id, task).await?;
    }
    let accepted_at = Utc::now();
    let accepted_event = NewWorkEvent {
        event_id: request.request_id,
        request_id: request.request_id,
        task_id: None,
        event_type: "request.accepted".to_string(),
        actor_identity: request.requester_identity.clone(),
        payload: serde_json::json!({
            "schema_version": "snowman.work.event.v1",
            "classification": request.classification,
            "objective_sha256": hex::encode(objective_digest),
            "request_contract_sha256": hex::encode(request.request_contract_sha256),
            "initial_task_count": request.tasks.len(),
        }),
        occurred_at: accepted_at,
    };
    validate_work_event(&accepted_event)?;
    let accepted_digest = work_event_digest(community_id, 0, None, &accepted_event)?;
    sqlx::query(
        r#"
        INSERT INTO snowman_work_events
          (community_id, event_id, request_id, task_id, sequence, event_type,
           actor_identity, payload, previous_event_sha256, event_sha256, occurred_at)
        VALUES ($1,$2,$3,NULL,0,$4,$5,$6,NULL,$7,$8)
        "#,
    )
    .bind(community_id)
    .bind(accepted_event.event_id)
    .bind(accepted_event.request_id)
    .bind(&accepted_event.event_type)
    .bind(&accepted_event.actor_identity)
    .bind(&accepted_event.payload)
    .bind(accepted_digest.as_slice())
    .bind(accepted_event.occurred_at)
    .execute(&mut *tx)
    .await?;
    refresh_request_status(&mut tx, community_id, request.request_id).await?;
    tx.commit().await?;
    Ok(EnqueuedWorkRequest {
        request_id: request.request_id,
        inserted: true,
    })
}

/// Load the server-owned request constraints a lead planner may not override.
pub async fn work_plan_envelope(
    pool: &PgPool,
    community_id: CommunityId,
    request_id: Uuid,
    lead_task_id: Uuid,
) -> Result<Option<WorkPlanEnvelope>> {
    let row = sqlx::query(
        r#"
        SELECT r.request_id, r.objective_sha256, r.classification,
               r.client_ready_delivery, r.deadline_at,
               GREATEST(r.max_cost_microusd - COALESCE(SUM(s.cost_microusd),0),0)::bigint AS max_cost_microusd,
               GREATEST(r.max_input_tokens - COALESCE(SUM(s.input_tokens),0),0)::bigint AS max_input_tokens,
               GREATEST(r.max_output_tokens - COALESCE(SUM(s.output_tokens),0),0)::bigint AS max_output_tokens,
               t.task_id AS lead_task_id
        FROM snowman_work_requests r
        JOIN snowman_work_tasks t
          ON t.community_id=r.community_id AND t.request_id=r.request_id
         AND t.task_id=$3 AND t.specialist_role='lead'
        LEFT JOIN snowman_spend_ledger s
          ON s.community_id=r.community_id AND s.request_id=r.request_id
        WHERE r.community_id=$1 AND r.request_id=$2
          AND r.status NOT IN ('completed','failed','cancelled','expired')
        GROUP BY r.community_id, r.request_id, t.community_id, t.task_id
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(request_id)
    .bind(lead_task_id)
    .fetch_optional(pool)
    .await?;
    row.map(|row| -> Result<WorkPlanEnvelope> {
        Ok(WorkPlanEnvelope {
            request_id: row.try_get("request_id")?,
            lead_task_id: row.try_get("lead_task_id")?,
            objective_sha256: vec_to_sha256(row.try_get("objective_sha256")?)?,
            classification: row.try_get("classification")?,
            client_ready_delivery: row.try_get("client_ready_delivery")?,
            deadline_at: row.try_get("deadline_at")?,
            max_cost_microusd: row.try_get("max_cost_microusd")?,
            max_input_tokens: row.try_get("max_input_tokens")?,
            max_output_tokens: row.try_get("max_output_tokens")?,
        })
    })
    .transpose()
}

/// Load only active, evaluated, tenant-local model routes.
pub async fn active_model_routes(
    pool: &PgPool,
    community_id: CommunityId,
) -> Result<Vec<StoredModelRoute>> {
    sqlx::query(
        r#"
        SELECT model_id, gateway_url, suited_roles, allowed_classifications,
               quality_score, latency_score,
               max_cost_microusd_per_million_tokens, max_context_tokens
        FROM snowman_model_routes
        WHERE community_id=$1 AND status='active' AND evaluated_at <= NOW()
        ORDER BY model_id
        "#,
    )
    .bind(community_id.as_uuid())
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| -> Result<StoredModelRoute> {
        Ok(StoredModelRoute {
            model_id: row.try_get("model_id")?,
            gateway_url: row.try_get("gateway_url")?,
            suited_roles: row.try_get("suited_roles")?,
            allowed_classifications: row.try_get("allowed_classifications")?,
            quality_score: row.try_get("quality_score")?,
            latency_score: row.try_get("latency_score")?,
            max_cost_microusd_per_million_tokens: row
                .try_get("max_cost_microusd_per_million_tokens")?,
            max_context_tokens: row.try_get("max_context_tokens")?,
        })
    })
    .collect()
}

/// Persist a bounded context handoff and its lifecycle receipt exactly once.
pub async fn publish_context_packet(
    pool: &PgPool,
    community_id: CommunityId,
    packet: &NewContextPacket,
) -> Result<PublishedContextPacket> {
    validate_context_packet(&packet.manifest)
        .map_err(|error| DbError::InvalidData(error.to_string()))?;
    if packet.manifest.community_id != *community_id.as_uuid()
        || packet.created_by_identity_id.is_nil()
        || packet.source_task_id.is_nil()
        || packet.lease_generation <= 0
        || packet.lease_token_sha256 == [0; 32]
        || packet.artifact_id.trim() != packet.artifact_id
        || packet.artifact_id.is_empty()
        || packet.artifact_id.len() > 512
        || packet.artifact_version.trim() != packet.artifact_version
        || packet.artifact_version.is_empty()
        || packet.artifact_version.len() > 256
        || packet.artifact_type.trim() != packet.artifact_type
        || packet.artifact_type.is_empty()
        || packet.artifact_type.len() > 128
        || packet
            .expires_at
            .is_some_and(|expires_at| expires_at <= packet.created_at)
    {
        return Err(DbError::InvalidData(
            "context packet publisher, artifact, tenant, or expiry is invalid".into(),
        ));
    }
    let manifest_json = serde_json::to_value(&packet.manifest)
        .map_err(|error| DbError::InvalidData(format!("context manifest is invalid: {error}")))?;
    let manifest_bytes = serde_json::to_vec(&packet.manifest)
        .map_err(|error| DbError::InvalidData(format!("context manifest is invalid: {error}")))?;
    let manifest_sha256 = sha256(&manifest_bytes);
    let community_id = *community_id.as_uuid();
    let authority = context_authority_name(packet.manifest.authority);
    let classification = classification_name(packet.manifest.classification);
    let mut tx = pool.begin().await?;
    let lease_authorized: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1
          FROM snowman_work_requests r
          JOIN snowman_work_tasks t
            ON t.community_id=r.community_id AND t.request_id=r.request_id
          JOIN snowman_task_leases l
            ON l.community_id=t.community_id AND l.task_id=t.task_id
          JOIN snowman_workforce_identities i
            ON i.community_id=t.community_id AND i.identity_id=t.service_identity_id
          JOIN snowman_workforce_capability_grants g
            ON g.community_id=i.community_id AND g.identity_id=i.identity_id
          WHERE r.community_id=$1 AND r.request_id=$2
            AND r.status NOT IN ('cancelled', 'expired')
            AND t.task_id=$3 AND t.service_identity_id=$4
            AND t.status IN ('leased', 'running')
            AND l.worker_identity_id=$4 AND l.generation=$5
            AND l.lease_token_sha256=$6 AND l.expires_at > NOW()
            AND i.identity_type='service' AND i.role='agent'
            AND i.status='active' AND i.revoked_at IS NULL
            AND (i.expires_at IS NULL OR i.expires_at > NOW())
            AND g.capability='workforce.context.write'
            AND g.revoked_at IS NULL
            AND (g.expires_at IS NULL OR g.expires_at > NOW())
        )
        "#,
    )
    .bind(community_id)
    .bind(packet.manifest.request_id)
    .bind(packet.source_task_id)
    .bind(packet.created_by_identity_id)
    .bind(packet.lease_generation)
    .bind(packet.lease_token_sha256.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if !lease_authorized {
        return Err(DbError::AccessDenied(
            "context publication requires the publisher's live fenced task lease".into(),
        ));
    }
    let existing = sqlx::query(
        r#"
        SELECT p.request_id, p.authority, p.artifact_id, p.artifact_version, p.artifact_type,
               p.content_sha256, p.size_bytes, p.expires_at,
               m.created_by_identity_id, m.manifest_sha256, m.created_at
        FROM snowman_context_packets p
        JOIN snowman_context_packet_manifests m
          ON m.community_id=p.community_id AND m.context_packet_id=p.context_packet_id
        WHERE p.community_id=$1 AND p.context_packet_id=$2
        "#,
    )
    .bind(community_id)
    .bind(packet.manifest.context_packet_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        let exact = existing.try_get::<Uuid, _>("request_id")? == packet.manifest.request_id
            && existing.try_get::<String, _>("authority")? == authority
            && existing.try_get::<String, _>("artifact_id")? == packet.artifact_id
            && existing.try_get::<String, _>("artifact_version")? == packet.artifact_version
            && existing.try_get::<String, _>("artifact_type")? == packet.artifact_type
            && existing.try_get::<Vec<u8>, _>("content_sha256")?.as_slice()
                == packet.manifest.content_sha256.as_slice()
            && existing.try_get::<i64, _>("size_bytes")?
                == i64::try_from(packet.manifest.size_bytes).unwrap_or(i64::MAX)
            && existing.try_get::<Option<DateTime<Utc>>, _>("expires_at")? == packet.expires_at
            && existing.try_get::<Uuid, _>("created_by_identity_id")?
                == packet.created_by_identity_id
            && existing
                .try_get::<Vec<u8>, _>("manifest_sha256")?
                .as_slice()
                == manifest_sha256.as_slice()
            && existing.try_get::<DateTime<Utc>, _>("created_at")? == packet.created_at;
        if exact {
            tx.commit().await?;
            return Ok(PublishedContextPacket {
                context_packet_id: packet.manifest.context_packet_id,
                request_id: packet.manifest.request_id,
                inserted: false,
            });
        }
        return Err(DbError::AccessDenied(
            "context packet identifier was reused for different evidence".into(),
        ));
    }
    let authority_row = sqlx::query(
        r#"
        SELECT r.objective_sha256, r.classification, r.status,
               EXISTS (
                 SELECT 1 FROM snowman_workforce_identities i
                 WHERE i.community_id=r.community_id AND i.identity_id=$3
                   AND i.identity_type='service' AND i.role='agent'
                   AND i.status='active' AND i.revoked_at IS NULL
                   AND (i.expires_at IS NULL OR i.expires_at > NOW())
                   AND EXISTS (
                     SELECT 1 FROM snowman_workforce_capability_grants g
                     WHERE g.community_id=i.community_id AND g.identity_id=i.identity_id
                       AND g.capability='workforce.context.write'
                       AND g.revoked_at IS NULL
                       AND (g.expires_at IS NULL OR g.expires_at > NOW())
                   )
               ) AND EXISTS (
                 SELECT 1 FROM snowman_work_tasks t
                 WHERE t.community_id=r.community_id AND t.request_id=r.request_id
                   AND t.service_identity_id=$3
                   AND t.status IN ('queued', 'leased', 'running', 'awaiting_approval', 'reviewing')
               ) AS publisher_authorized
        FROM snowman_work_requests r
        WHERE r.community_id=$1 AND r.request_id=$2
        FOR UPDATE
        "#,
    )
    .bind(community_id)
    .bind(packet.manifest.request_id)
    .bind(packet.created_by_identity_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| DbError::InvalidData("context packet request was not found".into()))?;
    if authority_row
        .try_get::<Vec<u8>, _>("objective_sha256")?
        .as_slice()
        != packet.manifest.objective_sha256.as_slice()
        || authority_row.try_get::<String, _>("classification")? != classification
        || matches!(
            authority_row.try_get::<String, _>("status")?.as_str(),
            "cancelled" | "expired"
        )
        || !authority_row.try_get::<bool, _>("publisher_authorized")?
    {
        return Err(DbError::AccessDenied(
            "context packet does not match request or publisher authority".into(),
        ));
    }
    sqlx::query(
        r#"
        INSERT INTO snowman_context_packets
          (community_id, context_packet_id, request_id, schema_version,
           classification, authority, artifact_id, artifact_version, artifact_type,
           content_sha256, size_bytes, expires_at, created_at)
        VALUES ($1,$2,$3,'snowman.workforce.context.v1',$4,$5,$6,$7,$8,$9,$10,$11,$12)
        "#,
    )
    .bind(community_id)
    .bind(packet.manifest.context_packet_id)
    .bind(packet.manifest.request_id)
    .bind(classification)
    .bind(authority)
    .bind(&packet.artifact_id)
    .bind(&packet.artifact_version)
    .bind(&packet.artifact_type)
    .bind(packet.manifest.content_sha256.as_slice())
    .bind(
        i64::try_from(packet.manifest.size_bytes).map_err(|_| {
            DbError::InvalidData("context packet size exceeds database bounds".into())
        })?,
    )
    .bind(packet.expires_at)
    .bind(packet.created_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO snowman_context_packet_manifests
          (community_id, context_packet_id, request_id, created_by_identity_id,
           objective_sha256, content_reference, source_event_sha256,
           manifest_sha256, artifact_references, evidence_references,
           decision_digests, open_question_digests, next_actions, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        "#,
    )
    .bind(community_id)
    .bind(packet.manifest.context_packet_id)
    .bind(packet.manifest.request_id)
    .bind(packet.created_by_identity_id)
    .bind(packet.manifest.objective_sha256.as_slice())
    .bind(&packet.manifest.content_reference)
    .bind(packet.manifest.source_event_sha256.as_slice())
    .bind(manifest_sha256.as_slice())
    .bind(
        packet
            .manifest
            .artifact_references
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .bind(
        packet
            .manifest
            .evidence_references
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .bind(
        packet
            .manifest
            .decision_digests
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .bind(
        packet
            .manifest
            .open_question_digests
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    )
    .bind(manifest_json["next_actions"].clone())
    .bind(packet.created_at)
    .execute(&mut *tx)
    .await?;
    let event = NewWorkEvent {
        event_id: packet.manifest.context_packet_id,
        request_id: packet.manifest.request_id,
        task_id: Some(packet.source_task_id),
        event_type: "context.published".into(),
        actor_identity: format!("snowman-service:{}", packet.created_by_identity_id),
        payload: serde_json::json!({
            "schema_version": "snowman.work.event.v1",
            "context_reference": packet.manifest.content_reference,
            "content_sha256": hex::encode(packet.manifest.content_sha256),
            "manifest_sha256": hex::encode(manifest_sha256),
            "source_event_sha256": hex::encode(packet.manifest.source_event_sha256),
            "artifact_reference_count": packet.manifest.artifact_references.len(),
            "evidence_reference_count": packet.manifest.evidence_references.len(),
            "next_action_count": packet.manifest.next_actions.len(),
        }),
        occurred_at: packet.created_at,
    };
    validate_work_event(&event)?;
    append_work_event_tx(&mut tx, community_id, &event).await?;
    tx.commit().await?;
    Ok(PublishedContextPacket {
        context_packet_id: packet.manifest.context_packet_id,
        request_id: packet.manifest.request_id,
        inserted: true,
    })
}

/// Load current, non-expired handoffs for an active specialist assignment.
///
/// Both identity capability and request assignment are re-evaluated in the
/// same statement that reads the packets. Revocation therefore closes access
/// without relying solely on the HTTP authorization layer.
pub async fn list_context_packets(
    pool: &PgPool,
    community_id: CommunityId,
    request_id: Uuid,
    reader_identity_id: Uuid,
) -> Result<Vec<StoredContextPacket>> {
    if request_id.is_nil() || reader_identity_id.is_nil() {
        return Err(DbError::InvalidData(
            "context packet reader or request is invalid".into(),
        ));
    }
    let rows = sqlx::query(
        r#"
        SELECT p.context_packet_id, p.classification, p.authority,
               p.artifact_id, p.artifact_version, p.artifact_type, p.content_sha256,
               p.size_bytes, p.expires_at, p.created_at,
               m.created_by_identity_id, m.objective_sha256,
               m.content_reference, m.source_event_sha256, m.manifest_sha256,
               m.artifact_references, m.evidence_references,
               m.decision_digests, m.open_question_digests, m.next_actions
        FROM snowman_context_packets p
        JOIN snowman_context_packet_manifests m
          ON m.community_id=p.community_id AND m.context_packet_id=p.context_packet_id
        JOIN snowman_work_requests r
          ON r.community_id=p.community_id AND r.request_id=p.request_id
        WHERE p.community_id=$1 AND p.request_id=$2
          AND (p.expires_at IS NULL OR p.expires_at > NOW())
          AND r.status NOT IN ('cancelled', 'expired')
          AND EXISTS (
            SELECT 1 FROM snowman_workforce_identities i
            JOIN snowman_workforce_capability_grants g
              ON g.community_id=i.community_id AND g.identity_id=i.identity_id
            WHERE i.community_id=p.community_id AND i.identity_id=$3
              AND i.identity_type='service' AND i.role='agent'
              AND i.status='active' AND i.revoked_at IS NULL
              AND (i.expires_at IS NULL OR i.expires_at > NOW())
              AND g.capability='workforce.context.read'
              AND g.revoked_at IS NULL
              AND (g.expires_at IS NULL OR g.expires_at > NOW())
          )
          AND EXISTS (
            SELECT 1 FROM snowman_work_tasks t
            WHERE t.community_id=p.community_id AND t.request_id=p.request_id
              AND t.service_identity_id=$3
              AND t.status IN ('queued', 'leased', 'running', 'awaiting_approval', 'reviewing')
          )
        ORDER BY p.created_at, p.context_packet_id
        LIMIT 128
        "#,
    )
    .bind(*community_id.as_uuid())
    .bind(request_id)
    .bind(reader_identity_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let classification =
                parse_classification_name(&row.try_get::<String, _>("classification")?)?;
            let authority = parse_context_authority_name(&row.try_get::<String, _>("authority")?)?;
            let next_actions = serde_json::from_value(row.try_get::<Value, _>("next_actions")?)
                .map_err(|error| {
                    DbError::InvalidData(format!(
                        "stored context next actions are invalid: {error}"
                    ))
                })?;
            let size_bytes = u64::try_from(row.try_get::<i64, _>("size_bytes")?)
                .map_err(|_| DbError::InvalidData("stored context size is negative".into()))?;
            let manifest = ContextPacketManifest {
                context_packet_id: row.try_get("context_packet_id")?,
                request_id,
                community_id: *community_id.as_uuid(),
                classification,
                authority,
                objective_sha256: vec_to_sha256(row.try_get("objective_sha256")?)?,
                content_reference: row.try_get("content_reference")?,
                content_sha256: vec_to_sha256(row.try_get("content_sha256")?)?,
                source_event_sha256: vec_to_sha256(row.try_get("source_event_sha256")?)?,
                size_bytes,
                artifact_references: row
                    .try_get::<Vec<String>, _>("artifact_references")?
                    .into_iter()
                    .collect(),
                evidence_references: row
                    .try_get::<Vec<String>, _>("evidence_references")?
                    .into_iter()
                    .collect(),
                decision_digests: row
                    .try_get::<Vec<String>, _>("decision_digests")?
                    .into_iter()
                    .collect(),
                open_question_digests: row
                    .try_get::<Vec<String>, _>("open_question_digests")?
                    .into_iter()
                    .collect(),
                next_actions,
            };
            validate_context_packet(&manifest)
                .map_err(|error| DbError::InvalidData(error.to_string()))?;
            Ok(StoredContextPacket {
                manifest,
                artifact_id: row.try_get("artifact_id")?,
                artifact_version: row.try_get("artifact_version")?,
                artifact_type: row.try_get("artifact_type")?,
                expires_at: row.try_get("expires_at")?,
                created_by_identity_id: row.try_get("created_by_identity_id")?,
                manifest_sha256: vec_to_sha256(row.try_get("manifest_sha256")?)?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}

/// Idempotently persist one bounded recurring-work authorization.
pub async fn create_work_schedule(
    pool: &PgPool,
    community_id: CommunityId,
    schedule: &NewWorkSchedule,
) -> Result<bool> {
    if schedule.schedule_id.is_nil()
        || schedule.request_id.is_nil()
        || schedule.created_by_identity_id.is_nil()
        || schedule.trigger_identity_id.is_nil()
        || schedule.executor_identity_id.is_nil()
        || !valid_proactive_execution(&schedule.specialist_role, &schedule.capability)
        || !is_context_reference(&schedule.instruction_reference)
        || schedule.context_references.len() >= 64
        || schedule
            .context_references
            .iter()
            .any(|reference| !is_context_reference(reference))
        || !(1..=20_000_000).contains(&schedule.expected_input_tokens)
        || !(1..=5_000_000).contains(&schedule.max_output_tokens)
        || !(0..=500_000_000).contains(&schedule.max_cost_microusd)
        || schedule.expected_artifact_type.trim().is_empty()
        || schedule.expected_artifact_type.len() > 128
        || !matches!(schedule.risk_tier.as_str(), "low" | "moderate" | "high")
        || (!schedule.reversible && schedule.risk_tier == "low")
        || !(0..=10_000).contains(&schedule.confidence_basis_points)
        || schedule.usefulness_sha256 == [0; 32]
        || !(900..=2_592_000).contains(&schedule.cadence_seconds)
        || schedule.created_at > schedule.next_run_at
        || schedule.ends_at <= schedule.next_run_at
        || schedule.ends_at > schedule.created_at + Duration::days(366)
        || !(1..=366).contains(&schedule.max_occurrences)
        || !(1..=20).contains(&schedule.max_attempts)
        || schedule
            .requested_model_id
            .as_ref()
            .is_some_and(|model| model.trim().is_empty() || model.len() > 128)
    {
        return Err(DbError::InvalidData(
            "work schedule violates bounded recurrence or execution policy".into(),
        ));
    }
    let mut references = schedule.context_references.clone();
    references.push(schedule.instruction_reference.clone());
    references.sort();
    references.dedup();
    if references.len() > 64 {
        return Err(DbError::AccessDenied(
            "work schedule exceeds the immutable context-reference limit".into(),
        ));
    }
    let canonical = serde_json::to_vec(schedule)
        .map_err(|error| DbError::InvalidData(format!("work schedule is invalid: {error}")))?;
    let schedule_sha256 = sha256(&canonical);
    let mut tx = pool.begin().await?;
    let authorization = sqlx::query(
        r#"
        SELECT r.status,
          EXISTS (
            SELECT 1 FROM snowman_workforce_identities i
            JOIN snowman_workforce_capability_grants g
              ON g.community_id=i.community_id AND g.identity_id=i.identity_id
            WHERE i.community_id=$1 AND i.identity_id=$3 AND i.identity_type='human'
              AND i.status='active' AND i.revoked_at IS NULL
              AND (i.expires_at IS NULL OR i.expires_at > NOW())
              AND g.capability='workforce.schedules.manage' AND g.revoked_at IS NULL
              AND (g.expires_at IS NULL OR g.expires_at > NOW())
          ) AS creator_ready,
          NOT EXISTS (
            SELECT 1 FROM unnest(ARRAY['workforce.schedules.trigger','workforce.proactive.propose']) required(capability)
            WHERE NOT EXISTS (
              SELECT 1 FROM snowman_workforce_identities i
              JOIN snowman_workforce_capability_grants g
                ON g.community_id=i.community_id AND g.identity_id=i.identity_id
              WHERE i.community_id=$1 AND i.identity_id=$4 AND i.identity_type='service'
                AND i.role='agent' AND i.status='active' AND i.revoked_at IS NULL
                AND (i.expires_at IS NULL OR i.expires_at > NOW())
                AND g.capability=required.capability AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at > NOW())
            )
          ) AS trigger_ready,
          NOT EXISTS (
            SELECT 1 FROM unnest(ARRAY[$6::text,'workforce.context.write']) required(capability)
            WHERE NOT EXISTS (
              SELECT 1 FROM snowman_workforce_identities i
              JOIN snowman_workforce_capability_grants g
                ON g.community_id=i.community_id AND g.identity_id=i.identity_id
              WHERE i.community_id=$1 AND i.identity_id=$5 AND i.identity_type='service'
                AND i.role='agent' AND i.status='active' AND i.revoked_at IS NULL
                AND (i.expires_at IS NULL OR i.expires_at > NOW())
                AND g.capability=required.capability AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at > NOW())
            )
          ) AS executor_ready
        FROM snowman_work_requests r
        WHERE r.community_id=$1 AND r.request_id=$2
        FOR UPDATE
        "#,
    )
    .bind(*community_id.as_uuid())
    .bind(schedule.request_id)
    .bind(schedule.created_by_identity_id)
    .bind(schedule.trigger_identity_id)
    .bind(schedule.executor_identity_id)
    .bind(&schedule.capability)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| DbError::InvalidData("scheduled work request was not found".into()))?;
    if !matches!(
        authorization.try_get::<String, _>("status")?.as_str(),
        "requested" | "planned" | "running" | "awaiting_approval" | "reviewing"
    ) || !authorization.try_get::<bool, _>("creator_ready")?
        || !authorization.try_get::<bool, _>("trigger_ready")?
        || !authorization.try_get::<bool, _>("executor_ready")?
    {
        return Err(DbError::AccessDenied(
            "schedule creator, trigger, executor, or request lifecycle is not authorized".into(),
        ));
    }
    let inserted = sqlx::query(
        r#"
        INSERT INTO snowman_work_schedules
          (community_id, schedule_id, request_id, created_by_identity_id,
           trigger_identity_id, executor_identity_id, specialist_role, capability,
           instruction_reference, context_references, requested_model_id,
           expected_input_tokens, max_output_tokens, max_cost_microusd,
           expected_artifact_type, risk_tier, reversible, confidence_basis_points,
           usefulness_sha256, cadence_seconds, next_run_at, ends_at,
           max_occurrences, max_attempts, schedule_sha256, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$26)
        ON CONFLICT (community_id, schedule_id) DO NOTHING
        "#,
    )
    .bind(*community_id.as_uuid())
    .bind(schedule.schedule_id)
    .bind(schedule.request_id)
    .bind(schedule.created_by_identity_id)
    .bind(schedule.trigger_identity_id)
    .bind(schedule.executor_identity_id)
    .bind(&schedule.specialist_role)
    .bind(&schedule.capability)
    .bind(&schedule.instruction_reference)
    .bind(&references)
    .bind(&schedule.requested_model_id)
    .bind(schedule.expected_input_tokens)
    .bind(schedule.max_output_tokens)
    .bind(schedule.max_cost_microusd)
    .bind(&schedule.expected_artifact_type)
    .bind(&schedule.risk_tier)
    .bind(schedule.reversible)
    .bind(schedule.confidence_basis_points)
    .bind(schedule.usefulness_sha256.as_slice())
    .bind(schedule.cadence_seconds)
    .bind(schedule.next_run_at)
    .bind(schedule.ends_at)
    .bind(schedule.max_occurrences)
    .bind(schedule.max_attempts)
    .bind(schedule_sha256.as_slice())
    .bind(schedule.created_at)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !inserted {
        let existing: Vec<u8> = sqlx::query_scalar(
            "SELECT schedule_sha256 FROM snowman_work_schedules WHERE community_id=$1 AND schedule_id=$2",
        )
        .bind(*community_id.as_uuid())
        .bind(schedule.schedule_id)
        .fetch_one(&mut *tx)
        .await?;
        if existing.as_slice() != schedule_sha256.as_slice() {
            return Err(DbError::AccessDenied(
                "schedule identifier was reused for a different contract".into(),
            ));
        }
    } else {
        let event = NewWorkEvent {
            event_id: schedule.schedule_id,
            request_id: schedule.request_id,
            task_id: None,
            event_type: "schedule.authorized".into(),
            actor_identity: format!("snowman:{}", schedule.created_by_identity_id),
            payload: serde_json::json!({
                "schema_version": "snowman.work.schedule.event.v1",
                "schedule_id": schedule.schedule_id,
                "schedule_sha256": hex::encode(schedule_sha256),
                "trigger_identity_id": schedule.trigger_identity_id,
                "executor_identity_id": schedule.executor_identity_id,
                "specialist_role": schedule.specialist_role,
                "capability": schedule.capability,
                "cadence_seconds": schedule.cadence_seconds,
                "next_run_at": schedule.next_run_at,
                "ends_at": schedule.ends_at,
                "max_occurrences": schedule.max_occurrences,
            }),
            occurred_at: schedule.created_at,
        };
        validate_work_event(&event)?;
        append_work_event_tx(&mut tx, *community_id.as_uuid(), &event).await?;
    }
    tx.commit().await?;
    Ok(inserted)
}

/// Stop a recurring authorization and expire any occurrence that has not yet
/// become a governed proactive task. Completed task evidence is preserved.
pub async fn cancel_work_schedule(
    pool: &PgPool,
    community_id: CommunityId,
    request_id: Uuid,
    schedule_id: Uuid,
    cancellation_id: Uuid,
    actor_identity_id: Uuid,
    cancelled_at: DateTime<Utc>,
) -> Result<bool> {
    if request_id.is_nil()
        || schedule_id.is_nil()
        || cancellation_id.is_nil()
        || actor_identity_id.is_nil()
        || cancelled_at > Utc::now() + Duration::minutes(5)
    {
        return Err(DbError::InvalidData(
            "schedule cancellation identity or time is invalid".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    let authorized: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1 FROM snowman_workforce_identities i
          JOIN snowman_workforce_capability_grants g
            ON g.community_id=i.community_id AND g.identity_id=i.identity_id
          WHERE i.community_id=$1 AND i.identity_id=$4 AND i.identity_type='human'
            AND i.status='active' AND i.revoked_at IS NULL
            AND (i.expires_at IS NULL OR i.expires_at > NOW())
            AND g.capability='workforce.schedules.manage' AND g.revoked_at IS NULL
            AND (g.expires_at IS NULL OR g.expires_at > NOW())
            AND EXISTS (
              SELECT 1 FROM snowman_work_schedules s
              WHERE s.community_id=$1 AND s.request_id=$2 AND s.schedule_id=$3
            )
        )
        "#,
    )
    .bind(*community_id.as_uuid())
    .bind(request_id)
    .bind(schedule_id)
    .bind(actor_identity_id)
    .fetch_one(&mut *tx)
    .await?;
    if !authorized {
        return Err(DbError::AccessDenied(
            "schedule cancellation is not authorized".into(),
        ));
    }
    let changed = sqlx::query(
        "UPDATE snowman_work_schedules SET status='cancelled', updated_at=$4 \
         WHERE community_id=$1 AND request_id=$2 AND schedule_id=$3 \
           AND status IN ('active','paused')",
    )
    .bind(*community_id.as_uuid())
    .bind(request_id)
    .bind(schedule_id)
    .bind(cancelled_at)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if changed {
        sqlx::query(
            "UPDATE snowman_work_schedule_occurrences SET status='expired', updated_at=$4 \
             WHERE community_id=$1 AND request_id=$2 AND schedule_id=$3 AND status='claimed'",
        )
        .bind(*community_id.as_uuid())
        .bind(request_id)
        .bind(schedule_id)
        .bind(cancelled_at)
        .execute(&mut *tx)
        .await?;
        refresh_request_status(&mut tx, *community_id.as_uuid(), request_id).await?;
        let event = NewWorkEvent {
            event_id: cancellation_id,
            request_id,
            task_id: None,
            event_type: "schedule.cancelled".into(),
            actor_identity: format!("snowman:{actor_identity_id}"),
            payload: serde_json::json!({
                "schema_version": "snowman.work.schedule.event.v1",
                "schedule_id": schedule_id,
                "reason": "human_cancelled"
            }),
            occurred_at: cancelled_at,
        };
        validate_work_event(&event)?;
        append_work_event_tx(&mut tx, *community_id.as_uuid(), &event).await?;
    }
    tx.commit().await?;
    Ok(changed)
}

/// Claim one due occurrence for the exact tenant-local trigger identity. Lost
/// responses replay by `claim_id`; abandoned claims are re-fenced after expiry.
pub async fn claim_due_work_schedule(
    pool: &PgPool,
    community_id: CommunityId,
    trigger_identity_id: Uuid,
    claim_id: Uuid,
    requested_at: DateTime<Utc>,
) -> Result<Option<ClaimedWorkScheduleOccurrence>> {
    if trigger_identity_id.is_nil()
        || claim_id.is_nil()
        || requested_at < Utc::now() - Duration::minutes(5)
        || requested_at > Utc::now() + Duration::minutes(5)
    {
        return Err(DbError::InvalidData(
            "schedule claim identity or time is invalid".into(),
        ));
    }
    let community_uuid = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let authorized: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1 FROM snowman_workforce_identities i
          JOIN snowman_workforce_capability_grants g
            ON g.community_id=i.community_id AND g.identity_id=i.identity_id
          WHERE i.community_id=$1 AND i.identity_id=$2 AND i.identity_type='service'
            AND i.role='agent' AND i.status='active' AND i.revoked_at IS NULL
            AND (i.expires_at IS NULL OR i.expires_at > NOW())
            AND g.capability='workforce.schedules.trigger' AND g.revoked_at IS NULL
            AND (g.expires_at IS NULL OR g.expires_at > NOW())
        )
        "#,
    )
    .bind(community_uuid)
    .bind(trigger_identity_id)
    .fetch_one(&mut *tx)
    .await?;
    if !authorized {
        return Err(DbError::AccessDenied(
            "schedule trigger identity is not authorized".into(),
        ));
    }
    sqlx::query(
        "UPDATE snowman_work_schedule_occurrences SET status='expired', updated_at=$3 \
         WHERE community_id=$1 AND trigger_identity_id=$2 AND status='claimed' \
           AND expires_at <= $3",
    )
    .bind(community_uuid)
    .bind(trigger_identity_id)
    .bind(requested_at)
    .execute(&mut *tx)
    .await?;

    let existing = sqlx::query(
        r#"
        SELECT o.schedule_id, o.occurrence_id, o.request_id, o.action_id,
               o.claim_generation, o.claim_id, o.claim_expires_at,
               o.source_event_sha256, o.proposed_at, o.scheduled_for, o.expires_at,
               s.executor_identity_id, s.specialist_role, s.capability,
               s.instruction_reference, s.context_references, s.requested_model_id,
               s.expected_input_tokens, s.max_output_tokens, s.max_cost_microusd,
               s.expected_artifact_type, s.risk_tier, s.reversible,
               s.confidence_basis_points, s.usefulness_sha256, s.max_attempts,
               s.ends_at
        FROM snowman_work_schedule_occurrences o
        JOIN snowman_work_schedules s
          ON s.community_id=o.community_id AND s.schedule_id=o.schedule_id
        WHERE o.community_id=$1 AND o.trigger_identity_id=$2 AND o.status='claimed'
          AND s.ends_at > $4
          AND (o.claim_id=$3 OR o.claim_expires_at <= $4)
        ORDER BY (o.claim_id=$3) DESC, o.due_at, o.occurrence_id
        LIMIT 1 FOR UPDATE OF o SKIP LOCKED
        "#,
    )
    .bind(community_uuid)
    .bind(trigger_identity_id)
    .bind(claim_id)
    .bind(requested_at)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = existing {
        let replay = row.try_get::<Option<Uuid>, _>("claim_id")? == Some(claim_id);
        let row = if replay {
            row
        } else {
            let reclaimed_expires_at = (requested_at + Duration::minutes(30))
                .min(row.try_get::<DateTime<Utc>, _>("ends_at")?);
            sqlx::query(
                r#"
                UPDATE snowman_work_schedule_occurrences
                SET claim_id=$4, claim_generation=claim_generation+1,
                    proposed_at=$5, scheduled_for=$5, expires_at=$6,
                    claim_expires_at=$7, updated_at=$5
                WHERE community_id=$1 AND occurrence_id=$2 AND trigger_identity_id=$3
                RETURNING schedule_id, occurrence_id, request_id, action_id,
                          claim_generation, claim_id, claim_expires_at,
                          source_event_sha256, proposed_at, scheduled_for, expires_at
                "#,
            )
            .bind(community_uuid)
            .bind(row.try_get::<Uuid, _>("occurrence_id")?)
            .bind(trigger_identity_id)
            .bind(claim_id)
            .bind(requested_at)
            .bind(reclaimed_expires_at)
            .bind(requested_at + Duration::minutes(2))
            .fetch_one(&mut *tx)
            .await?
        };
        let schedule_id: Uuid = row.try_get("schedule_id")?;
        let schedule = sqlx::query(
            r#"
            SELECT executor_identity_id, specialist_role, capability,
                   instruction_reference, context_references, requested_model_id,
                   expected_input_tokens, max_output_tokens, max_cost_microusd,
                   expected_artifact_type, risk_tier, reversible,
                   confidence_basis_points, usefulness_sha256, max_attempts
            FROM snowman_work_schedules
            WHERE community_id=$1 AND schedule_id=$2 AND trigger_identity_id=$3
            "#,
        )
        .bind(community_uuid)
        .bind(schedule_id)
        .bind(trigger_identity_id)
        .fetch_one(&mut *tx)
        .await?;
        let claimed = schedule_occurrence_from_rows(&row, &schedule)?;
        tx.commit().await?;
        return Ok(Some(claimed));
    }

    let schedule = sqlx::query(
        r#"
        SELECT s.* FROM snowman_work_schedules s
        JOIN snowman_work_requests r
          ON r.community_id=s.community_id AND r.request_id=s.request_id
        WHERE s.community_id=$1 AND s.trigger_identity_id=$2 AND s.status='active'
          AND s.next_run_at <= $3 AND s.next_run_at <= s.ends_at
          AND s.ends_at > $3
          AND s.occurrence_count < s.max_occurrences
          AND r.status IN ('requested','planned','running','awaiting_approval','reviewing')
        ORDER BY s.next_run_at, s.schedule_id
        LIMIT 1 FOR UPDATE OF s SKIP LOCKED
        "#,
    )
    .bind(community_uuid)
    .bind(trigger_identity_id)
    .bind(requested_at)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(schedule) = schedule else {
        tx.commit().await?;
        return Ok(None);
    };
    let schedule_id: Uuid = schedule.try_get("schedule_id")?;
    let request_id: Uuid = schedule.try_get("request_id")?;
    let due_at: DateTime<Utc> = schedule.try_get("next_run_at")?;
    let occurrence_number = schedule.try_get::<i32, _>("occurrence_count")? + 1;
    let occurrence_id = schedule_occurrence_uuid(
        b"snowman.schedule-occurrence.v1\0",
        schedule_id,
        occurrence_number,
        due_at,
    );
    let action_id = schedule_occurrence_uuid(
        b"snowman.schedule-action.v1\0",
        schedule_id,
        occurrence_number,
        due_at,
    );
    let schedule_sha256: Vec<u8> = schedule.try_get("schedule_sha256")?;
    let mut source_hasher = Sha256::new();
    source_hasher.update(b"snowman.schedule-source-event.v1\0");
    update_digest_field(&mut source_hasher, &schedule_sha256);
    update_digest_field(&mut source_hasher, occurrence_id.as_bytes());
    update_digest_field(&mut source_hasher, &due_at.timestamp_micros().to_be_bytes());
    let source_event_sha256: [u8; 32] = source_hasher.finalize().into();
    let ends_at: DateTime<Utc> = schedule.try_get("ends_at")?;
    let expires_at = (requested_at + Duration::minutes(30)).min(ends_at);
    let claim_expires_at = requested_at + Duration::minutes(2);
    let occurrence = sqlx::query(
        r#"
        INSERT INTO snowman_work_schedule_occurrences
          (community_id, occurrence_id, schedule_id, request_id, action_id,
           trigger_identity_id, claim_id, due_at, proposed_at, scheduled_for,
           expires_at, source_event_sha256, claim_expires_at, created_at, updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,$12,$9,$9)
        RETURNING schedule_id, occurrence_id, request_id, action_id,
                  claim_generation, claim_id, claim_expires_at,
                  source_event_sha256, proposed_at, scheduled_for, expires_at
        "#,
    )
    .bind(community_uuid)
    .bind(occurrence_id)
    .bind(schedule_id)
    .bind(request_id)
    .bind(action_id)
    .bind(trigger_identity_id)
    .bind(claim_id)
    .bind(due_at)
    .bind(requested_at)
    .bind(expires_at)
    .bind(source_event_sha256.as_slice())
    .bind(claim_expires_at)
    .fetch_one(&mut *tx)
    .await?;
    let cadence = Duration::seconds(i64::from(schedule.try_get::<i32, _>("cadence_seconds")?));
    // Do not replay every missed interval after downtime. One overdue run is
    // materialized, then cadence resumes from the observed claim time.
    let next_run_at = (due_at + cadence).max(requested_at + cadence);
    let completed = occurrence_number >= schedule.try_get::<i32, _>("max_occurrences")?
        || next_run_at > ends_at;
    sqlx::query(
        "UPDATE snowman_work_schedules SET occurrence_count=$3, next_run_at=$4, \
         status=CASE WHEN $5 THEN 'completed' ELSE status END, updated_at=$6 \
         WHERE community_id=$1 AND schedule_id=$2",
    )
    .bind(community_uuid)
    .bind(schedule_id)
    .bind(occurrence_number)
    .bind(next_run_at)
    .bind(completed)
    .bind(requested_at)
    .execute(&mut *tx)
    .await?;
    let claimed = schedule_occurrence_from_rows(&occurrence, &schedule)?;
    tx.commit().await?;
    Ok(Some(claimed))
}

/// Evaluate and durably record one proactive next-useful action exactly once.
///
/// Automatic execution is only a queue decision. A later worker still needs
/// the exact action capability, a fenced lease, and hard spend enforcement.
pub async fn schedule_proactive_action(
    pool: &PgPool,
    community_id: CommunityId,
    proposal: &NewProactiveAction,
) -> Result<ScheduledProactiveAction> {
    let decision = decide_proactive_action(&proposal.action, &proposal.policy);
    let executable = decision != ProactiveDecision::Reject;
    let task = proposal.execution_task.as_ref();
    if proposal.action.community_id != *community_id.as_uuid()
        || proposal.action.action_id.is_nil()
        || proposal.action.objective_id.is_nil()
        || proposal.proposed_by_identity_id.is_nil()
        || proposal.source_event_sha256 == [0; 32]
        || proposal.created_at > proposal.scheduled_for
        || proposal.expires_at <= proposal.scheduled_for
        || executable != task.is_some()
    {
        return Err(DbError::InvalidData(
            "proactive action scope, evidence, or schedule is invalid".into(),
        ));
    }
    if let Some(task) = task {
        validate_model_gateway_route(&task.model_gateway_route)?;
        let instruction_reference = task
            .expected_artifact_contract
            .get("instruction_reference")
            .and_then(Value::as_str);
        let artifact_type = task
            .expected_artifact_contract
            .get("artifact_type")
            .and_then(Value::as_str);
        if task.task_id != proposal.action.action_id
            || task.parent_task_id.is_some()
            || task.service_identity_id.is_nil()
            || task.available_at != proposal.scheduled_for
            || task.deadline_at != Some(proposal.expires_at)
            || task.max_cost_microusd
                != i64::try_from(proposal.action.expected_cost_microusd).unwrap_or(-1)
            || task.approval_required != (decision != ProactiveDecision::ExecuteAutomatically)
            || !task
                .required_capabilities
                .contains(&proposal.action.capability)
            || !valid_proactive_execution(&task.specialist_role, &proposal.action.capability)
            || task.specialist_role == "lead"
            || task.model_id.trim().is_empty()
            || task.max_cost_microusd < 0
            || task.expected_input_tokens < 0
            || task.max_output_tokens < 0
            || task.execution_snapshot_sha256 == [0; 32]
            || task.context_references.len() > 64
            || task
                .context_references
                .iter()
                .any(|item| !is_context_reference(item))
            || instruction_reference.is_none_or(|reference| {
                !is_context_reference(reference)
                    || !task.context_references.iter().any(|item| item == reference)
            })
            || artifact_type.is_none_or(|value| value.trim().is_empty() || value.len() > 128)
            || !valid_capability_set(&task.required_capabilities)
            || task.risk_tier != risk_tier_name(proposal.action.risk_tier)
            || task.reversible != proposal.action.reversible
            || task.risk_tier == "prohibited"
            || (!task.reversible && !task.approval_required)
            || !(1..=20).contains(&task.max_attempts)
            || !(0..=100).contains(&task.priority)
        {
            return Err(DbError::AccessDenied(
                "proactive execution task violates identity, model, context, budget, or risk policy"
                    .into(),
            ));
        }
    }
    let action_bytes = serde_json::to_vec(&(&proposal.action, &proposal.execution_task))
        .map_err(|error| DbError::InvalidData(format!("proactive action is invalid: {error}")))?;
    let policy_bytes = serde_json::to_vec(&proposal.policy)
        .map_err(|error| DbError::InvalidData(format!("proactive policy is invalid: {error}")))?;
    let action_sha256 = sha256(&action_bytes);
    let policy_sha256 = sha256(&policy_bytes);
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let request = sqlx::query(
        r#"
        SELECT r.status, r.classification, r.max_cost_microusd,
               r.max_input_tokens, r.max_output_tokens,
               COALESCE((
                 SELECT SUM(s.cost_microusd) FROM snowman_spend_ledger s
                 WHERE s.community_id=r.community_id AND s.request_id=r.request_id
               ), 0)::bigint AS used_cost_microusd,
               COALESCE((
                 SELECT SUM(s.input_tokens) FROM snowman_spend_ledger s
                 WHERE s.community_id=r.community_id AND s.request_id=r.request_id
               ), 0)::bigint AS used_input_tokens,
               COALESCE((
                 SELECT SUM(s.output_tokens) FROM snowman_spend_ledger s
                 WHERE s.community_id=r.community_id AND s.request_id=r.request_id
               ), 0)::bigint AS used_output_tokens,
               COALESCE((
                 SELECT SUM(GREATEST(t.max_cost_microusd - COALESCE((
                   SELECT SUM(s.cost_microusd) FROM snowman_spend_ledger s
                   WHERE s.community_id=t.community_id AND s.task_id=t.task_id
                 ), 0), 0)) FROM snowman_work_tasks t
                 WHERE t.community_id=r.community_id AND t.request_id=r.request_id
                   AND t.status IN ('queued','awaiting_approval','leased','running','reviewing')
               ), 0)::bigint AS task_reserved_cost_microusd,
               COALESCE((
                 SELECT SUM(GREATEST(t.expected_input_tokens - COALESCE((
                   SELECT SUM(s.input_tokens) FROM snowman_spend_ledger s
                   WHERE s.community_id=t.community_id AND s.task_id=t.task_id
                 ), 0), 0)) FROM snowman_work_tasks t
                 WHERE t.community_id=r.community_id AND t.request_id=r.request_id
                   AND t.status IN ('queued','awaiting_approval','leased','running','reviewing')
               ), 0)::bigint AS task_reserved_input_tokens,
               COALESCE((
                 SELECT SUM(GREATEST(t.max_output_tokens - COALESCE((
                   SELECT SUM(s.output_tokens) FROM snowman_spend_ledger s
                   WHERE s.community_id=t.community_id AND s.task_id=t.task_id
                 ), 0), 0)) FROM snowman_work_tasks t
                 WHERE t.community_id=r.community_id AND t.request_id=r.request_id
                   AND t.status IN ('queued','awaiting_approval','leased','running','reviewing')
               ), 0)::bigint AS task_reserved_output_tokens,
               COALESCE((
                 SELECT SUM(a.expected_cost_microusd) FROM snowman_proactive_actions a
                 WHERE a.community_id=r.community_id AND a.request_id=r.request_id
                   AND a.task_id IS NULL
                   AND a.status IN ('queued', 'awaiting_approval', 'leased', 'running')
               ), 0)::bigint AS proactive_reserved_microusd,
               (SELECT COUNT(*)::bigint FROM snowman_work_tasks t
                WHERE t.community_id=r.community_id AND t.request_id=r.request_id) AS task_count,
               EXISTS (
                 SELECT 1 FROM snowman_workforce_identities i
                 JOIN snowman_workforce_capability_grants g
                   ON g.community_id=i.community_id AND g.identity_id=i.identity_id
                 WHERE i.community_id=r.community_id AND i.identity_id=$3
                   AND i.identity_type='service' AND i.role='agent'
                   AND i.status='active' AND i.revoked_at IS NULL
                   AND (i.expires_at IS NULL OR i.expires_at > NOW())
                   AND g.capability='workforce.proactive.propose'
                   AND g.revoked_at IS NULL
                   AND (g.expires_at IS NULL OR g.expires_at > NOW())
               ) AS proposer_authorized
        FROM snowman_work_requests r
        WHERE r.community_id=$1 AND r.request_id=$2
        FOR UPDATE
        "#,
    )
    .bind(community_id)
    .bind(proposal.action.objective_id)
    .bind(proposal.proposed_by_identity_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| DbError::InvalidData("proactive action request was not found".into()))?;
    if !request.try_get::<bool, _>("proposer_authorized")?
        || !matches!(
            request.try_get::<String, _>("status")?.as_str(),
            "requested" | "planned" | "running" | "awaiting_approval" | "reviewing"
        )
    {
        return Err(DbError::AccessDenied(
            "proactive proposer or request lifecycle is not authorized".into(),
        ));
    }
    let existing = sqlx::query(
        r#"
        SELECT request_id, task_id, proposed_by_identity_id, source_event_sha256,
               policy_sha256, action_sha256, decision, scheduled_for,
               expires_at, created_at
        FROM snowman_proactive_actions
        WHERE community_id=$1 AND action_id=$2
        "#,
    )
    .bind(community_id)
    .bind(proposal.action.action_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        let exact = existing.try_get::<Uuid, _>("request_id")? == proposal.action.objective_id
            && existing.try_get::<Option<Uuid>, _>("task_id")?
                == proposal.execution_task.as_ref().map(|task| task.task_id)
            && existing.try_get::<Uuid, _>("proposed_by_identity_id")?
                == proposal.proposed_by_identity_id
            && existing
                .try_get::<Vec<u8>, _>("source_event_sha256")?
                .as_slice()
                == proposal.source_event_sha256.as_slice()
            && existing.try_get::<Vec<u8>, _>("policy_sha256")?.as_slice()
                == policy_sha256.as_slice()
            && existing.try_get::<Vec<u8>, _>("action_sha256")?.as_slice()
                == action_sha256.as_slice()
            && existing.try_get::<String, _>("decision")? == proactive_decision_name(decision)
            && existing.try_get::<DateTime<Utc>, _>("scheduled_for")? == proposal.scheduled_for
            && existing.try_get::<DateTime<Utc>, _>("expires_at")? == proposal.expires_at
            && existing.try_get::<DateTime<Utc>, _>("created_at")? == proposal.created_at;
        if exact {
            tx.commit().await?;
            return Ok(ScheduledProactiveAction {
                action_id: proposal.action.action_id,
                request_id: proposal.action.objective_id,
                decision,
                inserted: false,
            });
        }
        return Err(DbError::AccessDenied(
            "proactive action identifier was reused for a different policy decision".into(),
        ));
    }
    if decision != ProactiveDecision::Reject {
        let task = proposal
            .execution_task
            .as_ref()
            .expect("non-rejected proactive action has an execution task");
        if request.try_get::<i64, _>("task_count")? >= 64 {
            return Err(DbError::AccessDenied(
                "proactive action would exceed the request task limit".into(),
            ));
        }
        let proactive_reserved_microusd =
            request.try_get::<i64, _>("proactive_reserved_microusd")?;
        let committed_cost = request
            .try_get::<i64, _>("used_cost_microusd")?
            .checked_add(request.try_get::<i64, _>("task_reserved_cost_microusd")?)
            .and_then(|value| value.checked_add(proactive_reserved_microusd))
            .and_then(|value| value.checked_add(task.max_cost_microusd))
            .ok_or_else(|| DbError::AccessDenied("proactive cost reservation overflowed".into()))?;
        let committed_input = request
            .try_get::<i64, _>("used_input_tokens")?
            .checked_add(request.try_get::<i64, _>("task_reserved_input_tokens")?)
            .and_then(|value| value.checked_add(task.expected_input_tokens))
            .ok_or_else(|| {
                DbError::AccessDenied("proactive input reservation overflowed".into())
            })?;
        let committed_output = request
            .try_get::<i64, _>("used_output_tokens")?
            .checked_add(request.try_get::<i64, _>("task_reserved_output_tokens")?)
            .and_then(|value| value.checked_add(task.max_output_tokens))
            .ok_or_else(|| {
                DbError::AccessDenied("proactive output reservation overflowed".into())
            })?;
        if committed_cost > request.try_get::<i64, _>("max_cost_microusd")?
            || committed_input > request.try_get::<i64, _>("max_input_tokens")?
            || committed_output > request.try_get::<i64, _>("max_output_tokens")?
        {
            return Err(DbError::AccessDenied(
                "proactive action would exceed a request cost or token ceiling".into(),
            ));
        }
        let identity_ready: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
              SELECT 1 FROM snowman_workforce_identities i
              WHERE i.community_id=$1 AND i.identity_id=$2
                AND i.identity_type='service' AND i.role='agent' AND i.status='active'
                AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
                AND NOT EXISTS (
                  SELECT 1 FROM unnest($3::text[]) required(capability)
                  WHERE NOT EXISTS (
                    SELECT 1 FROM snowman_workforce_capability_grants g
                    WHERE g.community_id=i.community_id AND g.identity_id=i.identity_id
                      AND g.capability=required.capability AND g.revoked_at IS NULL
                      AND (g.expires_at IS NULL OR g.expires_at > NOW())
                  )
                )
            )
            "#,
        )
        .bind(community_id)
        .bind(task.service_identity_id)
        .bind(&task.required_capabilities)
        .fetch_one(&mut *tx)
        .await?;
        if !identity_ready {
            return Err(DbError::AccessDenied(
                "proactive executor lacks an active exact capability grant".into(),
            ));
        }
        let model_ready: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
              SELECT 1 FROM snowman_model_routes m
              WHERE m.community_id=$1 AND m.model_id=$2 AND m.gateway_url=$3
                AND m.status='active' AND m.evaluated_at <= NOW()
                AND $4=ANY(m.suited_roles)
                AND $5=ANY(m.allowed_classifications)
            )
            "#,
        )
        .bind(community_id)
        .bind(&task.model_id)
        .bind(&task.model_gateway_route)
        .bind(&task.specialist_role)
        .bind(request.try_get::<String, _>("classification")?)
        .fetch_one(&mut *tx)
        .await?;
        if !model_ready {
            return Err(DbError::AccessDenied(
                "proactive model route is not active for its role and classification".into(),
            ));
        }
        insert_task(&mut tx, community_id, proposal.action.objective_id, task).await?;
    }
    sqlx::query(
        r#"
        INSERT INTO snowman_proactive_actions
          (community_id, action_id, request_id, task_id, proposed_by_identity_id,
           trigger_kind, capability, risk_tier, reversible,
           expected_cost_microusd, confidence_basis_points, usefulness_sha256,
           source_event_sha256, policy_sha256, action_sha256, decision, status,
           scheduled_for, expires_at, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
        "#,
    )
    .bind(community_id)
    .bind(proposal.action.action_id)
    .bind(proposal.action.objective_id)
    .bind(proposal.execution_task.as_ref().map(|task| task.task_id))
    .bind(proposal.proposed_by_identity_id)
    .bind(proactive_trigger_name(proposal.action.trigger))
    .bind(&proposal.action.capability)
    .bind(risk_tier_name(proposal.action.risk_tier))
    .bind(proposal.action.reversible)
    .bind(
        i64::try_from(proposal.action.expected_cost_microusd).map_err(|_| {
            DbError::InvalidData("proactive action cost exceeds database bounds".into())
        })?,
    )
    .bind(i32::from(proposal.action.confidence_basis_points))
    .bind(proposal.action.usefulness_sha256.as_slice())
    .bind(proposal.source_event_sha256.as_slice())
    .bind(policy_sha256.as_slice())
    .bind(action_sha256.as_slice())
    .bind(proactive_decision_name(decision))
    .bind(proactive_status_name(decision))
    .bind(proposal.scheduled_for)
    .bind(proposal.expires_at)
    .bind(proposal.created_at)
    .execute(&mut *tx)
    .await?;
    let mut event_payload = serde_json::json!({
        "schema_version": "snowman.proactive.decision.v2",
        "action_sha256": hex::encode(action_sha256),
        "policy_sha256": hex::encode(policy_sha256),
        "source_event_sha256": hex::encode(proposal.source_event_sha256),
        "trigger": proactive_trigger_name(proposal.action.trigger),
        "capability": proposal.action.capability,
        "decision": proactive_decision_name(decision),
        "scheduled_for": proposal.scheduled_for,
        "expires_at": proposal.expires_at,
    });
    if let Some(task) = proposal.execution_task.as_ref() {
        let object = event_payload
            .as_object_mut()
            .expect("proactive event payload is an object");
        object.insert(
            "execution_snapshot_sha256".into(),
            Value::String(hex::encode(task.execution_snapshot_sha256)),
        );
        object.insert(
            "executor_identity_id".into(),
            Value::String(task.service_identity_id.to_string()),
        );
        object.insert(
            "specialist_role".into(),
            Value::String(task.specialist_role.clone()),
        );
        object.insert("model_id".into(), Value::String(task.model_id.clone()));
    }
    let event = NewWorkEvent {
        event_id: proposal.action.action_id,
        request_id: proposal.action.objective_id,
        task_id: proposal.execution_task.as_ref().map(|task| task.task_id),
        event_type: format!("proactive.{}", proactive_status_name(decision)),
        actor_identity: format!("snowman-service:{}", proposal.proposed_by_identity_id),
        payload: event_payload,
        occurred_at: proposal.created_at,
    };
    validate_work_event(&event)?;
    append_work_event_tx(&mut tx, community_id, &event).await?;
    if decision != ProactiveDecision::Reject {
        refresh_request_status(&mut tx, community_id, proposal.action.objective_id).await?;
    }
    tx.commit().await?;
    Ok(ScheduledProactiveAction {
        action_id: proposal.action.action_id,
        request_id: proposal.action.objective_id,
        decision,
        inserted: true,
    })
}

const fn proactive_trigger_name(trigger: ProactiveTrigger) -> &'static str {
    match trigger {
        ProactiveTrigger::UserObjective => "user_objective",
        ProactiveTrigger::AuthorizedSchedule => "authorized_schedule",
        ProactiveTrigger::TenantSignal => "tenant_signal",
        ProactiveTrigger::PolicyReview => "policy_review",
    }
}

const fn proactive_decision_name(decision: ProactiveDecision) -> &'static str {
    match decision {
        ProactiveDecision::ExecuteAutomatically => "execute_automatically",
        ProactiveDecision::AwaitHumanApproval => "await_human_approval",
        ProactiveDecision::Reject => "reject",
    }
}

const fn proactive_status_name(decision: ProactiveDecision) -> &'static str {
    match decision {
        ProactiveDecision::ExecuteAutomatically => "queued",
        ProactiveDecision::AwaitHumanApproval => "awaiting_approval",
        ProactiveDecision::Reject => "rejected",
    }
}

const fn risk_tier_name(risk: snowman_workforce::RiskTier) -> &'static str {
    match risk {
        snowman_workforce::RiskTier::Low => "low",
        snowman_workforce::RiskTier::Moderate => "moderate",
        snowman_workforce::RiskTier::High => "high",
        snowman_workforce::RiskTier::Prohibited => "prohibited",
    }
}

const fn classification_name(classification: Classification) -> &'static str {
    match classification {
        Classification::Internal => "internal",
        Classification::Confidential => "confidential",
        Classification::Restricted => "restricted",
    }
}

const fn context_authority_name(authority: ContextAuthority) -> &'static str {
    match authority {
        ContextAuthority::Analyst360 => "analyst360",
        ContextAuthority::SnowmanCommandCenter => "snowman-command-center",
    }
}

fn parse_classification_name(value: &str) -> Result<Classification> {
    match value {
        "internal" => Ok(Classification::Internal),
        "confidential" => Ok(Classification::Confidential),
        "restricted" => Ok(Classification::Restricted),
        _ => Err(DbError::InvalidData(
            "stored context classification is invalid".into(),
        )),
    }
}

fn parse_context_authority_name(value: &str) -> Result<ContextAuthority> {
    match value {
        "analyst360" => Ok(ContextAuthority::Analyst360),
        "snowman-command-center" => Ok(ContextAuthority::SnowmanCommandCenter),
        _ => Err(DbError::InvalidData(
            "stored context authority is invalid".into(),
        )),
    }
}

/// Atomically replace a leased lead planning task with its governed DAG.
pub async fn commit_work_plan(
    pool: &PgPool,
    community_id: CommunityId,
    plan: &NewWorkPlan,
) -> Result<CommittedWorkPlan> {
    if plan.plan_id.is_nil()
        || plan.request_id.is_nil()
        || plan.lead_task_id.is_nil()
        || plan.planner_identity_id.is_nil()
        || plan.lease_generation <= 0
        || plan.plan_sha256 == [0; 32]
        || plan.tasks.is_empty()
        || plan.tasks.len() > 64
    {
        return Err(DbError::InvalidData(
            "governed team plan identity is invalid".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let existing = sqlx::query(
        "SELECT plan_id, request_id, lead_task_id, plan_sha256, committed_by_identity_id \
         FROM snowman_team_plans WHERE community_id=$1 AND request_id=$2 FOR UPDATE",
    )
    .bind(community_id)
    .bind(plan.request_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        let exact = existing.try_get::<Uuid, _>("plan_id")? == plan.plan_id
            && existing.try_get::<Uuid, _>("lead_task_id")? == plan.lead_task_id
            && existing.try_get::<Uuid, _>("committed_by_identity_id")? == plan.planner_identity_id
            && existing.try_get::<Vec<u8>, _>("plan_sha256")?.as_slice()
                == plan.plan_sha256.as_slice();
        if !exact {
            return Err(DbError::AccessDenied(
                "work request already has a different committed team plan".into(),
            ));
        }
        tx.commit().await?;
        return Ok(CommittedWorkPlan {
            plan_id: plan.plan_id,
            request_id: plan.request_id,
            task_count: plan.tasks.len(),
            inserted: false,
        });
    }

    let authority = sqlx::query(
        r#"
        SELECT r.max_cost_microusd, r.max_input_tokens, r.max_output_tokens,
               r.classification
        FROM snowman_work_requests r
        JOIN snowman_work_tasks t
          ON t.community_id=r.community_id AND t.request_id=r.request_id
         AND t.task_id=$3 AND t.specialist_role='lead' AND t.status='leased'
        JOIN snowman_task_leases l
          ON l.community_id=t.community_id AND l.task_id=t.task_id
         AND l.worker_identity_id=$4 AND l.generation=$5
         AND l.lease_token_sha256=$6 AND l.expires_at > NOW()
        WHERE r.community_id=$1 AND r.request_id=$2
          AND r.status NOT IN ('completed','failed','cancelled','expired')
        FOR UPDATE OF r
        "#,
    )
    .bind(community_id)
    .bind(plan.request_id)
    .bind(plan.lead_task_id)
    .bind(plan.planner_identity_id)
    .bind(plan.lease_generation)
    .bind(plan.lease_token_sha256.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| DbError::AccessDenied("planning lease is stale, expired, or unbound".into()))?;
    let used = sqlx::query(
        r#"
        SELECT COALESCE(SUM(cost_microusd),0)::bigint AS used_cost,
               COALESCE(SUM(input_tokens),0)::bigint AS used_input,
               COALESCE(SUM(output_tokens),0)::bigint AS used_output
        FROM snowman_spend_ledger
        WHERE community_id=$1 AND request_id=$2
        "#,
    )
    .bind(community_id)
    .bind(plan.request_id)
    .fetch_one(&mut *tx)
    .await?;
    let existing_task_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM snowman_work_tasks WHERE community_id=$1 AND request_id=$2",
    )
    .bind(community_id)
    .bind(plan.request_id)
    .fetch_one(&mut *tx)
    .await?;
    if existing_task_count != 1 {
        return Err(DbError::AccessDenied(
            "team plan expansion requires exactly one lead planning task".into(),
        ));
    }

    let mut ids = std::collections::HashSet::new();
    let mut identities = std::collections::HashSet::new();
    let mut cost = 0_i64;
    let mut input = 0_i64;
    let mut output = 0_i64;
    let request_classification: String = authority.try_get("classification")?;
    for planned in &plan.tasks {
        let task = &planned.task;
        if task.task_id == plan.lead_task_id
            || !ids.insert(task.task_id)
            || !identities.insert(task.service_identity_id)
            || task.service_identity_id == plan.planner_identity_id
        {
            return Err(DbError::AccessDenied(
                "specialist task and service identities must be unique".into(),
            ));
        }
        if task.max_cost_microusd < 0
            || task.expected_input_tokens < 0
            || task.max_output_tokens < 0
        {
            return Err(DbError::InvalidData(
                "specialist task budget reservations must be non-negative".into(),
            ));
        }
        validate_model_gateway_route(&task.model_gateway_route)?;
        if task.context_references.len() > 64
            || task
                .context_references
                .iter()
                .any(|item| !is_context_reference(item))
            || task.risk_tier == "prohibited"
            || (!task.reversible && !task.approval_required)
            || !valid_capability_set(&task.required_capabilities)
        {
            return Err(DbError::AccessDenied(
                "specialist task violates plan policy".into(),
            ));
        }
        cost = cost.checked_add(task.max_cost_microusd).ok_or_else(|| {
            DbError::InvalidData("specialist task cost reservations overflowed".into())
        })?;
        input = input
            .checked_add(task.expected_input_tokens)
            .ok_or_else(|| {
                DbError::InvalidData("specialist task input reservations overflowed".into())
            })?;
        output = output.checked_add(task.max_output_tokens).ok_or_else(|| {
            DbError::InvalidData("specialist task output reservations overflowed".into())
        })?;
        let identity_ready: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
              SELECT 1 FROM snowman_workforce_identities i
              WHERE i.community_id=$1 AND i.identity_id=$2
                AND i.identity_type='service' AND i.role='agent' AND i.status='active'
                AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
                AND NOT EXISTS (
                  SELECT 1 FROM unnest($3::text[]) required(capability)
                  WHERE NOT EXISTS (
                    SELECT 1 FROM snowman_workforce_capability_grants g
                    WHERE g.community_id=i.community_id AND g.identity_id=i.identity_id
                      AND g.capability=required.capability AND g.revoked_at IS NULL
                      AND (g.expires_at IS NULL OR g.expires_at > NOW())
                  )
                )
            )
            "#,
        )
        .bind(community_id)
        .bind(task.service_identity_id)
        .bind(&task.required_capabilities)
        .fetch_one(&mut *tx)
        .await?;
        if !identity_ready {
            return Err(DbError::AccessDenied(
                "specialist service identity lacks an active capability grant".into(),
            ));
        }
        let model_ready: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
              SELECT 1 FROM snowman_model_routes m
              WHERE m.community_id=$1 AND m.model_id=$2 AND m.gateway_url=$3
                AND m.status='active' AND m.evaluated_at <= NOW()
                AND $4=ANY(m.suited_roles)
                AND $5=ANY(m.allowed_classifications)
            )
            "#,
        )
        .bind(community_id)
        .bind(&task.model_id)
        .bind(&task.model_gateway_route)
        .bind(&task.specialist_role)
        .bind(&request_classification)
        .fetch_one(&mut *tx)
        .await?;
        if !model_ready {
            return Err(DbError::AccessDenied(
                "specialist model route is not active for its role and classification".into(),
            ));
        }
    }
    for planned in &plan.tasks {
        if planned
            .depends_on
            .iter()
            .any(|dependency| !ids.contains(dependency))
        {
            return Err(DbError::AccessDenied(
                "team plan contains a dependency outside its task graph".into(),
            ));
        }
    }
    if !planned_graph_is_acyclic(&plan.tasks) {
        return Err(DbError::AccessDenied(
            "team plan contains a self-dependency or cycle".into(),
        ));
    }
    let remaining_cost =
        authority.try_get::<i64, _>("max_cost_microusd")? - used.try_get::<i64, _>("used_cost")?;
    let remaining_input =
        authority.try_get::<i64, _>("max_input_tokens")? - used.try_get::<i64, _>("used_input")?;
    let remaining_output = authority.try_get::<i64, _>("max_output_tokens")?
        - used.try_get::<i64, _>("used_output")?;
    if cost > remaining_cost.max(0)
        || input > remaining_input.max(0)
        || output > remaining_output.max(0)
    {
        return Err(DbError::AccessDenied(
            "specialist plan exceeds the remaining request budget".into(),
        ));
    }

    sqlx::query(
        "INSERT INTO snowman_team_plans \
         (community_id,plan_id,request_id,lead_task_id,plan_sha256,committed_by_identity_id,committed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(community_id)
    .bind(plan.plan_id)
    .bind(plan.request_id)
    .bind(plan.lead_task_id)
    .bind(plan.plan_sha256.as_slice())
    .bind(plan.planner_identity_id)
    .bind(plan.committed_at)
    .execute(&mut *tx)
    .await?;
    for planned in &plan.tasks {
        insert_task(&mut tx, community_id, plan.request_id, &planned.task).await?;
    }
    for planned in &plan.tasks {
        for dependency in &planned.depends_on {
            sqlx::query(
                "INSERT INTO snowman_work_task_dependencies \
                 (community_id,request_id,task_id,depends_on_task_id) VALUES ($1,$2,$3,$4)",
            )
            .bind(community_id)
            .bind(plan.request_id)
            .bind(planned.task.task_id)
            .bind(dependency)
            .execute(&mut *tx)
            .await?;
        }
    }
    sqlx::query(
        "UPDATE snowman_work_tasks SET status='succeeded', updated_at=NOW() \
         WHERE community_id=$1 AND task_id=$2",
    )
    .bind(community_id)
    .bind(plan.lead_task_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM snowman_task_leases WHERE community_id=$1 AND task_id=$2")
        .bind(community_id)
        .bind(plan.lead_task_id)
        .execute(&mut *tx)
        .await?;
    let event = NewWorkEvent {
        event_id: plan.plan_id,
        request_id: plan.request_id,
        task_id: Some(plan.lead_task_id),
        event_type: "plan.committed".into(),
        actor_identity: format!("snowman-service:{}", plan.planner_identity_id),
        payload: serde_json::json!({
            "schema_version": "snowman.work.event.v1",
            "plan_sha256": hex::encode(plan.plan_sha256),
            "specialist_task_count": plan.tasks.len(),
            "unique_service_identity_count": identities.len(),
        }),
        occurred_at: plan.committed_at,
    };
    append_work_event_tx(&mut tx, community_id, &event).await?;
    refresh_request_status(&mut tx, community_id, plan.request_id).await?;
    tx.commit().await?;
    Ok(CommittedWorkPlan {
        plan_id: plan.plan_id,
        request_id: plan.request_id,
        task_count: plan.tasks.len(),
        inserted: true,
    })
}

/// Read one request from the writer with strict tenant scoping.
///
/// Raw objective text and requester identifiers are deliberately omitted. The
/// command center receives only current state, budgets, bounded event metadata,
/// and immutable evidence coordinates.
pub async fn get_work_request_status(
    pool: &PgPool,
    community_id: CommunityId,
    request_id: Uuid,
) -> Result<Option<WorkRequestStatus>> {
    let community_id = *community_id.as_uuid();
    let request = sqlx::query(
        r#"
        SELECT r.request_id, r.objective_sha256, r.request_contract_sha256,
               r.classification, r.status,
               r.client_ready_delivery,
               r.deadline_at, r.max_cost_microusd, r.max_input_tokens,
               r.max_output_tokens, r.created_at, r.updated_at,
               COALESCE(SUM(s.cost_microusd), 0)::bigint AS used_cost_microusd,
               COALESCE(SUM(s.input_tokens), 0)::bigint AS used_input_tokens,
               COALESCE(SUM(s.output_tokens), 0)::bigint AS used_output_tokens
        FROM snowman_work_requests r
        LEFT JOIN snowman_spend_ledger s
          ON s.community_id=r.community_id AND s.request_id=r.request_id
        WHERE r.community_id=$1 AND r.request_id=$2
        GROUP BY r.community_id, r.request_id
        "#,
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_optional(pool)
    .await?;
    let Some(request) = request else {
        return Ok(None);
    };

    let task_rows = sqlx::query(
        r#"
        SELECT task_id, parent_task_id, specialist_role, model_id,
               max_cost_microusd, expected_input_tokens, max_output_tokens,
               required_capabilities, expected_artifact_contract,
               context_packet_id, risk_tier, reversible, approval_required,
               status, attempt_count, max_attempts, deadline_at,
               execution_snapshot_sha256,
               ARRAY(
                 SELECT context_reference FROM (
                   SELECT c.context_reference
                   FROM snowman_work_task_context_refs c
                   WHERE c.community_id=t.community_id AND c.task_id=t.task_id
                   UNION
                   SELECT e.payload->>'context_reference'
                   FROM snowman_work_task_dependencies d
                   JOIN snowman_work_events e
                     ON e.community_id=d.community_id
                    AND e.task_id=d.depends_on_task_id
                    AND e.event_type='context.published'
                   WHERE d.community_id=t.community_id AND d.task_id=t.task_id
                     AND e.payload->>'context_reference' IS NOT NULL
                 ) available_context
                 ORDER BY context_reference
               ) AS context_references
        FROM snowman_work_tasks t
        WHERE t.community_id=$1 AND t.request_id=$2
        ORDER BY created_at, task_id
        "#,
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_all(pool)
    .await?;
    let tasks = task_rows
        .into_iter()
        .map(|row| -> Result<WorkTaskStatus> {
            Ok(WorkTaskStatus {
                task_id: row.try_get("task_id")?,
                parent_task_id: row.try_get("parent_task_id")?,
                specialist_role: row.try_get("specialist_role")?,
                model_id: row.try_get("model_id")?,
                max_cost_microusd: row.try_get("max_cost_microusd")?,
                expected_input_tokens: row.try_get("expected_input_tokens")?,
                max_output_tokens: row.try_get("max_output_tokens")?,
                required_capabilities: row.try_get("required_capabilities")?,
                expected_artifact_contract: row.try_get("expected_artifact_contract")?,
                context_references: row.try_get("context_references")?,
                context_packet_id: row.try_get("context_packet_id")?,
                risk_tier: row.try_get("risk_tier")?,
                reversible: row.try_get("reversible")?,
                approval_required: row.try_get("approval_required")?,
                status: row.try_get("status")?,
                attempt_count: row.try_get("attempt_count")?,
                max_attempts: row.try_get("max_attempts")?,
                deadline_at: row.try_get("deadline_at")?,
                execution_snapshot_sha256: hex::encode(
                    row.try_get::<Vec<u8>, _>("execution_snapshot_sha256")?,
                ),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let event_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM snowman_work_events WHERE community_id=$1 AND request_id=$2",
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_one(pool)
    .await?;
    let mut event_rows = sqlx::query(
        r#"
        SELECT event_id, task_id, sequence, event_type, actor_identity, payload,
               previous_event_sha256, event_sha256, occurred_at
        FROM snowman_work_events
        WHERE community_id=$1 AND request_id=$2
        ORDER BY sequence DESC
        LIMIT 200
        "#,
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_all(pool)
    .await?;
    event_rows.reverse();
    let events = event_rows
        .into_iter()
        .map(|row| -> Result<WorkEventStatus> {
            Ok(WorkEventStatus {
                event_id: row.try_get("event_id")?,
                task_id: row.try_get("task_id")?,
                sequence: row.try_get("sequence")?,
                event_type: row.try_get("event_type")?,
                actor_identity: row.try_get("actor_identity")?,
                payload: row.try_get("payload")?,
                previous_event_sha256: row
                    .try_get::<Option<Vec<u8>>, _>("previous_event_sha256")?
                    .map(hex::encode),
                event_sha256: hex::encode(row.try_get::<Vec<u8>, _>("event_sha256")?),
                occurred_at: row.try_get("occurred_at")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Some(WorkRequestStatus {
        request_id: request.try_get("request_id")?,
        objective_sha256: hex::encode(request.try_get::<Vec<u8>, _>("objective_sha256")?),
        request_contract_sha256: hex::encode(
            request.try_get::<Vec<u8>, _>("request_contract_sha256")?,
        ),
        classification: request.try_get("classification")?,
        client_ready_delivery: request.try_get("client_ready_delivery")?,
        status: request.try_get("status")?,
        deadline_at: request.try_get("deadline_at")?,
        max_cost_microusd: request.try_get("max_cost_microusd")?,
        used_cost_microusd: request.try_get("used_cost_microusd")?,
        max_input_tokens: request.try_get("max_input_tokens")?,
        used_input_tokens: request.try_get("used_input_tokens")?,
        max_output_tokens: request.try_get("max_output_tokens")?,
        used_output_tokens: request.try_get("used_output_tokens")?,
        tasks,
        events,
        event_count,
        created_at: request.try_get("created_at")?,
        updated_at: request.try_get("updated_at")?,
    }))
}

/// Cancel every non-terminal task and invalidate every live lease atomically.
///
/// Cancellation is tenant-scoped, human-attributed, hash-chained, and
/// idempotent by `cancellation_id`. A worker holding a previously valid bearer
/// lease cannot heartbeat, spend, or finish after this transaction commits.
pub async fn cancel_work_request(
    pool: &PgPool,
    community_id: CommunityId,
    cancellation: &WorkRequestCancellation,
) -> Result<Option<CancelledWorkRequest>> {
    if cancellation.cancellation_id.is_nil()
        || cancellation.request_id.is_nil()
        || cancellation.actor_identity.trim() != cancellation.actor_identity
        || cancellation.actor_identity.is_empty()
        || cancellation.actor_identity.len() > 256
        || !valid_reason_code(&cancellation.reason_code)
    {
        return Err(DbError::InvalidData(
            "request cancellation identity or reason is invalid".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let request = sqlx::query(
        "SELECT status FROM snowman_work_requests \
         WHERE community_id=$1 AND request_id=$2 FOR UPDATE",
    )
    .bind(community_id)
    .bind(cancellation.request_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(request) = request else {
        tx.commit().await?;
        return Ok(None);
    };
    let status: String = request.try_get("status")?;
    if status == "cancelled" {
        let existing = sqlx::query(
            "SELECT actor_identity, payload, occurred_at FROM snowman_work_events \
             WHERE community_id=$1 AND request_id=$2 AND event_id=$3 \
               AND event_type='request.cancelled'",
        )
        .bind(community_id)
        .bind(cancellation.request_id)
        .bind(cancellation.cancellation_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(existing) = existing else {
            return Err(DbError::AccessDenied(
                "work request was cancelled by a different operation".into(),
            ));
        };
        let payload: Value = existing.try_get("payload")?;
        let exact = existing.try_get::<String, _>("actor_identity")? == cancellation.actor_identity
            && existing.try_get::<DateTime<Utc>, _>("occurred_at")? == cancellation.occurred_at
            && payload.get("reason_code").and_then(Value::as_str)
                == Some(cancellation.reason_code.as_str());
        if !exact {
            return Err(DbError::AccessDenied(
                "cancellation identifier was reused for different evidence".into(),
            ));
        }
        let cancelled_task_count = payload
            .get("cancelled_task_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                DbError::InvalidData("stored cancellation evidence is invalid".into())
            })?;
        tx.commit().await?;
        return Ok(Some(CancelledWorkRequest {
            request_id: cancellation.request_id,
            cancelled_task_count,
            inserted: false,
        }));
    }
    if matches!(status.as_str(), "completed" | "failed" | "expired") {
        return Err(DbError::AccessDenied(format!(
            "a {status} work request cannot be cancelled"
        )));
    }

    let cancelled = sqlx::query(
        r#"
        UPDATE snowman_work_tasks SET status='cancelled', updated_at=NOW()
        WHERE community_id=$1 AND request_id=$2
          AND status NOT IN (
            'succeeded','failed','cancelled','expired','dead_lettered'
          )
        RETURNING task_id
        "#,
    )
    .bind(community_id)
    .bind(cancellation.request_id)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM snowman_task_leases l USING snowman_work_tasks t \
         WHERE l.community_id=$1 AND t.community_id=l.community_id \
           AND t.task_id=l.task_id AND t.request_id=$2",
    )
    .bind(community_id)
    .bind(cancellation.request_id)
    .execute(&mut *tx)
    .await?;
    let cancelled_schedules = sqlx::query(
        "UPDATE snowman_work_schedules SET status='cancelled', updated_at=$3 \
         WHERE community_id=$1 AND request_id=$2 AND status IN ('active','paused') \
         RETURNING schedule_id",
    )
    .bind(community_id)
    .bind(cancellation.request_id)
    .bind(cancellation.occurred_at)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE snowman_work_schedule_occurrences SET status='expired', updated_at=$3 \
         WHERE community_id=$1 AND request_id=$2 AND status='claimed'",
    )
    .bind(community_id)
    .bind(cancellation.request_id)
    .bind(cancellation.occurred_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE snowman_work_requests SET status='cancelled', updated_at=NOW() \
         WHERE community_id=$1 AND request_id=$2",
    )
    .bind(community_id)
    .bind(cancellation.request_id)
    .execute(&mut *tx)
    .await?;
    let cancelled_task_count = cancelled.len() as u64;
    let event = NewWorkEvent {
        event_id: cancellation.cancellation_id,
        request_id: cancellation.request_id,
        task_id: None,
        event_type: "request.cancelled".into(),
        actor_identity: cancellation.actor_identity.clone(),
        payload: serde_json::json!({
            "schema_version": "snowman.work.event.v1",
            "reason_code": cancellation.reason_code,
            "cancelled_task_count": cancelled_task_count,
            "cancelled_schedule_count": cancelled_schedules.len(),
            "leases_invalidated": true,
        }),
        occurred_at: cancellation.occurred_at,
    };
    validate_work_event(&event)?;
    append_work_event_tx(&mut tx, community_id, &event).await?;
    tx.commit().await?;
    Ok(Some(CancelledWorkRequest {
        request_id: cancellation.request_id,
        cancelled_task_count,
        inserted: true,
    }))
}

/// Claim the next due task using `FOR UPDATE SKIP LOCKED` and a fenced lease.
pub async fn claim_next_work_task(
    pool: &PgPool,
    community_id: CommunityId,
    worker_identity_id: Uuid,
    claim_id: Uuid,
    lease_token_sha256: [u8; 32],
    lease_duration: Duration,
) -> Result<Option<LeasedWorkTask>> {
    if lease_duration <= Duration::zero() || claim_id.is_nil() {
        return Err(DbError::InvalidData(
            "a positive lease duration is required".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let existing = sqlx::query(
        r#"
        SELECT t.*, r.objective, r.request_contract_sha256, r.classification,
               r.created_at AS request_created_at,
               r.deadline_at AS request_deadline_at,
               r.max_cost_microusd AS request_max_cost_microusd,
               r.max_input_tokens AS request_max_input_tokens,
               r.max_output_tokens AS request_max_output_tokens,
               l.claim_id, l.generation AS lease_generation,
               l.expires_at AS lease_expires_at,
               ARRAY(
                 SELECT context_reference FROM (
                   SELECT c.context_reference FROM snowman_work_task_context_refs c
                   WHERE c.community_id=t.community_id AND c.task_id=t.task_id
                   UNION
                   SELECT e.payload->>'context_reference'
                   FROM snowman_work_task_dependencies d
                   JOIN snowman_work_events e
                     ON e.community_id=d.community_id
                    AND e.task_id=d.depends_on_task_id
                    AND e.event_type='context.published'
                   WHERE d.community_id=t.community_id AND d.task_id=t.task_id
                     AND e.payload->>'context_reference' IS NOT NULL
                 ) available_context
                 ORDER BY context_reference
               ) AS context_references
        FROM snowman_task_leases l
        JOIN snowman_work_tasks t
          ON t.community_id=l.community_id AND t.task_id=l.task_id
        JOIN snowman_work_requests r
          ON r.community_id=t.community_id AND r.request_id=t.request_id
        WHERE l.community_id=$1 AND l.worker_identity_id=$2 AND l.claim_id=$3
          AND l.lease_token_sha256=$4 AND l.expires_at > NOW()
          AND EXISTS (
            SELECT 1 FROM snowman_workforce_identities i
            WHERE i.community_id=t.community_id AND i.identity_id=t.service_identity_id
              AND i.identity_type='service' AND i.role='agent' AND i.status='active'
              AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
          )
          AND NOT EXISTS (
            SELECT 1 FROM unnest(t.required_capabilities) required(capability)
            WHERE NOT EXISTS (
              SELECT 1 FROM snowman_workforce_capability_grants g
              WHERE g.community_id=t.community_id AND g.identity_id=t.service_identity_id
                AND g.capability=required.capability AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at > NOW())
            )
          )
          AND EXISTS (
            SELECT 1 FROM snowman_model_routes m
            WHERE m.community_id=t.community_id AND m.model_id=t.model_id
              AND m.gateway_url=t.model_gateway_route
              AND m.status='active' AND m.evaluated_at <= NOW()
              AND t.specialist_role=ANY(m.suited_roles)
              AND r.classification=ANY(m.allowed_classifications)
          )
          AND (
            NOT t.approval_required OR (
              SELECT a.decision='approved'
                     AND a.task_snapshot_sha256=t.execution_snapshot_sha256
                     AND a.expires_at > NOW()
              FROM snowman_work_approvals a
              WHERE a.community_id=t.community_id AND a.request_id=t.request_id
                AND a.task_id=t.task_id
              ORDER BY a.decided_at DESC, a.approval_id DESC LIMIT 1
            ) IS TRUE
          )
        "#,
    )
    .bind(community_id)
    .bind(worker_identity_id)
    .bind(claim_id)
    .bind(lease_token_sha256.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        let leased = leased_work_task_from_row(&existing)?;
        tx.commit().await?;
        return Ok(Some(leased));
    }
    let conflicting_claim: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM snowman_task_leases \
         WHERE community_id=$1 AND worker_identity_id=$2 AND claim_id=$3)",
    )
    .bind(community_id)
    .bind(worker_identity_id)
    .bind(claim_id)
    .fetch_one(&mut *tx)
    .await?;
    if conflicting_claim {
        return Err(DbError::AccessDenied(
            "workforce claim ID was reused with a different lease token".into(),
        ));
    }
    let candidate = sqlx::query(
        r#"
        SELECT t.*, r.objective, r.request_contract_sha256, r.classification,
               r.created_at AS request_created_at,
               r.deadline_at AS request_deadline_at,
               r.max_cost_microusd AS request_max_cost_microusd,
               r.max_input_tokens AS request_max_input_tokens,
               r.max_output_tokens AS request_max_output_tokens,
               ARRAY(
                 SELECT context_reference FROM (
                   SELECT c.context_reference FROM snowman_work_task_context_refs c
                   WHERE c.community_id=t.community_id AND c.task_id=t.task_id
                   UNION
                   SELECT e.payload->>'context_reference'
                   FROM snowman_work_task_dependencies d
                   JOIN snowman_work_events e
                     ON e.community_id=d.community_id
                    AND e.task_id=d.depends_on_task_id
                    AND e.event_type='context.published'
                   WHERE d.community_id=t.community_id AND d.task_id=t.task_id
                     AND e.payload->>'context_reference' IS NOT NULL
                 ) available_context
                 ORDER BY context_reference
               ) AS context_references
        FROM snowman_work_tasks t
        JOIN snowman_work_requests r
          ON r.community_id=t.community_id AND r.request_id=t.request_id
        WHERE t.community_id=$1 AND t.service_identity_id=$2
          AND t.status='queued' AND t.available_at <= NOW()
          AND NOT EXISTS (
            SELECT 1
            FROM snowman_work_task_dependencies d
            JOIN snowman_work_tasks dependency
              ON dependency.community_id=d.community_id
             AND dependency.task_id=d.depends_on_task_id
            WHERE d.community_id=t.community_id AND d.task_id=t.task_id
              AND dependency.status <> 'succeeded'
          )
          AND (t.deadline_at IS NULL OR t.deadline_at > NOW())
          AND EXISTS (
            SELECT 1 FROM snowman_workforce_identities i
            WHERE i.community_id=t.community_id
              AND i.identity_id=t.service_identity_id
              AND i.identity_type='service' AND i.role='agent' AND i.status='active'
              AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
          )
          AND NOT EXISTS (
            SELECT 1 FROM unnest(t.required_capabilities) required(capability)
            WHERE NOT EXISTS (
              SELECT 1 FROM snowman_workforce_capability_grants g
              WHERE g.community_id=t.community_id
                AND g.identity_id=t.service_identity_id
                AND g.capability=required.capability AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at > NOW())
            )
          )
          AND EXISTS (
            SELECT 1 FROM snowman_model_routes m
            WHERE m.community_id=t.community_id
              AND m.model_id=t.model_id
              AND m.gateway_url=t.model_gateway_route
              AND m.status='active' AND m.evaluated_at <= NOW()
              AND t.specialist_role=ANY(m.suited_roles)
              AND r.classification=ANY(m.allowed_classifications)
          )
          AND (
            NOT t.approval_required OR (
              SELECT a.decision = 'approved'
                     AND a.task_snapshot_sha256 = t.execution_snapshot_sha256
                     AND a.expires_at > NOW()
              FROM snowman_work_approvals a
              WHERE a.community_id=t.community_id
                AND a.request_id=t.request_id
                AND a.task_id=t.task_id
              ORDER BY a.decided_at DESC, a.approval_id DESC
              LIMIT 1
            ) IS TRUE
          )
        ORDER BY t.priority DESC, t.created_at ASC
        FOR UPDATE OF t SKIP LOCKED
        LIMIT 1
        "#,
    )
    .bind(community_id)
    .bind(worker_identity_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(task) = candidate else {
        tx.commit().await?;
        return Ok(None);
    };
    let task_id: Uuid = task.try_get("task_id")?;
    let expires_at = Utc::now() + lease_duration;
    let lease = sqlx::query(
        r#"
        INSERT INTO snowman_task_leases
          (community_id, task_id, worker_identity_id, claim_id, generation,
           lease_token_sha256, leased_at, heartbeat_at, expires_at)
        VALUES ($1,$2,$3,$4,1,$5,NOW(),NOW(),$6)
        ON CONFLICT (community_id, task_id) DO UPDATE SET
          worker_identity_id=EXCLUDED.worker_identity_id,
          claim_id=EXCLUDED.claim_id,
          generation=snowman_task_leases.generation + 1,
          lease_token_sha256=EXCLUDED.lease_token_sha256,
          leased_at=NOW(), heartbeat_at=NOW(), expires_at=EXCLUDED.expires_at
        RETURNING generation, expires_at
        "#,
    )
    .bind(community_id)
    .bind(task_id)
    .bind(worker_identity_id)
    .bind(claim_id)
    .bind(lease_token_sha256.as_slice())
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE snowman_work_tasks SET status='leased', attempt_count=attempt_count+1, updated_at=NOW() WHERE community_id=$1 AND task_id=$2",
    )
    .bind(community_id)
    .bind(task_id)
    .execute(&mut *tx)
    .await?;
    let request_id = task.try_get::<Uuid, _>("request_id")?;
    let lease_generation = lease.try_get::<i64, _>("generation")?;
    let lease_expires_at = lease.try_get::<DateTime<Utc>, _>("expires_at")?;
    let claimed_event = NewWorkEvent {
        event_id: claim_id,
        request_id,
        task_id: Some(task_id),
        event_type: "task.claimed".to_string(),
        actor_identity: format!("snowman-service:{worker_identity_id}"),
        payload: serde_json::json!({
            "claim_id": claim_id,
            "lease_generation": lease_generation,
            "lease_expires_at": lease_expires_at,
            "execution_snapshot_sha256": hex::encode(
                task.try_get::<Vec<u8>, _>("execution_snapshot_sha256")?
            ),
        }),
        occurred_at: Utc::now(),
    };
    validate_work_event(&claimed_event)?;
    append_work_event_tx(&mut tx, community_id, &claimed_event).await?;
    refresh_request_status(&mut tx, community_id, request_id).await?;
    tx.commit().await?;

    Ok(Some(LeasedWorkTask {
        community_id,
        request_id,
        task_id,
        claim_id,
        objective: task.try_get("objective")?,
        request_contract_sha256: vec_to_sha256(task.try_get("request_contract_sha256")?)?,
        classification: task.try_get("classification")?,
        request_created_at: task.try_get("request_created_at")?,
        request_deadline_at: task.try_get("request_deadline_at")?,
        max_cost_microusd: task.try_get("request_max_cost_microusd")?,
        max_input_tokens: task.try_get("request_max_input_tokens")?,
        max_output_tokens: task.try_get("request_max_output_tokens")?,
        specialist_role: task.try_get("specialist_role")?,
        service_identity_id: task.try_get("service_identity_id")?,
        required_capabilities: task.try_get("required_capabilities")?,
        model_gateway_route: task.try_get("model_gateway_route")?,
        model_id: task.try_get("model_id")?,
        task_max_cost_microusd: task.try_get("max_cost_microusd")?,
        expected_input_tokens: task.try_get("expected_input_tokens")?,
        task_max_output_tokens: task.try_get("max_output_tokens")?,
        execution_snapshot_sha256: vec_to_sha256(task.try_get("execution_snapshot_sha256")?)?,
        expected_artifact_contract: task.try_get("expected_artifact_contract")?,
        context_references: task.try_get("context_references")?,
        context_packet_id: task.try_get("context_packet_id")?,
        risk_tier: task.try_get("risk_tier")?,
        reversible: task.try_get("reversible")?,
        approval_required: task.try_get("approval_required")?,
        lease_generation,
        lease_expires_at,
    }))
}

fn leased_work_task_from_row(row: &sqlx::postgres::PgRow) -> Result<LeasedWorkTask> {
    Ok(LeasedWorkTask {
        community_id: row.try_get("community_id")?,
        request_id: row.try_get("request_id")?,
        task_id: row.try_get("task_id")?,
        claim_id: row.try_get("claim_id")?,
        objective: row.try_get("objective")?,
        request_contract_sha256: vec_to_sha256(row.try_get("request_contract_sha256")?)?,
        classification: row.try_get("classification")?,
        request_created_at: row.try_get("request_created_at")?,
        request_deadline_at: row.try_get("request_deadline_at")?,
        max_cost_microusd: row.try_get("request_max_cost_microusd")?,
        max_input_tokens: row.try_get("request_max_input_tokens")?,
        max_output_tokens: row.try_get("request_max_output_tokens")?,
        specialist_role: row.try_get("specialist_role")?,
        service_identity_id: row.try_get("service_identity_id")?,
        required_capabilities: row.try_get("required_capabilities")?,
        model_gateway_route: row.try_get("model_gateway_route")?,
        model_id: row.try_get("model_id")?,
        task_max_cost_microusd: row.try_get("max_cost_microusd")?,
        expected_input_tokens: row.try_get("expected_input_tokens")?,
        task_max_output_tokens: row.try_get("max_output_tokens")?,
        execution_snapshot_sha256: vec_to_sha256(row.try_get("execution_snapshot_sha256")?)?,
        expected_artifact_contract: row.try_get("expected_artifact_contract")?,
        context_references: row.try_get("context_references")?,
        context_packet_id: row.try_get("context_packet_id")?,
        risk_tier: row.try_get("risk_tier")?,
        reversible: row.try_get("reversible")?,
        approval_required: row.try_get("approval_required")?,
        lease_generation: row.try_get("lease_generation")?,
        lease_expires_at: row.try_get("lease_expires_at")?,
    })
}

/// Extend a live lease only when every fencing attribute still matches.
pub async fn heartbeat_work_task(
    pool: &PgPool,
    community_id: CommunityId,
    task_id: Uuid,
    worker_identity_id: Uuid,
    generation: i64,
    lease_token_sha256: [u8; 32],
    lease_duration: Duration,
) -> Result<bool> {
    if lease_duration <= Duration::zero() {
        return Err(DbError::InvalidData(
            "lease duration must be positive".into(),
        ));
    }
    let result = sqlx::query(
        r#"
        UPDATE snowman_task_leases l SET heartbeat_at=NOW(), expires_at=$6
        FROM snowman_work_tasks t, snowman_work_requests r
        WHERE l.community_id=$1 AND l.task_id=$2 AND l.worker_identity_id=$3
          AND l.generation=$4 AND l.lease_token_sha256=$5 AND l.expires_at > NOW()
          AND t.community_id=l.community_id AND t.task_id=l.task_id
          AND r.community_id=t.community_id AND r.request_id=t.request_id
          AND EXISTS (
            SELECT 1 FROM snowman_workforce_identities i
            WHERE i.community_id=t.community_id AND i.identity_id=t.service_identity_id
              AND i.identity_type='service' AND i.role='agent' AND i.status='active'
              AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
          )
          AND NOT EXISTS (
            SELECT 1 FROM unnest(t.required_capabilities) required(capability)
            WHERE NOT EXISTS (
              SELECT 1 FROM snowman_workforce_capability_grants g
              WHERE g.community_id=t.community_id AND g.identity_id=t.service_identity_id
                AND g.capability=required.capability AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at > NOW())
            )
          )
          AND EXISTS (
            SELECT 1 FROM snowman_model_routes m
            WHERE m.community_id=t.community_id AND m.model_id=t.model_id
              AND m.gateway_url=t.model_gateway_route
              AND m.status='active' AND m.evaluated_at <= NOW()
              AND t.specialist_role=ANY(m.suited_roles)
              AND r.classification=ANY(m.allowed_classifications)
          )
          AND (
            NOT t.approval_required OR (
              SELECT a.decision='approved'
                     AND a.task_snapshot_sha256=t.execution_snapshot_sha256
                     AND a.expires_at > NOW()
              FROM snowman_work_approvals a
              WHERE a.community_id=t.community_id AND a.request_id=t.request_id
                AND a.task_id=t.task_id
              ORDER BY a.decided_at DESC, a.approval_id DESC LIMIT 1
            ) IS TRUE
          )
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(task_id)
    .bind(worker_identity_id)
    .bind(generation)
    .bind(lease_token_sha256.as_slice())
    .bind(Utc::now() + lease_duration)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Reserve one reminder delivery under the exact live lease of a
/// `deadline_operations` task. The recipient list is resolved from the
/// requester's current Snowman human sessions and persisted on first use, so a
/// lost response or lease retry produces the same signed event and never lets
/// the worker choose a recipient.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_work_reminder(
    pool: &PgPool,
    community_id: CommunityId,
    delivery_id: Uuid,
    task_id: Uuid,
    worker_identity_id: Uuid,
    generation: i64,
    lease_token_sha256: [u8; 32],
) -> Result<PreparedWorkReminder> {
    if delivery_id.is_nil() || task_id.is_nil() || worker_identity_id.is_nil() || generation <= 0 {
        return Err(DbError::InvalidData(
            "reminder delivery requires non-nil identities and a positive lease generation".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2::text || ':work-reminder', 0))")
        .bind(community_id)
        .bind(task_id)
        .execute(&mut *tx)
        .await?;

    if let Some(existing) = sqlx::query(
        r#"
        SELECT delivery_id, request_id, task_id, worker_identity_id,
               target_pubkeys, event_created_at, nostr_event_id
        FROM snowman_work_reminder_receipts
        WHERE community_id=$1 AND task_id=$2
        "#,
    )
    .bind(community_id)
    .bind(task_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        if existing.try_get::<Uuid, _>("delivery_id")? != delivery_id
            || existing.try_get::<Uuid, _>("worker_identity_id")? != worker_identity_id
        {
            return Err(DbError::AccessDenied(
                "reminder delivery coordinate was reused by another worker or task".into(),
            ));
        }
        let targets = existing.try_get::<Vec<Vec<u8>>, _>("target_pubkeys")?;
        validate_reminder_targets(&targets)?;
        let event_id = existing
            .try_get::<Option<Vec<u8>>, _>("nostr_event_id")?
            .map(vec_to_sha256)
            .transpose()?;
        let prepared = PreparedWorkReminder {
            delivery_id,
            request_id: existing.try_get("request_id")?,
            task_id,
            target_pubkeys: targets,
            event_created_at: existing.try_get("event_created_at")?,
            nostr_event_id: event_id,
        };
        tx.commit().await?;
        return Ok(prepared);
    }

    let task = sqlx::query(
        r#"
        SELECT t.request_id, t.available_at, r.requester_identity
        FROM snowman_work_tasks t
        JOIN snowman_work_requests r
          ON r.community_id=t.community_id AND r.request_id=t.request_id
        JOIN snowman_task_leases l
          ON l.community_id=t.community_id AND l.task_id=t.task_id
         AND l.worker_identity_id=$3 AND l.generation=$4
         AND l.lease_token_sha256=$5 AND l.expires_at > NOW()
        WHERE t.community_id=$1 AND t.task_id=$2
          AND t.service_identity_id=$3
          AND t.status IN ('leased','running','reviewing')
          AND t.specialist_role='deadline_operations'
          AND t.required_capabilities @> ARRAY['deadline.remind']::TEXT[]
          AND r.status NOT IN ('completed','failed','cancelled','expired')
          AND EXISTS (
            SELECT 1 FROM snowman_workforce_identities i
            WHERE i.community_id=t.community_id AND i.identity_id=t.service_identity_id
              AND i.identity_type='service' AND i.role='agent' AND i.status='active'
              AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
          )
          AND EXISTS (
            SELECT 1 FROM snowman_workforce_capability_grants g
            WHERE g.community_id=t.community_id AND g.identity_id=t.service_identity_id
              AND g.capability='deadline.remind' AND g.revoked_at IS NULL
              AND (g.expires_at IS NULL OR g.expires_at > NOW())
          )
          AND EXISTS (
            SELECT 1 FROM snowman_model_routes m
            WHERE m.community_id=t.community_id AND m.model_id=t.model_id
              AND m.gateway_url=t.model_gateway_route AND m.status='active'
              AND m.evaluated_at <= NOW()
              AND 'deadline_operations'=ANY(m.suited_roles)
              AND r.classification=ANY(m.allowed_classifications)
          )
          AND (
            NOT t.approval_required OR (
              SELECT a.decision='approved'
                     AND a.task_snapshot_sha256=t.execution_snapshot_sha256
                     AND a.expires_at > NOW()
              FROM snowman_work_approvals a
              WHERE a.community_id=t.community_id AND a.request_id=t.request_id
                AND a.task_id=t.task_id
              ORDER BY a.decided_at DESC, a.approval_id DESC LIMIT 1
            ) IS TRUE
          )
        FOR UPDATE OF t, r
        "#,
    )
    .bind(community_id)
    .bind(task_id)
    .bind(worker_identity_id)
    .bind(generation)
    .bind(lease_token_sha256.as_slice())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        DbError::AccessDenied(
            "reminder task lease, capability, approval, or model route is no longer valid".into(),
        )
    })?;
    let requester_identity = task.try_get::<String, _>("requester_identity")?;
    let target_rows = sqlx::query(
        r#"
        SELECT DISTINCT b.pubkey
        FROM snowman_workforce_identities i
        JOIN snowman_workforce_key_bindings b
          ON b.community_id=i.community_id AND b.identity_id=i.identity_id
        JOIN snowman_workforce_sessions s
          ON s.community_id=b.community_id AND s.identity_id=b.identity_id
         AND s.session_id=b.session_id AND s.device_pubkey=b.pubkey
        WHERE i.community_id=$1
          AND $2='snowman:' || i.identity_id::TEXT
          AND i.identity_type='human' AND i.status='active'
          AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
          AND b.binding_type='human_device' AND b.revoked_at IS NULL
          AND (b.expires_at IS NULL OR b.expires_at > NOW())
          AND s.revoked_at IS NULL AND s.expires_at > NOW()
        ORDER BY b.pubkey
        LIMIT 17
        "#,
    )
    .bind(community_id)
    .bind(&requester_identity)
    .fetch_all(&mut *tx)
    .await?;
    let targets = target_rows
        .into_iter()
        .map(|row| row.try_get::<Vec<u8>, _>("pubkey"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    validate_reminder_targets(&targets)?;
    let request_id = task.try_get::<Uuid, _>("request_id")?;
    let event_created_at = task.try_get::<DateTime<Utc>, _>("available_at")?;
    sqlx::query(
        r#"
        INSERT INTO snowman_work_reminder_receipts
          (community_id, delivery_id, request_id, task_id, worker_identity_id,
           target_pubkeys, event_created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        "#,
    )
    .bind(community_id)
    .bind(delivery_id)
    .bind(request_id)
    .bind(task_id)
    .bind(worker_identity_id)
    .bind(&targets)
    .bind(event_created_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(PreparedWorkReminder {
        delivery_id,
        request_id,
        task_id,
        target_pubkeys: targets,
        event_created_at,
        nostr_event_id: None,
    })
}

fn validate_reminder_targets(targets: &[Vec<u8>]) -> Result<()> {
    if targets.is_empty() || targets.len() > 16 || targets.iter().any(|key| key.len() != 32) {
        return Err(DbError::AccessDenied(
            "reminder recipient has no bounded active Snowman device set".into(),
        ));
    }
    Ok(())
}

/// Record the exact relay-signed reminder event for a prepared delivery.
pub async fn record_work_reminder_event(
    pool: &PgPool,
    community_id: CommunityId,
    delivery_id: Uuid,
    worker_identity_id: Uuid,
    nostr_event_id: [u8; 32],
    delivered_at: DateTime<Utc>,
) -> Result<bool> {
    if delivery_id.is_nil()
        || worker_identity_id.is_nil()
        || nostr_event_id == [0; 32]
        || delivered_at > Utc::now() + Duration::minutes(5)
    {
        return Err(DbError::InvalidData(
            "reminder receipt identity, event digest, or time is invalid".into(),
        ));
    }
    let row = sqlx::query(
        r#"
        UPDATE snowman_work_reminder_receipts
        SET nostr_event_id=$4, delivered_at=$5
        WHERE community_id=$1 AND delivery_id=$2 AND worker_identity_id=$3
          AND nostr_event_id IS NULL AND delivered_at IS NULL
          AND EXISTS (
            SELECT 1 FROM events e
            WHERE e.community_id=$1 AND e.id=$4 AND e.kind=40007
              AND e.channel_id IS NULL AND e.deleted_at IS NULL
          )
        RETURNING task_id
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(delivery_id)
    .bind(worker_identity_id)
    .bind(nostr_event_id.as_slice())
    .bind(delivered_at)
    .fetch_optional(pool)
    .await?;
    if row.is_some() {
        return Ok(true);
    }
    let exact: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1 FROM snowman_work_reminder_receipts
          WHERE community_id=$1 AND delivery_id=$2 AND worker_identity_id=$3
            AND nostr_event_id=$4 AND delivered_at IS NOT NULL
        )
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(delivery_id)
    .bind(worker_identity_id)
    .bind(nostr_event_id.as_slice())
    .fetch_one(pool)
    .await?;
    if !exact {
        return Err(DbError::AccessDenied(
            "reminder receipt conflicts with the prepared delivery".into(),
        ));
    }
    Ok(false)
}

/// Finish a task only under its current live fenced lease.
pub async fn finish_work_task(
    pool: &PgPool,
    community_id: CommunityId,
    completion: &WorkTaskCompletion,
) -> Result<bool> {
    if completion.completion_id.is_nil()
        || completion.task_id.is_nil()
        || completion.worker_identity_id.is_nil()
        || completion.generation <= 0
    {
        return Err(DbError::InvalidData(
            "completion requires non-nil identities and a positive lease generation".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let task = sqlx::query(
        "SELECT request_id, status FROM snowman_work_tasks WHERE community_id=$1 AND task_id=$2",
    )
    .bind(community_id)
    .bind(completion.task_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(task) = task else {
        tx.commit().await?;
        return Ok(false);
    };
    let request_id = task.try_get::<Uuid, _>("request_id")?;
    let event = NewWorkEvent {
        event_id: completion.completion_id,
        request_id,
        task_id: Some(completion.task_id),
        event_type: if completion.succeeded {
            "task.succeeded".to_string()
        } else {
            "task.failed".to_string()
        },
        actor_identity: format!("snowman-service:{}", completion.worker_identity_id),
        payload: completion.result_payload.clone(),
        occurred_at: completion.occurred_at,
    };
    validate_work_event(&event)?;
    let result = sqlx::query(
        r#"
        UPDATE snowman_work_tasks t
        SET status=$6, updated_at=NOW()
        WHERE t.community_id=$1 AND t.task_id=$2 AND t.status IN ('leased','running','reviewing')
          AND t.service_identity_id=$3
          AND EXISTS (
            SELECT 1 FROM snowman_task_leases l
            WHERE l.community_id=$1 AND l.task_id=$2 AND l.worker_identity_id=$3
              AND l.generation=$4 AND l.lease_token_sha256=$5
              AND l.expires_at > NOW()
          )
          AND EXISTS (
            SELECT 1 FROM snowman_workforce_identities i
            WHERE i.community_id=t.community_id AND i.identity_id=t.service_identity_id
              AND i.identity_type='service' AND i.role='agent' AND i.status='active'
              AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
          )
          AND NOT EXISTS (
            SELECT 1 FROM unnest(t.required_capabilities) required(capability)
            WHERE NOT EXISTS (
              SELECT 1 FROM snowman_workforce_capability_grants g
              WHERE g.community_id=t.community_id AND g.identity_id=t.service_identity_id
                AND g.capability=required.capability AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at > NOW())
            )
          )
          AND EXISTS (
            SELECT 1 FROM snowman_model_routes m
            JOIN snowman_work_requests r
              ON r.community_id=t.community_id AND r.request_id=t.request_id
            WHERE m.community_id=t.community_id AND m.model_id=t.model_id
              AND m.gateway_url=t.model_gateway_route
              AND m.status='active' AND m.evaluated_at <= NOW()
              AND t.specialist_role=ANY(m.suited_roles)
              AND r.classification=ANY(m.allowed_classifications)
          )
          AND (
            NOT t.approval_required OR (
              SELECT a.decision='approved'
                     AND a.task_snapshot_sha256=t.execution_snapshot_sha256
                     AND a.expires_at > NOW()
              FROM snowman_work_approvals a
              WHERE a.community_id=t.community_id AND a.request_id=t.request_id
                AND a.task_id=t.task_id
              ORDER BY a.decided_at DESC, a.approval_id DESC LIMIT 1
            ) IS TRUE
          )
        "#,
    )
    .bind(community_id)
    .bind(completion.task_id)
    .bind(completion.worker_identity_id)
    .bind(completion.generation)
    .bind(completion.lease_token_sha256.as_slice())
    .bind(if completion.succeeded {
        "succeeded"
    } else {
        "failed"
    })
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 1 {
        sqlx::query("DELETE FROM snowman_task_leases WHERE community_id=$1 AND task_id=$2")
            .bind(community_id)
            .bind(completion.task_id)
            .execute(&mut *tx)
            .await?;
        append_work_event_tx(&mut tx, community_id, &event).await?;
        refresh_request_status(&mut tx, community_id, request_id).await?;
        tx.commit().await?;
        return Ok(true);
    }

    let terminal = if completion.succeeded {
        "succeeded"
    } else {
        "failed"
    };
    let exact_replay = task.try_get::<String, _>("status")? == terminal
        && sqlx::query(
            "SELECT request_id, task_id, event_type, actor_identity, payload, occurred_at \
             FROM snowman_work_events WHERE community_id=$1 AND event_id=$2",
        )
        .bind(community_id)
        .bind(completion.completion_id)
        .fetch_optional(&mut *tx)
        .await?
        .is_some_and(|existing| {
            existing.try_get::<Uuid, _>("request_id").ok() == Some(event.request_id)
                && existing.try_get::<Option<Uuid>, _>("task_id").ok() == Some(event.task_id)
                && existing.try_get::<String, _>("event_type").ok()
                    == Some(event.event_type.clone())
                && existing.try_get::<String, _>("actor_identity").ok()
                    == Some(event.actor_identity.clone())
                && existing.try_get::<Value, _>("payload").ok() == Some(event.payload.clone())
                && existing.try_get::<DateTime<Utc>, _>("occurred_at").ok()
                    == Some(event.occurred_at)
        });
    tx.commit().await?;
    Ok(exact_replay)
}

/// Enforce deadlines and recover abandoned leases under one idempotent,
/// capability-authorized scheduler tick. Every mutation appends request-local
/// hash-chain evidence in the same transaction as the state transition.
pub async fn maintain_workforce(
    pool: &PgPool,
    community_id: CommunityId,
    tick_id: Uuid,
    scheduler_identity_id: Uuid,
    requested_at: DateTime<Utc>,
) -> Result<WorkforceMaintenanceResult> {
    let requested_at = DateTime::<Utc>::from_timestamp_micros(requested_at.timestamp_micros())
        .ok_or_else(|| DbError::InvalidData("maintenance requested time is invalid".into()))?;
    if tick_id.is_nil()
        || scheduler_identity_id.is_nil()
        || requested_at < Utc::now() - Duration::days(1)
        || requested_at > Utc::now() + Duration::minutes(5)
    {
        return Err(DbError::InvalidData(
            "maintenance tick identity or requested time is invalid".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let authorized: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1 FROM snowman_workforce_identities i
          JOIN snowman_workforce_capability_grants g
            ON g.community_id=i.community_id AND g.identity_id=i.identity_id
          WHERE i.community_id=$1 AND i.identity_id=$2
            AND i.identity_type='service' AND i.role='agent'
            AND i.status='active' AND i.revoked_at IS NULL
            AND (i.expires_at IS NULL OR i.expires_at > NOW())
            AND g.capability='workforce.maintenance'
            AND g.revoked_at IS NULL
            AND (g.expires_at IS NULL OR g.expires_at > NOW())
        )
        "#,
    )
    .bind(community_id)
    .bind(scheduler_identity_id)
    .fetch_one(&mut *tx)
    .await?;
    if !authorized {
        return Err(DbError::AccessDenied(
            "workforce scheduler identity is not authorized".into(),
        ));
    }

    // Serialize maintenance per tenant before checking the durable receipt.
    // This closes the lost-response race and fixes request-event lock ordering
    // even if two scheduler identities are accidentally active at once.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':workforce-maintenance', 0))",
    )
    .bind(community_id)
    .execute(&mut *tx)
    .await?;

    if let Some(existing) = sqlx::query(
        "SELECT scheduler_identity_id, requested_at, result FROM snowman_workforce_maintenance_ticks \
         WHERE community_id=$1 AND tick_id=$2",
    )
    .bind(community_id)
    .bind(tick_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        if existing.try_get::<Uuid, _>("scheduler_identity_id")? != scheduler_identity_id
            || existing.try_get::<DateTime<Utc>, _>("requested_at")? != requested_at
        {
            return Err(DbError::AccessDenied(
                "maintenance tick ID was reused with different evidence".into(),
            ));
        }
        let result = serde_json::from_value(existing.try_get::<Value, _>("result")?)
            .map_err(|error| DbError::InvalidData(format!("invalid maintenance receipt: {error}")))?;
        tx.commit().await?;
        return Ok(result);
    }

    let observed_at: DateTime<Utc> = sqlx::query_scalar("SELECT NOW()")
        .fetch_one(&mut *tx)
        .await?;
    let actor_identity = format!("snowman-service:{scheduler_identity_id}");

    let expired_requests = sqlx::query(
        r#"
        WITH due AS (
          SELECT request_id FROM snowman_work_requests
          WHERE community_id=$1
            AND status IN ('requested','planned','running','awaiting_approval','reviewing')
            AND deadline_at IS NOT NULL AND deadline_at <= $2
          ORDER BY deadline_at, request_id
          LIMIT 100 FOR UPDATE SKIP LOCKED
        )
        UPDATE snowman_work_requests r SET status='expired', updated_at=$2
        FROM due WHERE r.community_id=$1 AND r.request_id=due.request_id
        RETURNING r.request_id
        "#,
    )
    .bind(community_id)
    .bind(observed_at)
    .fetch_all(&mut *tx)
    .await?;
    let expired_request_ids = expired_requests
        .iter()
        .map(|row| row.try_get::<Uuid, _>("request_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut expired_task_rows = Vec::new();
    if !expired_request_ids.is_empty() {
        expired_task_rows = sqlx::query(
            r#"
            WITH due AS (
              SELECT t.task_id, t.request_id, t.status AS previous_status,
                     (SELECT a.action_id FROM snowman_proactive_actions a
                      WHERE a.community_id=t.community_id AND a.task_id=t.task_id) AS proactive_action_id
              FROM snowman_work_tasks t
              WHERE t.community_id=$1 AND t.request_id=ANY($2)
                AND t.status NOT IN ('succeeded','failed','cancelled','expired','dead_lettered')
              FOR UPDATE
            )
            UPDATE snowman_work_tasks t SET status='expired', updated_at=$3
            FROM due WHERE t.community_id=$1 AND t.task_id=due.task_id
            RETURNING t.request_id, t.task_id, due.previous_status, due.proactive_action_id
            "#,
        )
        .bind(community_id)
        .bind(&expired_request_ids)
        .bind(observed_at)
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM snowman_task_leases WHERE community_id=$1 AND task_id IN (\
             SELECT task_id FROM snowman_work_tasks WHERE community_id=$1 AND request_id=ANY($2))",
        )
        .bind(community_id)
        .bind(&expired_request_ids)
        .execute(&mut *tx)
        .await?;
    }

    for request_id in &expired_request_ids {
        append_maintenance_event(
            &mut tx,
            community_id,
            tick_id,
            *request_id,
            None,
            "request.expired",
            &actor_identity,
            serde_json::json!({
                "schema_version": "snowman.workforce.maintenance.event.v1",
                "tick_id": tick_id,
                "reason": "request_deadline_elapsed"
            }),
            observed_at,
        )
        .await?;
    }
    let mut materialized_expired_actions = 0_u64;
    for row in &expired_task_rows {
        let request_id: Uuid = row.try_get("request_id")?;
        let task_id: Uuid = row.try_get("task_id")?;
        append_maintenance_event(
            &mut tx,
            community_id,
            tick_id,
            request_id,
            Some(task_id),
            "task.expired",
            &actor_identity,
            serde_json::json!({
                "schema_version": "snowman.workforce.maintenance.event.v1",
                "tick_id": tick_id,
                "reason": "request_deadline_elapsed",
                "previous_status": row.try_get::<String, _>("previous_status")?
            }),
            observed_at,
        )
        .await?;
        if let Some(action_id) = row.try_get::<Option<Uuid>, _>("proactive_action_id")? {
            materialized_expired_actions += 1;
            append_maintenance_event(
                &mut tx,
                community_id,
                tick_id,
                request_id,
                Some(task_id),
                "proactive.expired",
                &actor_identity,
                serde_json::json!({
                    "schema_version": "snowman.workforce.maintenance.event.v1",
                    "tick_id": tick_id,
                    "action_id": action_id,
                    "reason": "request_deadline_elapsed"
                }),
                observed_at,
            )
            .await?;
        }
    }

    let task_deadlines = sqlx::query(
        r#"
        WITH due AS (
          SELECT t.task_id, t.request_id, t.status AS previous_status,
                 (SELECT a.action_id FROM snowman_proactive_actions a
                  WHERE a.community_id=t.community_id AND a.task_id=t.task_id) AS proactive_action_id
          FROM snowman_work_tasks t
          JOIN snowman_work_requests r
            ON r.community_id=t.community_id AND r.request_id=t.request_id
          WHERE t.community_id=$1
            AND r.status NOT IN ('completed','failed','cancelled','expired')
            AND t.status NOT IN ('succeeded','failed','cancelled','expired','dead_lettered')
            AND t.deadline_at IS NOT NULL AND t.deadline_at <= $2
          ORDER BY t.deadline_at, t.task_id
          LIMIT 500 FOR UPDATE OF t SKIP LOCKED
        )
        UPDATE snowman_work_tasks t SET status='expired', updated_at=$2
        FROM due WHERE t.community_id=$1 AND t.task_id=due.task_id
        RETURNING t.request_id, t.task_id, due.previous_status, due.proactive_action_id
        "#,
    )
    .bind(community_id)
    .bind(observed_at)
    .fetch_all(&mut *tx)
    .await?;
    let task_deadline_ids = task_deadlines
        .iter()
        .map(|row| row.try_get::<Uuid, _>("task_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if !task_deadline_ids.is_empty() {
        sqlx::query("DELETE FROM snowman_task_leases WHERE community_id=$1 AND task_id=ANY($2)")
            .bind(community_id)
            .bind(&task_deadline_ids)
            .execute(&mut *tx)
            .await?;
    }
    let mut touched_requests = std::collections::HashSet::new();
    for row in &task_deadlines {
        let request_id: Uuid = row.try_get("request_id")?;
        let task_id: Uuid = row.try_get("task_id")?;
        touched_requests.insert(request_id);
        append_maintenance_event(
            &mut tx,
            community_id,
            tick_id,
            request_id,
            Some(task_id),
            "task.expired",
            &actor_identity,
            serde_json::json!({
                "schema_version": "snowman.workforce.maintenance.event.v1",
                "tick_id": tick_id,
                "reason": "task_deadline_elapsed",
                "previous_status": row.try_get::<String, _>("previous_status")?
            }),
            observed_at,
        )
        .await?;
        if let Some(action_id) = row.try_get::<Option<Uuid>, _>("proactive_action_id")? {
            materialized_expired_actions += 1;
            append_maintenance_event(
                &mut tx,
                community_id,
                tick_id,
                request_id,
                Some(task_id),
                "proactive.expired",
                &actor_identity,
                serde_json::json!({
                    "schema_version": "snowman.workforce.maintenance.event.v1",
                    "tick_id": tick_id,
                    "action_id": action_id,
                    "reason": "action_expiry_elapsed"
                }),
                observed_at,
            )
            .await?;
        }
    }

    let recovered = sqlx::query(
        r#"
        WITH due AS (
          SELECT t.task_id, t.request_id, t.attempt_count, t.max_attempts
          FROM snowman_work_tasks t
          JOIN snowman_task_leases l
            ON l.community_id=t.community_id AND l.task_id=t.task_id
          JOIN snowman_work_requests r
            ON r.community_id=t.community_id AND r.request_id=t.request_id
          WHERE t.community_id=$1 AND l.expires_at <= $2
            AND t.status IN ('leased','running','reviewing')
            AND r.status NOT IN ('completed','failed','cancelled','expired')
          ORDER BY l.expires_at, t.task_id
          LIMIT 500 FOR UPDATE OF t SKIP LOCKED
        )
        UPDATE snowman_work_tasks t SET
          status=CASE WHEN due.attempt_count >= due.max_attempts THEN 'dead_lettered' ELSE 'queued' END,
          available_at=CASE
            WHEN due.attempt_count >= due.max_attempts THEN t.available_at
            ELSE $2 + make_interval(
              secs => LEAST(300, (5 * power(2, LEAST(due.attempt_count, 6)))::integer)
            )
          END,
          updated_at=$2
        FROM due WHERE t.community_id=$1 AND t.task_id=due.task_id
        RETURNING t.request_id, t.task_id, t.status, t.available_at,
                  due.attempt_count, due.max_attempts
        "#,
    )
    .bind(community_id)
    .bind(observed_at)
    .fetch_all(&mut *tx)
    .await?;
    let recovered_ids = recovered
        .iter()
        .map(|row| row.try_get::<Uuid, _>("task_id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if !recovered_ids.is_empty() {
        sqlx::query("DELETE FROM snowman_task_leases WHERE community_id=$1 AND task_id=ANY($2)")
            .bind(community_id)
            .bind(&recovered_ids)
            .execute(&mut *tx)
            .await?;
    }
    let mut requeued_tasks = 0_u64;
    let mut dead_lettered_tasks = 0_u64;
    for row in &recovered {
        let request_id: Uuid = row.try_get("request_id")?;
        let task_id: Uuid = row.try_get("task_id")?;
        let status: String = row.try_get("status")?;
        let requeued = status == "queued";
        if requeued {
            requeued_tasks += 1;
        } else {
            dead_lettered_tasks += 1;
        }
        touched_requests.insert(request_id);
        append_maintenance_event(
            &mut tx,
            community_id,
            tick_id,
            request_id,
            Some(task_id),
            if requeued {
                "task.requeued"
            } else {
                "task.dead_lettered"
            },
            &actor_identity,
            serde_json::json!({
                "schema_version": "snowman.workforce.maintenance.event.v1",
                "tick_id": tick_id,
                "reason": "lease_expired",
                "attempt_count": row.try_get::<i32, _>("attempt_count")?,
                "max_attempts": row.try_get::<i32, _>("max_attempts")?,
                "available_at": row.try_get::<DateTime<Utc>, _>("available_at")?
            }),
            observed_at,
        )
        .await?;
    }

    let expired_actions = sqlx::query(
        r#"
        WITH due AS (
          SELECT a.action_id, a.request_id,
            CASE WHEN r.status='expired' THEN 'request_deadline_elapsed'
                 ELSE 'action_expiry_elapsed' END AS reason
          FROM snowman_proactive_actions a
          JOIN snowman_work_requests r
            ON r.community_id=a.community_id AND r.request_id=a.request_id
          WHERE a.community_id=$1
            AND a.status IN ('queued','awaiting_approval','leased','running')
            AND (a.expires_at <= $2 OR r.status='expired')
          ORDER BY a.expires_at, a.action_id
          LIMIT 500 FOR UPDATE OF a SKIP LOCKED
        )
        UPDATE snowman_proactive_actions a SET status='expired'
        FROM due WHERE a.community_id=$1 AND a.action_id=due.action_id
        RETURNING a.request_id, a.action_id, due.reason
        "#,
    )
    .bind(community_id)
    .bind(observed_at)
    .fetch_all(&mut *tx)
    .await?;
    for row in &expired_actions {
        let request_id: Uuid = row.try_get("request_id")?;
        let action_id: Uuid = row.try_get("action_id")?;
        append_maintenance_event(
            &mut tx,
            community_id,
            tick_id,
            request_id,
            None,
            "proactive.expired",
            &actor_identity,
            serde_json::json!({
                "schema_version": "snowman.workforce.maintenance.event.v1",
                "tick_id": tick_id,
                "action_id": action_id,
                "reason": row.try_get::<String, _>("reason")?
            }),
            observed_at,
        )
        .await?;
    }

    for request_id in touched_requests {
        refresh_request_status(&mut tx, community_id, request_id).await?;
    }
    let result = WorkforceMaintenanceResult {
        observed_at,
        expired_requests: expired_request_ids.len() as u64,
        expired_tasks: (expired_task_rows.len() + task_deadlines.len()) as u64,
        expired_proactive_actions: materialized_expired_actions + expired_actions.len() as u64,
        requeued_tasks,
        dead_lettered_tasks,
    };
    sqlx::query(
        "INSERT INTO snowman_workforce_maintenance_ticks \
         (community_id, tick_id, scheduler_identity_id, requested_at, observed_at, result) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(community_id)
    .bind(tick_id)
    .bind(scheduler_identity_id)
    .bind(requested_at)
    .bind(observed_at)
    .bind(serde_json::to_value(&result).map_err(|error| {
        DbError::InvalidData(format!("maintenance receipt serialization failed: {error}"))
    })?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
async fn append_maintenance_event(
    tx: &mut Transaction<'_, Postgres>,
    community_id: Uuid,
    tick_id: Uuid,
    request_id: Uuid,
    task_id: Option<Uuid>,
    event_type: &str,
    actor_identity: &str,
    payload: Value,
    occurred_at: DateTime<Utc>,
) -> Result<()> {
    let target_id = task_id.unwrap_or(request_id);
    let event = NewWorkEvent {
        event_id: maintenance_event_id(tick_id, event_type, target_id, &payload),
        request_id,
        task_id,
        event_type: event_type.to_string(),
        actor_identity: actor_identity.to_string(),
        payload,
        occurred_at,
    };
    validate_work_event(&event)?;
    append_work_event_tx(tx, community_id, &event).await?;
    Ok(())
}

/// Append one request-local event under a PostgreSQL advisory lock so parallel
/// workers cannot fork the sequence or hash chain. Exact event-ID replays return
/// the original coordinates; conflicting reuse fails closed.
pub async fn append_work_event(
    pool: &PgPool,
    community_id: CommunityId,
    event: &NewWorkEvent,
) -> Result<AppendedWorkEvent> {
    validate_work_event(event)?;
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let result = append_work_event_tx(&mut tx, community_id, event).await?;
    tx.commit().await?;
    Ok(result)
}

async fn append_work_event_tx(
    tx: &mut Transaction<'_, Postgres>,
    community_id: Uuid,
    event: &NewWorkEvent,
) -> Result<AppendedWorkEvent> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2::text, 0))")
        .bind(community_id)
        .bind(event.request_id)
        .execute(&mut **tx)
        .await?;

    if let Some(existing) = sqlx::query(
        "SELECT request_id, sequence, event_type, actor_identity, payload, occurred_at, \
                previous_event_sha256, event_sha256, task_id \
         FROM snowman_work_events WHERE community_id=$1 AND event_id=$2",
    )
    .bind(community_id)
    .bind(event.event_id)
    .fetch_optional(&mut **tx)
    .await?
    {
        let previous = optional_vec_to_sha256(existing.try_get("previous_event_sha256")?)?;
        let digest = vec_to_sha256(existing.try_get("event_sha256")?)?;
        let exact_replay = existing.try_get::<Uuid, _>("request_id")? == event.request_id
            && existing.try_get::<String, _>("event_type")? == event.event_type
            && existing.try_get::<String, _>("actor_identity")? == event.actor_identity
            && existing.try_get::<Value, _>("payload")? == event.payload
            && existing.try_get::<DateTime<Utc>, _>("occurred_at")? == event.occurred_at
            && existing.try_get::<Option<Uuid>, _>("task_id")? == event.task_id;
        if !exact_replay {
            return Err(DbError::AccessDenied(
                "work event ID was reused with different evidence".into(),
            ));
        }
        return Ok(AppendedWorkEvent {
            sequence: existing.try_get("sequence")?,
            previous_event_sha256: previous,
            event_sha256: digest,
        });
    }

    let previous = sqlx::query(
        "SELECT sequence, event_sha256 FROM snowman_work_events \
         WHERE community_id=$1 AND request_id=$2 ORDER BY sequence DESC LIMIT 1",
    )
    .bind(community_id)
    .bind(event.request_id)
    .fetch_optional(&mut **tx)
    .await?;
    let sequence = previous
        .as_ref()
        .map(|row| row.try_get::<i64, _>("sequence"))
        .transpose()?
        .map_or(0, |value| value + 1);
    let previous_digest = previous
        .map(|row| vec_to_sha256(row.try_get("event_sha256")?))
        .transpose()?;
    let event_digest = work_event_digest(community_id, sequence, previous_digest, event)?;

    sqlx::query(
        r#"
        INSERT INTO snowman_work_events
          (community_id, event_id, request_id, task_id, sequence, event_type,
           actor_identity, payload, previous_event_sha256, event_sha256, occurred_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(community_id)
    .bind(event.event_id)
    .bind(event.request_id)
    .bind(event.task_id)
    .bind(sequence)
    .bind(&event.event_type)
    .bind(&event.actor_identity)
    .bind(&event.payload)
    .bind(previous_digest.map(|value| value.to_vec()))
    .bind(event_digest.as_slice())
    .bind(event.occurred_at)
    .execute(&mut **tx)
    .await?;
    Ok(AppendedWorkEvent {
        sequence,
        previous_event_sha256: previous_digest,
        event_sha256: event_digest,
    })
}

/// Record spend atomically after enforcing the request's hard cost/token caps.
pub async fn record_work_spend(
    pool: &PgPool,
    community_id: CommunityId,
    entry: &SpendEntry,
) -> Result<()> {
    if entry.ledger_entry_id.is_nil()
        || entry.request_id.is_nil()
        || entry.task_id.is_nil()
        || entry.worker_identity_id.is_nil()
        || entry.lease_generation <= 0
        || entry.model_id.trim().is_empty()
        || entry.input_tokens < 0
        || entry.output_tokens < 0
        || entry.cost_microusd < 0
    {
        return Err(DbError::InvalidData(
            "spend values must be non-negative".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2::text, 0))")
        .bind(community_id)
        .bind(entry.ledger_entry_id)
        .execute(&mut *tx)
        .await?;
    let existing = sqlx::query(
        "SELECT request_id, task_id, worker_identity_id, model_id, input_tokens, output_tokens, \
                cost_microusd, provider_receipt_sha256, recorded_at \
         FROM snowman_spend_ledger WHERE community_id=$1 AND ledger_entry_id=$2",
    )
    .bind(community_id)
    .bind(entry.ledger_entry_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        let exact_replay = existing.try_get::<Uuid, _>("request_id")? == entry.request_id
            && existing.try_get::<Uuid, _>("task_id")? == entry.task_id
            && existing.try_get::<Uuid, _>("worker_identity_id")? == entry.worker_identity_id
            && existing.try_get::<String, _>("model_id")? == entry.model_id
            && existing.try_get::<i64, _>("input_tokens")? == entry.input_tokens
            && existing.try_get::<i64, _>("output_tokens")? == entry.output_tokens
            && existing.try_get::<i64, _>("cost_microusd")? == entry.cost_microusd
            && existing
                .try_get::<Vec<u8>, _>("provider_receipt_sha256")?
                .as_slice()
                == entry.provider_receipt_sha256.as_slice()
            && existing.try_get::<DateTime<Utc>, _>("recorded_at")? == entry.recorded_at;
        if exact_replay {
            tx.commit().await?;
            return Ok(());
        }
        return Err(DbError::AccessDenied(
            "spend ledger entry ID was reused with different evidence".into(),
        ));
    }
    let task = sqlx::query(
        "SELECT t.request_id, t.model_id, t.max_cost_microusd, t.max_output_tokens, EXISTS ( \
           SELECT 1 FROM snowman_task_leases l \
           WHERE l.community_id=t.community_id AND l.task_id=t.task_id \
             AND l.worker_identity_id=$3 AND l.generation=$4 \
             AND l.lease_token_sha256=$5 AND l.expires_at > NOW() \
         ) AND t.service_identity_id=$3 AND EXISTS ( \
           SELECT 1 FROM snowman_workforce_identities i \
           WHERE i.community_id=t.community_id AND i.identity_id=t.service_identity_id \
             AND i.identity_type='service' AND i.role='agent' AND i.status='active' \
             AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW()) \
         ) AND NOT EXISTS ( \
           SELECT 1 FROM unnest(t.required_capabilities) required(capability) \
           WHERE NOT EXISTS ( \
             SELECT 1 FROM snowman_workforce_capability_grants g \
             WHERE g.community_id=t.community_id AND g.identity_id=t.service_identity_id \
               AND g.capability=required.capability AND g.revoked_at IS NULL \
               AND (g.expires_at IS NULL OR g.expires_at > NOW()) \
           ) \
         ) AND EXISTS ( \
           SELECT 1 FROM snowman_model_routes m \
           JOIN snowman_work_requests r \
             ON r.community_id=t.community_id AND r.request_id=t.request_id \
           WHERE m.community_id=t.community_id AND m.model_id=t.model_id \
             AND m.gateway_url=t.model_gateway_route \
             AND m.status='active' AND m.evaluated_at <= NOW() \
             AND t.specialist_role=ANY(m.suited_roles) \
             AND r.classification=ANY(m.allowed_classifications) \
         ) AND ( \
           NOT t.approval_required OR ( \
             SELECT a.decision='approved' \
                    AND a.task_snapshot_sha256=t.execution_snapshot_sha256 \
                    AND a.expires_at > NOW() \
             FROM snowman_work_approvals a \
             WHERE a.community_id=t.community_id AND a.request_id=t.request_id \
               AND a.task_id=t.task_id \
             ORDER BY a.decided_at DESC, a.approval_id DESC LIMIT 1 \
           ) IS TRUE \
         ) AS live_lease \
         FROM snowman_work_tasks t \
         WHERE t.community_id=$1 AND t.task_id=$2 FOR UPDATE OF t",
    )
    .bind(community_id)
    .bind(entry.task_id)
    .bind(entry.worker_identity_id)
    .bind(entry.lease_generation)
    .bind(entry.lease_token_sha256.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if task.try_get::<Uuid, _>("request_id")? != entry.request_id
        || task.try_get::<String, _>("model_id")? != entry.model_id
        || !task.try_get::<bool, _>("live_lease")?
    {
        return Err(DbError::AccessDenied(
            "spend receipt does not match the live task lease, request, and governed model route"
                .into(),
        ));
    }
    let task_used = sqlx::query(
        r#"
        SELECT COALESCE(SUM(cost_microusd),0)::bigint AS cost,
               COALESCE(SUM(output_tokens),0)::bigint AS output
        FROM snowman_spend_ledger
        WHERE community_id=$1 AND task_id=$2
        "#,
    )
    .bind(community_id)
    .bind(entry.task_id)
    .fetch_one(&mut *tx)
    .await?;
    if task_used.try_get::<i64, _>("cost")? + entry.cost_microusd
        > task.try_get::<i64, _>("max_cost_microusd")?
        || task_used.try_get::<i64, _>("output")? + entry.output_tokens
            > task.try_get::<i64, _>("max_output_tokens")?
    {
        return Err(DbError::AccessDenied(
            "Snowman specialist task cost or output-token ceiling would be exceeded".into(),
        ));
    }
    let budget = sqlx::query(
        r#"
        SELECT max_cost_microusd, max_input_tokens, max_output_tokens
        FROM snowman_work_requests
        WHERE community_id=$1 AND request_id=$2
        FOR UPDATE
        "#,
    )
    .bind(community_id)
    .bind(entry.request_id)
    .fetch_one(&mut *tx)
    .await?;
    let used = sqlx::query(
        r#"
        SELECT COALESCE(SUM(cost_microusd),0)::bigint AS cost,
               COALESCE(SUM(input_tokens),0)::bigint AS input,
               COALESCE(SUM(output_tokens),0)::bigint AS output
        FROM snowman_spend_ledger WHERE community_id=$1 AND request_id=$2
        "#,
    )
    .bind(community_id)
    .bind(entry.request_id)
    .fetch_one(&mut *tx)
    .await?;
    let would_exceed = used.try_get::<i64, _>("cost")? + entry.cost_microusd
        > budget.try_get::<i64, _>("max_cost_microusd")?
        || used.try_get::<i64, _>("input")? + entry.input_tokens
            > budget.try_get::<i64, _>("max_input_tokens")?
        || used.try_get::<i64, _>("output")? + entry.output_tokens
            > budget.try_get::<i64, _>("max_output_tokens")?;
    if would_exceed {
        return Err(DbError::AccessDenied(
            "Snowman workforce request budget would be exceeded".into(),
        ));
    }
    sqlx::query(
        r#"
        INSERT INTO snowman_spend_ledger
          (community_id, ledger_entry_id, request_id, task_id, worker_identity_id, model_id,
           input_tokens, output_tokens, cost_microusd,
           provider_receipt_sha256, recorded_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(community_id)
    .bind(entry.ledger_entry_id)
    .bind(entry.request_id)
    .bind(entry.task_id)
    .bind(entry.worker_identity_id)
    .bind(&entry.model_id)
    .bind(entry.input_tokens)
    .bind(entry.output_tokens)
    .bind(entry.cost_microusd)
    .bind(entry.provider_receipt_sha256.as_slice())
    .bind(entry.recorded_at)
    .execute(&mut *tx)
    .await?;
    let spend_event = NewWorkEvent {
        event_id: entry.ledger_entry_id,
        request_id: entry.request_id,
        task_id: Some(entry.task_id),
        event_type: "task.spend_recorded".to_string(),
        actor_identity: format!("snowman-service:{}", entry.worker_identity_id),
        payload: serde_json::json!({
            "model_id": entry.model_id,
            "input_tokens": entry.input_tokens,
            "output_tokens": entry.output_tokens,
            "cost_microusd": entry.cost_microusd,
            "provider_receipt_sha256": hex::encode(entry.provider_receipt_sha256),
        }),
        occurred_at: entry.recorded_at,
    };
    validate_work_event(&spend_event)?;
    append_work_event_tx(&mut tx, community_id, &spend_event).await?;
    tx.commit().await?;
    Ok(())
}

/// Persist a human decision and atomically advance or stop the gated task.
pub async fn record_work_approval(
    pool: &PgPool,
    community_id: CommunityId,
    approval: &WorkApproval,
) -> Result<bool> {
    if approval.approval_id.is_nil()
        || approval.request_id.is_nil()
        || approval.task_id.is_nil()
        || approval.task_snapshot_sha256 == [0; 32]
        || approval.rationale_sha256 == [0; 32]
        || !matches!(
            approval.decision.as_str(),
            "approved" | "denied" | "revoked"
        )
        || approval.approver_identity.trim() != approval.approver_identity
        || approval.approver_identity.is_empty()
        || approval.approver_identity.len() > 256
        || approval.expires_at <= approval.decided_at
        || approval.expires_at - approval.decided_at > Duration::hours(24)
    {
        return Err(DbError::InvalidData(
            "approval requires bounded identities, evidence, decision, and expiry".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let existing = sqlx::query(
        "SELECT request_id, task_id, task_snapshot_sha256, decision, \
                approver_identity, rationale_sha256, decided_at, expires_at \
         FROM snowman_work_approvals WHERE community_id=$1 AND approval_id=$2",
    )
    .bind(community_id)
    .bind(approval.approval_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        let exact = existing.try_get::<Uuid, _>("request_id")? == approval.request_id
            && existing.try_get::<Uuid, _>("task_id")? == approval.task_id
            && existing
                .try_get::<Vec<u8>, _>("task_snapshot_sha256")?
                .as_slice()
                == approval.task_snapshot_sha256.as_slice()
            && existing.try_get::<String, _>("decision")? == approval.decision
            && existing.try_get::<String, _>("approver_identity")? == approval.approver_identity
            && existing
                .try_get::<Vec<u8>, _>("rationale_sha256")?
                .as_slice()
                == approval.rationale_sha256.as_slice()
            && existing.try_get::<DateTime<Utc>, _>("decided_at")? == approval.decided_at
            && existing.try_get::<DateTime<Utc>, _>("expires_at")? == approval.expires_at;
        if exact {
            tx.commit().await?;
            return Ok(false);
        }
        return Err(DbError::AccessDenied(
            "approval identifier was reused for a different decision".into(),
        ));
    }
    let task = sqlx::query(
        "SELECT t.execution_snapshot_sha256, t.approval_required, t.status, r.status AS request_status \
         FROM snowman_work_tasks t JOIN snowman_work_requests r \
           ON r.community_id=t.community_id AND r.request_id=t.request_id \
         WHERE t.community_id=$1 AND t.request_id=$2 AND t.task_id=$3 \
         FOR UPDATE OF t, r",
    )
    .bind(community_id)
    .bind(approval.request_id)
    .bind(approval.task_id)
    .fetch_one(&mut *tx)
    .await?;
    let current_snapshot: Vec<u8> = task.try_get("execution_snapshot_sha256")?;
    if current_snapshot.as_slice() != approval.task_snapshot_sha256.as_slice()
        || !task.try_get::<bool, _>("approval_required")?
        || matches!(
            task.try_get::<String, _>("request_status")?.as_str(),
            "completed" | "failed" | "cancelled" | "expired"
        )
    {
        return Err(DbError::AccessDenied(
            "approval does not match the current gated task snapshot".into(),
        ));
    }
    sqlx::query(
        r#"
        INSERT INTO snowman_work_approvals
          (community_id, request_id, task_id, approval_id, task_snapshot_sha256,
           decision, approver_identity, rationale_sha256, decided_at, expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(community_id)
    .bind(approval.request_id)
    .bind(approval.task_id)
    .bind(approval.approval_id)
    .bind(approval.task_snapshot_sha256.as_slice())
    .bind(&approval.decision)
    .bind(approval.approver_identity.trim())
    .bind(approval.rationale_sha256.as_slice())
    .bind(approval.decided_at)
    .bind(approval.expires_at)
    .execute(&mut *tx)
    .await?;
    let next_status = match approval.decision.as_str() {
        "approved" => "queued",
        "denied" => "failed",
        _ => "awaiting_approval",
    };
    let updated = sqlx::query(
        "UPDATE snowman_work_tasks SET status=$4, updated_at=NOW() \
         WHERE community_id=$1 AND request_id=$2 AND task_id=$3 \
           AND status IN ('awaiting_approval','queued','leased','running','reviewing')",
    )
    .bind(community_id)
    .bind(approval.request_id)
    .bind(approval.task_id)
    .bind(next_status)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(DbError::AccessDenied(
            "approval cannot change a terminal task".into(),
        ));
    }
    if approval.decision != "approved" {
        sqlx::query("DELETE FROM snowman_task_leases WHERE community_id=$1 AND task_id=$2")
            .bind(community_id)
            .bind(approval.task_id)
            .execute(&mut *tx)
            .await?;
    }
    let event = NewWorkEvent {
        event_id: approval.approval_id,
        request_id: approval.request_id,
        task_id: Some(approval.task_id),
        event_type: "task.approval_decided".into(),
        actor_identity: approval.approver_identity.clone(),
        payload: serde_json::json!({
            "schema_version": "snowman.work.event.v1",
            "decision": approval.decision,
            "task_snapshot_sha256": hex::encode(approval.task_snapshot_sha256),
            "rationale_sha256": hex::encode(approval.rationale_sha256),
            "expires_at": approval.expires_at,
            "lease_invalidated": approval.decision != "approved",
        }),
        occurred_at: approval.decided_at,
    };
    validate_work_event(&event)?;
    append_work_event_tx(&mut tx, community_id, &event).await?;
    refresh_request_status(&mut tx, community_id, approval.request_id).await?;
    tx.commit().await?;
    Ok(true)
}

async fn refresh_request_status(
    tx: &mut Transaction<'_, Postgres>,
    community_id: Uuid,
    request_id: Uuid,
) -> Result<()> {
    let counts = sqlx::query(
        r#"
        SELECT COUNT(*)::bigint AS total,
          COUNT(*) FILTER (WHERE status IN ('succeeded','failed','cancelled','expired','dead_lettered'))::bigint AS terminal,
          COUNT(*) FILTER (WHERE status IN ('failed','expired','dead_lettered'))::bigint AS failed,
          COUNT(*) FILTER (WHERE status='cancelled')::bigint AS cancelled,
          COUNT(*) FILTER (WHERE status='awaiting_approval')::bigint AS awaiting,
          COUNT(*) FILTER (WHERE status IN ('leased','running','reviewing'))::bigint AS active,
          EXISTS (
            SELECT 1 FROM snowman_work_schedules s
            WHERE s.community_id=$1 AND s.request_id=$2 AND s.status='active'
              AND s.next_run_at <= s.ends_at AND s.occurrence_count < s.max_occurrences
          ) AS active_schedule
        FROM snowman_work_tasks WHERE community_id=$1 AND request_id=$2
        "#,
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_one(&mut **tx)
    .await?;
    let total: i64 = counts.try_get("total")?;
    let terminal: i64 = counts.try_get("terminal")?;
    let failed: i64 = counts.try_get("failed")?;
    let cancelled: i64 = counts.try_get("cancelled")?;
    let awaiting: i64 = counts.try_get("awaiting")?;
    let active: i64 = counts.try_get("active")?;
    let active_schedule: bool = counts.try_get("active_schedule")?;
    let next = if active_schedule {
        "planned"
    } else if total > 0 && terminal == total {
        if failed > 0 {
            "failed"
        } else if cancelled > 0 {
            "cancelled"
        } else {
            "completed"
        }
    } else if active > 0 {
        "running"
    } else if awaiting > 0 {
        "awaiting_approval"
    } else {
        "planned"
    };
    sqlx::query(
        "UPDATE snowman_work_requests SET status=$3, updated_at=NOW() \
         WHERE community_id=$1 AND request_id=$2 AND status NOT IN ('cancelled','expired')",
    )
    .bind(community_id)
    .bind(request_id)
    .bind(next)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_task(
    tx: &mut Transaction<'_, Postgres>,
    community_id: Uuid,
    request_id: Uuid,
    task: &NewWorkTask,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO snowman_work_tasks
          (community_id, task_id, request_id, parent_task_id, specialist_role,
           service_identity_id, assigned_agent_pubkey, required_capabilities,
           model_gateway_route, model_id, max_cost_microusd, expected_input_tokens,
           max_output_tokens, execution_snapshot_sha256, expected_artifact_contract,
           context_packet_id, risk_tier, reversible, approval_required, status,
           priority, available_at, deadline_at, max_attempts)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
        "#,
    )
    .bind(community_id)
    .bind(task.task_id)
    .bind(request_id)
    .bind(task.parent_task_id)
    .bind(&task.specialist_role)
    .bind(task.service_identity_id)
    .bind(&task.assigned_agent_pubkey)
    .bind(&task.required_capabilities)
    .bind(&task.model_gateway_route)
    .bind(&task.model_id)
    .bind(task.max_cost_microusd)
    .bind(task.expected_input_tokens)
    .bind(task.max_output_tokens)
    .bind(task.execution_snapshot_sha256.as_slice())
    .bind(&task.expected_artifact_contract)
    .bind(task.context_packet_id)
    .bind(&task.risk_tier)
    .bind(task.reversible)
    .bind(task.approval_required)
    .bind(if task.approval_required {
        "awaiting_approval"
    } else {
        "queued"
    })
    .bind(task.priority)
    .bind(task.available_at)
    .bind(task.deadline_at)
    .bind(task.max_attempts)
    .execute(&mut **tx)
    .await?;
    for reference in &task.context_references {
        sqlx::query(
            "INSERT INTO snowman_work_task_context_refs \
             (community_id, request_id, task_id, context_reference) VALUES ($1,$2,$3,$4)",
        )
        .bind(community_id)
        .bind(request_id)
        .bind(task.task_id)
        .bind(reference)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

fn validate_new_request(request: &NewWorkRequest) -> Result<()> {
    if request.idempotency_key.trim().is_empty()
        || request.requester_identity.trim().is_empty()
        || request.objective.trim().is_empty()
        || request.tasks.is_empty()
        || request.request_contract_sha256 == [0; 32]
    {
        return Err(DbError::InvalidData(
            "idempotency key, requester, objective, and at least one task are required".into(),
        ));
    }
    if request.max_cost_microusd < 0
        || request.max_input_tokens < 0
        || request.max_output_tokens < 0
    {
        return Err(DbError::InvalidData(
            "work request budgets must be non-negative".into(),
        ));
    }
    let mut task_ids = std::collections::HashSet::new();
    let mut reserved_cost = 0_i64;
    let mut reserved_input = 0_i64;
    let mut reserved_output = 0_i64;
    for task in &request.tasks {
        if !task_ids.insert(task.task_id) {
            return Err(DbError::InvalidData(
                "duplicate task ID in work graph".into(),
            ));
        }
        validate_model_gateway_route(&task.model_gateway_route)?;
        if task.max_cost_microusd < 0
            || task.expected_input_tokens < 0
            || task.max_output_tokens < 0
        {
            return Err(DbError::InvalidData(
                "task budgets must be non-negative".into(),
            ));
        }
        reserved_cost = reserved_cost
            .checked_add(task.max_cost_microusd)
            .ok_or_else(|| DbError::InvalidData("task cost budget overflowed".into()))?;
        reserved_input = reserved_input
            .checked_add(task.expected_input_tokens)
            .ok_or_else(|| DbError::InvalidData("task input budget overflowed".into()))?;
        reserved_output = reserved_output
            .checked_add(task.max_output_tokens)
            .ok_or_else(|| DbError::InvalidData("task output budget overflowed".into()))?;
        if task.context_references.len() > 64
            || task
                .context_references
                .iter()
                .any(|reference| !is_context_reference(reference))
        {
            return Err(DbError::AccessDenied(
                "task context must use at most 64 immutable Snowman or Analyst references".into(),
            ));
        }
        if !valid_capability_set(&task.required_capabilities) {
            return Err(DbError::AccessDenied(
                "task capabilities must be explicit, namespaced, and non-ambient".into(),
            ));
        }
        if task.risk_tier == "prohibited" || (!task.reversible && !task.approval_required) {
            return Err(DbError::AccessDenied(
                "prohibited or irreversible work requires a different human-gated plan".into(),
            ));
        }
    }
    if reserved_cost > request.max_cost_microusd
        || reserved_input > request.max_input_tokens
        || reserved_output > request.max_output_tokens
    {
        return Err(DbError::AccessDenied(
            "task reservations exceed the request budget".into(),
        ));
    }
    Ok(())
}

fn validate_model_gateway_route(route: &str) -> Result<()> {
    let parsed = Url::parse(route).map_err(|_| {
        DbError::AccessDenied("model route must be a valid Snowman-controlled HTTPS URL".into())
    })?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let snowman_host = host == "snowmanai.org" || host.ends_with(".snowmanai.org");
    if parsed.scheme() != "https"
        || !snowman_host
        || parsed.port_or_known_default() != Some(443)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DbError::AccessDenied(
            "model route must use a credential-free Snowman-controlled HTTPS gateway on port 443"
                .into(),
        ));
    }
    Ok(())
}

fn valid_capability_set(capabilities: &[String]) -> bool {
    !capabilities.is_empty()
        && capabilities.len() <= 32
        && capabilities.iter().all(|capability| {
            capability.len() <= 128
                && capability.contains('.')
                && capability.chars().all(|character| {
                    character.is_ascii_lowercase()
                        || character.is_ascii_digit()
                        || matches!(character, '.' | '_')
                })
                && !matches!(
                    capability.as_str(),
                    "admin.all" | "aws.all" | "filesystem.all" | "network.all" | "tool.all"
                )
        })
}

fn valid_proactive_execution(role: &str, capability: &str) -> bool {
    matches!(
        (role, capability),
        ("governed_analyst", "analytics.query")
            | ("client_delivery", "artifact.build")
            | ("quality_risk_reviewer", "artifact.build")
            | ("research_evidence", "evidence.manifest.read")
            | ("deadline_operations", "deadline.remind")
    )
}

fn planned_graph_is_acyclic(tasks: &[NewPlannedTask]) -> bool {
    use std::collections::{HashMap, HashSet};

    let graph: HashMap<_, _> = tasks
        .iter()
        .map(|planned| (planned.task.task_id, planned.depends_on.as_slice()))
        .collect();
    fn visit(
        task_id: Uuid,
        graph: &HashMap<Uuid, &[Uuid]>,
        visiting: &mut HashSet<Uuid>,
        visited: &mut HashSet<Uuid>,
    ) -> bool {
        if visited.contains(&task_id) {
            return true;
        }
        if !visiting.insert(task_id) {
            return false;
        }
        let acyclic = graph[&task_id]
            .iter()
            .all(|dependency| visit(*dependency, graph, visiting, visited));
        visiting.remove(&task_id);
        if acyclic {
            visited.insert(task_id);
        }
        acyclic
    }
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    graph
        .keys()
        .all(|task_id| visit(*task_id, &graph, &mut visiting, &mut visited))
}

fn is_context_reference(reference: &str) -> bool {
    let digest = reference
        .strip_prefix("analyst360:sha256:")
        .or_else(|| reference.strip_prefix("snowman:sha256:"));
    digest.is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn valid_reason_code(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 128
        && reason.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_' | '-')
        })
}

fn validate_work_event(event: &NewWorkEvent) -> Result<()> {
    let event_type = event.event_type.trim();
    if event_type.is_empty()
        || event_type != event.event_type
        || event_type.len() > 128
        || !event_type.contains('.')
        || !event_type.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_' | '-')
        })
        || event.actor_identity.trim().is_empty()
        || event.actor_identity.trim() != event.actor_identity
        || event.actor_identity.len() > 256
    {
        return Err(DbError::InvalidData(
            "work event requires a namespaced type and bounded actor identity".into(),
        ));
    }
    let payload = serde_json::to_vec(&event.payload)
        .map_err(|error| DbError::InvalidData(format!("invalid work event payload: {error}")))?;
    if payload.len() > 65_536 {
        return Err(DbError::InvalidData(
            "work event payload exceeds the 64 KiB metadata limit".into(),
        ));
    }
    if value_contains_secret_key(&event.payload) {
        return Err(DbError::AccessDenied(
            "work event payload contains a credential-like field".into(),
        ));
    }
    Ok(())
}

fn value_contains_secret_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let normalized = key.to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                "authorization"
                    | "credential"
                    | "credentials"
                    | "password"
                    | "private_key"
                    | "secret"
                    | "token"
            ) || value_contains_secret_key(value)
        }),
        Value::Array(values) => values.iter().any(value_contains_secret_key),
        _ => false,
    }
}

fn work_event_digest(
    community_id: Uuid,
    sequence: i64,
    previous_event_sha256: Option<[u8; 32]>,
    event: &NewWorkEvent,
) -> Result<[u8; 32]> {
    let payload = serde_json::to_vec(&event.payload)
        .map_err(|error| DbError::InvalidData(format!("invalid work event payload: {error}")))?;
    let sequence_bytes = sequence.to_be_bytes();
    let occurred_at = event
        .occurred_at
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let task_id_bytes = event.task_id.map(|value| *value.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.work.event.v1\0");
    update_digest_field(&mut hasher, community_id.as_bytes());
    update_digest_field(&mut hasher, event.request_id.as_bytes());
    update_digest_field(
        &mut hasher,
        task_id_bytes.as_ref().map_or(&[], |value| value.as_slice()),
    );
    update_digest_field(&mut hasher, &sequence_bytes);
    update_digest_field(
        &mut hasher,
        previous_event_sha256
            .as_ref()
            .map_or(&[], |value| value.as_slice()),
    );
    update_digest_field(&mut hasher, event.event_id.as_bytes());
    update_digest_field(&mut hasher, event.event_type.as_bytes());
    update_digest_field(&mut hasher, event.actor_identity.as_bytes());
    update_digest_field(&mut hasher, occurred_at.as_bytes());
    update_digest_field(&mut hasher, &payload);
    Ok(hasher.finalize().into())
}

fn update_digest_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn schedule_occurrence_uuid(
    domain: &[u8],
    schedule_id: Uuid,
    occurrence_number: i32,
    due_at: DateTime<Utc>,
) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_digest_field(&mut hasher, schedule_id.as_bytes());
    update_digest_field(&mut hasher, &occurrence_number.to_be_bytes());
    update_digest_field(&mut hasher, &due_at.timestamp_micros().to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn schedule_occurrence_from_rows(
    occurrence: &sqlx::postgres::PgRow,
    schedule: &sqlx::postgres::PgRow,
) -> Result<ClaimedWorkScheduleOccurrence> {
    Ok(ClaimedWorkScheduleOccurrence {
        schedule_id: occurrence.try_get("schedule_id")?,
        occurrence_id: occurrence.try_get("occurrence_id")?,
        request_id: occurrence.try_get("request_id")?,
        action_id: occurrence.try_get("action_id")?,
        claim_generation: occurrence.try_get("claim_generation")?,
        executor_identity_id: schedule.try_get("executor_identity_id")?,
        specialist_role: schedule.try_get("specialist_role")?,
        capability: schedule.try_get("capability")?,
        instruction_reference: schedule.try_get("instruction_reference")?,
        context_references: schedule.try_get("context_references")?,
        requested_model_id: schedule.try_get("requested_model_id")?,
        expected_input_tokens: schedule.try_get("expected_input_tokens")?,
        max_output_tokens: schedule.try_get("max_output_tokens")?,
        max_cost_microusd: schedule.try_get("max_cost_microusd")?,
        expected_artifact_type: schedule.try_get("expected_artifact_type")?,
        risk_tier: schedule.try_get("risk_tier")?,
        reversible: schedule.try_get("reversible")?,
        confidence_basis_points: schedule.try_get("confidence_basis_points")?,
        usefulness_sha256: vec_to_sha256(schedule.try_get("usefulness_sha256")?)?,
        source_event_sha256: vec_to_sha256(occurrence.try_get("source_event_sha256")?)?,
        proposed_at: occurrence.try_get("proposed_at")?,
        scheduled_for: occurrence.try_get("scheduled_for")?,
        expires_at: occurrence.try_get("expires_at")?,
        max_attempts: schedule.try_get("max_attempts")?,
    })
}

fn maintenance_event_id(tick_id: Uuid, event_type: &str, target_id: Uuid, payload: &Value) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.workforce.maintenance-event.v1\0");
    update_digest_field(&mut hasher, tick_id.as_bytes());
    update_digest_field(&mut hasher, event_type.as_bytes());
    update_digest_field(&mut hasher, target_id.as_bytes());
    update_digest_field(
        &mut hasher,
        &serde_json::to_vec(payload).expect("JSON value serialization cannot fail"),
    );
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn vec_to_sha256(value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| DbError::InvalidData("expected a 32-byte SHA-256 digest".into()))
}

fn optional_vec_to_sha256(value: Option<Vec<u8>>) -> Result<Option<[u8; 32]>> {
    value.map(vec_to_sha256).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> NewWorkRequest {
        let request_id = Uuid::new_v4();
        NewWorkRequest {
            request_id,
            idempotency_key: "user-request-1".into(),
            requester_identity: "google:founder@snowmanai.org".into(),
            request_contract_sha256: sha256(b"complete-request-contract-v1"),
            objective: "Prepare an evidence-backed client-ready brief.".into(),
            classification: "confidential".into(),
            deadline_at: None,
            max_cost_microusd: 5_000_000,
            max_input_tokens: 500_000,
            max_output_tokens: 100_000,
            client_ready_delivery: true,
            tasks: vec![NewWorkTask {
                task_id: Uuid::new_v4(),
                parent_task_id: None,
                specialist_role: "research_evidence".into(),
                service_identity_id: Uuid::new_v4(),
                assigned_agent_pubkey: None,
                required_capabilities: vec!["context.read".into()],
                model_gateway_route: "https://models.snowmanai.org/anthropic".into(),
                model_id: "snowman-research-model".into(),
                max_cost_microusd: 1_000_000,
                expected_input_tokens: 10_000,
                max_output_tokens: 2_000,
                execution_snapshot_sha256: sha256(b"safe-task-v1"),
                expected_artifact_contract: serde_json::json!({"type": "brief"}),
                context_references: vec![format!("analyst360:sha256:{}", "a".repeat(64))],
                context_packet_id: None,
                risk_tier: "low".into(),
                reversible: true,
                approval_required: false,
                priority: 50,
                available_at: Utc::now(),
                deadline_at: None,
                max_attempts: 3,
            }],
        }
    }

    fn event() -> NewWorkEvent {
        NewWorkEvent {
            event_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(2),
            task_id: Some(Uuid::from_u128(3)),
            event_type: "task.claimed".into(),
            actor_identity: "snowman-service:research-worker".into(),
            payload: serde_json::json!({
                "artifact_ref": "sha256:abc",
                "lease_generation": 1
            }),
            occurred_at: DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[test]
    fn validates_safe_snowman_work_graph() {
        validate_new_request(&request()).expect("safe request");
    }

    #[test]
    fn rejects_direct_model_provider_and_irreversible_autonomy() {
        let mut direct = request();
        direct.tasks[0].model_gateway_route = "https://api.openai.com/v1".into();
        assert!(matches!(
            validate_new_request(&direct),
            Err(DbError::AccessDenied(_))
        ));

        let mut unsafe_request = request();
        unsafe_request.tasks[0].reversible = false;
        unsafe_request.tasks[0].approval_required = false;
        assert!(matches!(
            validate_new_request(&unsafe_request),
            Err(DbError::AccessDenied(_))
        ));
    }

    #[test]
    fn rejects_snowman_lookalike_model_route() {
        let mut invalid = request();
        invalid.tasks[0].model_gateway_route =
            "https://evil.example/.snowmanai.org/anthropic".into();
        assert!(matches!(
            validate_new_request(&invalid),
            Err(DbError::AccessDenied(_))
        ));
    }

    #[test]
    fn rejects_duplicate_task_ids() {
        let mut invalid = request();
        invalid.tasks.push(invalid.tasks[0].clone());
        assert!(matches!(
            validate_new_request(&invalid),
            Err(DbError::InvalidData(_))
        ));
    }

    #[test]
    fn work_event_digest_is_deterministic_and_chain_bound() {
        let event = event();
        let community = Uuid::from_u128(4);
        let first = work_event_digest(community, 0, None, &event).unwrap();
        assert_eq!(
            first,
            work_event_digest(community, 0, None, &event).unwrap()
        );
        assert_ne!(
            first,
            work_event_digest(community, 1, Some(first), &event).unwrap()
        );
    }

    #[test]
    fn work_event_rejects_nested_credentials() {
        let mut invalid = event();
        invalid.payload = serde_json::json!({"details": {"authorization": "Bearer nope"}});
        assert!(matches!(
            validate_work_event(&invalid),
            Err(DbError::AccessDenied(_))
        ));
    }

    #[test]
    fn maintenance_event_ids_are_deterministic_and_domain_bound() {
        let tick = Uuid::from_u128(10);
        let target = Uuid::from_u128(11);
        let payload = serde_json::json!({"reason": "lease_expired"});
        let event_id = maintenance_event_id(tick, "task.requeued", target, &payload);
        assert_eq!(
            event_id,
            maintenance_event_id(tick, "task.requeued", target, &payload)
        );
        assert_ne!(
            event_id,
            maintenance_event_id(tick, "task.dead_lettered", target, &payload)
        );
        assert_ne!(
            event_id,
            maintenance_event_id(
                tick,
                "task.requeued",
                target,
                &serde_json::json!({"reason": "task_deadline_elapsed"})
            )
        );
        assert_eq!(event_id.get_version_num(), 5);
    }

    #[test]
    fn schedule_occurrence_ids_are_deterministic_and_domain_bound() {
        let schedule = Uuid::from_u128(42);
        let due_at = "2026-07-27T00:00:00Z".parse().unwrap();
        let occurrence =
            schedule_occurrence_uuid(b"snowman.schedule-occurrence.v1\0", schedule, 3, due_at);
        assert_eq!(
            occurrence,
            schedule_occurrence_uuid(b"snowman.schedule-occurrence.v1\0", schedule, 3, due_at)
        );
        assert_ne!(
            occurrence,
            schedule_occurrence_uuid(b"snowman.schedule-action.v1\0", schedule, 3, due_at)
        );
        assert_ne!(
            occurrence,
            schedule_occurrence_uuid(b"snowman.schedule-occurrence.v1\0", schedule, 4, due_at)
        );
    }

    #[test]
    fn maintenance_receipt_round_trips_exactly() {
        let receipt = WorkforceMaintenanceResult {
            observed_at: DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            expired_requests: 1,
            expired_tasks: 2,
            expired_proactive_actions: 3,
            requeued_tasks: 4,
            dead_lettered_tasks: 5,
        };
        let stored = serde_json::to_value(&receipt).unwrap();
        assert_eq!(
            receipt,
            serde_json::from_value::<WorkforceMaintenanceResult>(stored).unwrap()
        );
    }

    #[test]
    fn proactive_execution_is_bound_to_worker_supported_role_capability_pairs() {
        assert!(valid_proactive_execution(
            "governed_analyst",
            "analytics.query"
        ));
        assert!(valid_proactive_execution(
            "quality_risk_reviewer",
            "artifact.build"
        ));
        assert!(valid_proactive_execution(
            "deadline_operations",
            "deadline.remind"
        ));
        assert!(!valid_proactive_execution(
            "deadline_operations",
            "calendar.write"
        ));
        assert!(!valid_proactive_execution(
            "governed_analyst",
            "artifact.build"
        ));
    }

    #[test]
    fn cancellation_reason_codes_are_bounded_and_machine_readable() {
        assert!(valid_reason_code("user.requested"));
        assert!(valid_reason_code("objective_superseded-2"));
        assert!(!valid_reason_code(""));
        assert!(!valid_reason_code("contains spaces"));
        assert!(!valid_reason_code("UPPERCASE"));
        assert!(!valid_reason_code(&"a".repeat(129)));
    }
}
