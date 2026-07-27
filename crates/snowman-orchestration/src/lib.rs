#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Fail-closed policy contracts for Snowman's continuously operating specialist teams.
//!
//! This crate is deliberately not a scheduler, model client, tool runner, or memory
//! store. It validates metadata-only plans and decides whether an already-governed
//! workforce task may be dispatched. Execution is composed through the existing
//! workforce lease, agent coordinator, model gateway, tool broker, and Analyst 360
//! evidence contracts. Raw client records, mail, transcripts, prompts, credentials,
//! provider endpoints, and arbitrary tool input have no representation here.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Exact orchestration-plan schema.
pub const PLAN_SCHEMA: &str = "snowman.orchestration.plan.v1";
/// Exact work-product receipt schema.
pub const RECEIPT_SCHEMA: &str = "snowman.orchestration.work-product-receipt.v1";
/// Exact aggregate progress schema.
pub const PROGRESS_SCHEMA: &str = "snowman.orchestration.progress.v1";

const MAX_PERSONAS: usize = 32;
const MAX_TASKS: usize = 128;
const MAX_REFS: usize = 128;
const MAX_GRANTS: usize = 32;
const MAX_REMINDERS: usize = 16;

/// Governed data classification. Ordering is increasing sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Snowman internal, non-client-confidential work.
    Internal,
    /// Client-confidential or Snowman-confidential work product.
    Confidential,
    /// Material subject to the narrowest approved runtime route.
    Restricted,
}

/// User-visible reason an orchestration plan exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkKind {
    /// A direct user request.
    UserRequest,
    /// A multi-step project outcome.
    Project,
    /// A deadline or reminder obligation.
    Deadline,
    /// A human-authorized recurring analysis.
    RecurringAnalytics,
    /// A policy-evaluated next-best-action proposal.
    NextBestAction,
}

/// Live authority state of a plan generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanState {
    /// Persisted for review; it cannot dispatch work.
    Draft,
    /// Current generation may dispatch under policy.
    Active,
    /// Temporarily stopped without discarding evidence.
    Paused,
    /// All required work products were accepted.
    Completed,
    /// User or policy cancelled this generation.
    Cancelled,
    /// A newer generation replaced this one.
    Superseded,
}

/// Local-time quiet-hours definition. The live scheduler must evaluate this
/// against a pinned IANA time-zone database and record that database version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuietHours {
    /// IANA time-zone name such as `America/Denver`.
    pub timezone: String,
    /// First quiet minute in local wall time, inclusive.
    pub start_local_minute: u16,
    /// First non-quiet minute in local wall time, exclusive.
    pub end_local_minute: u16,
    /// Whether metadata-only deadline reminders may be delivered during quiet hours.
    pub allow_deadline_reminders: bool,
}

impl QuietHours {
    /// Return whether an already timezone-resolved local wall-clock minute is quiet.
    pub fn contains_local_minute(&self, minute: u16) -> bool {
        if minute >= 1_440 || self.start_local_minute == self.end_local_minute {
            return false;
        }
        if self.start_local_minute < self.end_local_minute {
            (self.start_local_minute..self.end_local_minute).contains(&minute)
        } else {
            minute >= self.start_local_minute || minute < self.end_local_minute
        }
    }
}

/// Bounded scheduling policy. Cron expressions and arbitrary executable text
/// are intentionally excluded; recurring cadence authority is an existing
/// Snowman work-schedule generation reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulePolicy {
    /// Optional existing `snowman_work_schedules` generation coordinate.
    pub recurring_schedule_ref: Option<String>,
    /// Hard plan deadline.
    pub deadline_at: DateTime<Utc>,
    /// Sorted, unique seconds-before-deadline reminder offsets.
    pub reminder_offsets_seconds: Vec<u32>,
    /// Tenant/user local-time interruption policy.
    pub quiet_hours: QuietHours,
}

/// A configurable specialist identity and its reviewed model/tool envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecialistPersona {
    /// Stable persona identifier.
    pub persona_id: Uuid,
    /// Digest of the reviewed persona/system-policy version.
    pub persona_version_sha256: [u8; 32],
    /// Distinct Snowman workforce service identity.
    pub service_identity_id: Uuid,
    /// Exact policy role used by the existing coordinator/model gateway.
    pub specialist_role: String,
    /// Exact evaluated model catalog identifier.
    pub model_id: String,
    /// Immutable Snowman model-route revision coordinate, never a provider URL.
    pub model_route_ref: String,
    /// Exact tool-broker capability grants; wildcard capabilities are invalid.
    pub tool_capability_grants: BTreeSet<String>,
    /// Most sensitive data classification this persona route may receive.
    pub maximum_classification: Classification,
    /// Hard cumulative persona spend ceiling for this plan generation.
    pub max_cost_microusd: u64,
    /// Persona is default-off until explicitly enabled by governed configuration.
    pub enabled: bool,
}

/// Evidence-grounded score for one proposed unit of work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionScore {
    /// Confidence in basis points.
    pub confidence_basis_points: u16,
    /// Expected user/client value in basis points.
    pub value_basis_points: u16,
    /// Expected harm/irreversibility risk in basis points.
    pub risk_basis_points: u16,
    /// Digest of immutable evidence supporting the score.
    pub usefulness_sha256: [u8; 32],
}

/// One node in the specialist-team dependency DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationTask {
    /// Existing `snowman_work_tasks` identifier.
    pub task_id: Uuid,
    /// Persona assigned to this exact task.
    pub persona_id: Uuid,
    /// Task dependencies, all within the same plan generation.
    pub depends_on: BTreeSet<Uuid>,
    /// Immutable Analyst 360 context-manifest references only.
    pub analyst_context_manifest_refs: BTreeSet<String>,
    /// Subset of the persona's exact tool grants needed by this task.
    pub required_capabilities: BTreeSet<String>,
    /// Bounded artifact contract labels; no artifact bodies.
    pub expected_artifact_types: BTreeSet<String>,
    /// Task-specific action assessment.
    pub score: ActionScore,
    /// Whether an exact compensating/reversal path exists.
    pub reversible: bool,
    /// Whether live human approval is mandatory regardless of score.
    pub approval_required: bool,
    /// Whether policy may consider automatic execution.
    pub automatic_execution_candidate: bool,
    /// Hard task deadline, bounded by the plan deadline.
    pub deadline_at: DateTime<Utc>,
    /// Hard task cost ceiling.
    pub max_cost_microusd: u64,
}

/// Default-off policy for useful, low-risk, reversible automatic work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticExecutionPolicy {
    /// Master switch; false for every newly created plan.
    pub enabled: bool,
    /// Exact capability allowlist.
    pub allowed_capabilities: BTreeSet<String>,
    /// Minimum confidence.
    pub minimum_confidence_basis_points: u16,
    /// Minimum expected value.
    pub minimum_value_basis_points: u16,
    /// Maximum allowed risk.
    pub maximum_risk_basis_points: u16,
    /// Maximum automatic cost for any single task.
    pub max_task_cost_microusd: u64,
}

/// Metadata-only orchestration plan for one tenant/workspace/request generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrchestrationPlan {
    /// Exact schema version.
    pub schema_version: String,
    /// Stable plan identifier.
    pub plan_id: Uuid,
    /// Tenant/community boundary.
    pub community_id: Uuid,
    /// Snowman workspace boundary.
    pub workspace_id: Uuid,
    /// Existing workforce request.
    pub request_id: Uuid,
    /// Optional project coordinate.
    pub project_id: Option<Uuid>,
    /// Why the plan exists.
    pub work_kind: WorkKind,
    /// Monotonic plan authority generation.
    pub generation: u64,
    /// Prior plan replaced by this generation, when applicable.
    pub supersedes_plan_id: Option<Uuid>,
    /// Current authority state.
    pub state: PlanState,
    /// Digest of the objective retained by Analyst 360.
    pub objective_sha256: [u8; 32],
    /// Governed classification.
    pub classification: Classification,
    /// Hard plan spend ceiling.
    pub max_cost_microusd: u64,
    /// Scheduling, deadline, reminders, quiet hours, and timezone.
    pub schedule: SchedulePolicy,
    /// Default-off automatic execution policy.
    pub automatic_execution: AutomaticExecutionPolicy,
    /// Configured specialist team.
    pub personas: Vec<SpecialistPersona>,
    /// Dependency-ordered units of work.
    pub tasks: Vec<OrchestrationTask>,
}

/// Current crash-fenced lease evidence from the existing workforce task lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFence {
    /// Exact tenant.
    pub community_id: Uuid,
    /// Exact task.
    pub task_id: Uuid,
    /// Monotonic workforce lease generation.
    pub lease_generation: u64,
    /// Digest of the lease bearer token; never the token.
    pub lease_token_sha256: [u8; 32],
    /// Lease expiration.
    pub expires_at: DateTime<Utc>,
}

/// Live input used for one deterministic dispatch decision.
pub struct DispatchContext<'a> {
    /// Plan under evaluation.
    pub plan: &'a OrchestrationPlan,
    /// Task under evaluation.
    pub task_id: Uuid,
    /// Generation currently authoritative in durable state.
    pub live_plan_generation: u64,
    /// Task IDs with accepted successful receipts in the current generation.
    pub completed_dependencies: &'a BTreeSet<Uuid>,
    /// Current request spend.
    pub spent_microusd: u64,
    /// Whether an unexpired, exact human approval exists.
    pub human_approval_present: bool,
    /// Trusted current time.
    pub now: DateTime<Utc>,
    /// Local wall-clock minute resolved using the recorded IANA timezone.
    pub local_minute: u16,
}

/// Deterministic dispatch outcome. It grants no model or tool credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchDecision {
    /// Dependencies are not complete.
    WaitForDependencies,
    /// Quiet hours defer non-reminder work.
    DeferForQuietHours,
    /// A live exact approval is required.
    AwaitHumanApproval,
    /// The plan or task deadline expired.
    Expired,
    /// The request or task cost ceiling is exhausted.
    BudgetExhausted,
    /// Plan authority is paused, cancelled, completed, superseded, or stale.
    NoLiveAuthority,
    /// Safe useful work may use the normal coordinator/broker path automatically.
    ExecuteAutomatically,
    /// An exact approval authorizes the normal coordinator/broker path.
    ExecuteWithApproval,
}

/// Stable work-product outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    /// Required artifacts and evidence were produced.
    Succeeded,
    /// Work is blocked and requires a new governed task/decision.
    Blocked,
    /// Work failed without raw diagnostic retention here.
    Failed,
    /// Authority was cancelled before completion.
    Cancelled,
}

/// Evidence-preserving, metadata-only terminal receipt for one task generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkProductReceipt {
    /// Exact schema version.
    pub schema_version: String,
    /// Tenant boundary.
    pub community_id: Uuid,
    /// Workspace boundary.
    pub workspace_id: Uuid,
    /// Plan boundary.
    pub plan_id: Uuid,
    /// Exact plan generation.
    pub plan_generation: u64,
    /// Task boundary.
    pub task_id: Uuid,
    /// Workforce lease generation that produced the receipt.
    pub lease_generation: u64,
    /// Digest of the exact execution snapshot.
    pub execution_snapshot_sha256: [u8; 32],
    /// Terminal outcome.
    pub outcome: ReceiptOutcome,
    /// Immutable Analyst 360 work-product references.
    pub artifact_refs: BTreeSet<String>,
    /// Immutable Analyst 360 evidence/citation manifest references.
    pub evidence_refs: BTreeSet<String>,
    /// Existing coordinator/model/tool receipt coordinates, never credentials.
    pub execution_receipt_refs: BTreeSet<String>,
    /// Analyst 360 context/handoff manifest for replacement agents.
    pub handoff_manifest_ref: String,
    /// Digest of the handoff manifest bytes.
    pub handoff_manifest_sha256: [u8; 32],
    /// Actual accounted cost.
    pub actual_cost_microusd: u64,
    /// Trusted acceptance time.
    pub completed_at: DateTime<Utc>,
}

/// Aggregated request progress used to render status and resume work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressDigest {
    /// Exact schema version.
    pub schema_version: String,
    /// Plan identifier.
    pub plan_id: Uuid,
    /// Exact generation.
    pub plan_generation: u64,
    /// Digest over sorted accepted receipt coordinates.
    pub accepted_receipts_sha256: [u8; 32],
    /// Successfully completed tasks.
    pub completed_task_ids: BTreeSet<Uuid>,
    /// Tasks whose dependencies are now satisfied.
    pub next_ready_task_ids: BTreeSet<Uuid>,
    /// Cost accounted by accepted receipts.
    pub accounted_cost_microusd: u64,
}

/// Contract validation failures contain no user content.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Plan metadata violates the bounded contract.
    #[error("orchestration plan is invalid: {0}")]
    InvalidPlan(&'static str),
    /// Receipt metadata violates the bounded contract.
    #[error("orchestration receipt is invalid: {0}")]
    InvalidReceipt(&'static str),
}

/// Validate a complete plan before it is persisted or activated.
pub fn validate_plan(plan: &OrchestrationPlan) -> Result<(), Error> {
    if plan.schema_version != PLAN_SCHEMA
        || plan.plan_id.is_nil()
        || plan.community_id.is_nil()
        || plan.workspace_id.is_nil()
        || plan.request_id.is_nil()
        || plan.objective_sha256 == [0; 32]
        || plan.generation == 0
        || plan.personas.is_empty()
        || plan.personas.len() > MAX_PERSONAS
        || plan.tasks.is_empty()
        || plan.tasks.len() > MAX_TASKS
    {
        return Err(Error::InvalidPlan(
            "identity, schema, objective, generation, team, tasks, and deadline are required",
        ));
    }
    if (plan.generation == 1) != plan.supersedes_plan_id.is_none()
        || plan.supersedes_plan_id == Some(plan.plan_id)
    {
        return Err(Error::InvalidPlan(
            "supersession must accompany every generation after the first",
        ));
    }
    validate_schedule(&plan.schedule)?;
    validate_automatic_policy(&plan.automatic_execution)?;

    let mut personas = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for persona in &plan.personas {
        if persona.persona_id.is_nil()
            || persona.service_identity_id.is_nil()
            || persona.persona_version_sha256 == [0; 32]
            || !identities.insert(persona.service_identity_id)
            || !valid_identifier(&persona.specialist_role, 128)
            || !valid_identifier(&persona.model_id, 256)
            || !valid_model_route_ref(&persona.model_route_ref)
            || persona.tool_capability_grants.len() > MAX_GRANTS
            || persona
                .tool_capability_grants
                .iter()
                .any(|grant| !valid_capability(grant) || ambient_capability(grant))
            || personas.insert(persona.persona_id, persona).is_some()
        {
            return Err(Error::InvalidPlan(
                "persona identity, model route, capability, or version is invalid",
            ));
        }
    }

    let mut tasks = BTreeMap::new();
    let mut reserved = 0_u64;
    let mut persona_reserved: BTreeMap<Uuid, u64> = BTreeMap::new();
    for task in &plan.tasks {
        let Some(persona) = personas.get(&task.persona_id) else {
            return Err(Error::InvalidPlan("task references an unknown persona"));
        };
        if task.task_id.is_nil()
            || task.score.usefulness_sha256 == [0; 32]
            || task.score.confidence_basis_points > 10_000
            || task.score.value_basis_points > 10_000
            || task.score.risk_basis_points > 10_000
            || task.analyst_context_manifest_refs.len() > MAX_REFS
            || task
                .analyst_context_manifest_refs
                .iter()
                .any(|reference| !valid_analyst_ref(reference))
            || task.required_capabilities.is_empty()
            || task.required_capabilities.len() > MAX_GRANTS
            || !task
                .required_capabilities
                .is_subset(&persona.tool_capability_grants)
            || task.expected_artifact_types.is_empty()
            || task.expected_artifact_types.len() > 32
            || task
                .expected_artifact_types
                .iter()
                .any(|kind| !valid_identifier(kind, 128))
            || plan.classification > persona.maximum_classification
            || task.deadline_at > plan.schedule.deadline_at
            || (!task.reversible && !task.approval_required)
            || (task.automatic_execution_candidate && (!task.reversible || task.approval_required))
            || tasks.insert(task.task_id, task).is_some()
        {
            return Err(Error::InvalidPlan(
                "task capability, context, score, deadline, risk, artifact, or identity is invalid",
            ));
        }
        reserved = reserved
            .checked_add(task.max_cost_microusd)
            .ok_or(Error::InvalidPlan("plan cost overflow"))?;
        let entry = persona_reserved.entry(task.persona_id).or_default();
        *entry = entry
            .checked_add(task.max_cost_microusd)
            .ok_or(Error::InvalidPlan("persona cost overflow"))?;
    }
    if reserved > plan.max_cost_microusd
        || persona_reserved
            .iter()
            .any(|(id, total)| *total > personas[id].max_cost_microusd)
    {
        return Err(Error::InvalidPlan(
            "task ceilings exceed plan or persona budget",
        ));
    }
    validate_dag(&tasks)
}

/// Decide whether one task can enter the existing fenced coordinator path.
pub fn decide_dispatch(context: &DispatchContext<'_>) -> Result<DispatchDecision, Error> {
    validate_plan(context.plan)?;
    let plan = context.plan;
    let Some(task) = plan
        .tasks
        .iter()
        .find(|task| task.task_id == context.task_id)
    else {
        return Err(Error::InvalidPlan("dispatch task is not in the plan"));
    };
    if plan.state != PlanState::Active || plan.generation != context.live_plan_generation {
        return Ok(DispatchDecision::NoLiveAuthority);
    }
    let persona_enabled = plan
        .personas
        .iter()
        .find(|persona| persona.persona_id == task.persona_id)
        .is_some_and(|persona| persona.enabled);
    if !persona_enabled {
        return Ok(DispatchDecision::NoLiveAuthority);
    }
    if context.now >= task.deadline_at || context.now >= plan.schedule.deadline_at {
        return Ok(DispatchDecision::Expired);
    }
    if !task.depends_on.is_subset(context.completed_dependencies) {
        return Ok(DispatchDecision::WaitForDependencies);
    }
    if context.spent_microusd
        > plan
            .max_cost_microusd
            .saturating_sub(task.max_cost_microusd)
    {
        return Ok(DispatchDecision::BudgetExhausted);
    }
    let is_deadline_reminder = task.required_capabilities.len() == 1
        && task.required_capabilities.contains("deadline.remind");
    if plan
        .schedule
        .quiet_hours
        .contains_local_minute(context.local_minute)
        && !(is_deadline_reminder && plan.schedule.quiet_hours.allow_deadline_reminders)
    {
        return Ok(DispatchDecision::DeferForQuietHours);
    }
    if context.human_approval_present {
        return Ok(DispatchDecision::ExecuteWithApproval);
    }
    let policy = &plan.automatic_execution;
    let automatically_safe = policy.enabled
        && task.automatic_execution_candidate
        && task.reversible
        && !task.approval_required
        && task.score.confidence_basis_points >= policy.minimum_confidence_basis_points
        && task.score.value_basis_points >= policy.minimum_value_basis_points
        && task.score.risk_basis_points <= policy.maximum_risk_basis_points
        && task.max_cost_microusd <= policy.max_task_cost_microusd
        && task
            .required_capabilities
            .is_subset(&policy.allowed_capabilities);
    Ok(if automatically_safe {
        DispatchDecision::ExecuteAutomatically
    } else {
        DispatchDecision::AwaitHumanApproval
    })
}

/// Validate an exact workforce lease fence before launch or receipt acceptance.
pub fn validate_fence(fence: &ExecutionFence, now: DateTime<Utc>) -> Result<(), Error> {
    if fence.community_id.is_nil()
        || fence.task_id.is_nil()
        || fence.lease_generation == 0
        || fence.lease_token_sha256 == [0; 32]
        || fence.expires_at <= now
        || fence.expires_at > now + chrono::Duration::hours(4)
    {
        return Err(Error::InvalidPlan(
            "workforce lease fence is invalid or expired",
        ));
    }
    Ok(())
}

/// Aggregate accepted task receipts and determine newly ready DAG nodes.
/// Exact replay is harmless because duplicate task receipts are rejected.
pub fn aggregate_progress(
    plan: &OrchestrationPlan,
    receipts: &[WorkProductReceipt],
) -> Result<ProgressDigest, Error> {
    validate_plan(plan)?;
    if receipts.len() > plan.tasks.len() {
        return Err(Error::InvalidReceipt("more receipts than plan tasks"));
    }
    let tasks: BTreeMap<_, _> = plan.tasks.iter().map(|task| (task.task_id, task)).collect();
    let mut accepted = BTreeMap::new();
    let mut completed = BTreeSet::new();
    let mut cost = 0_u64;
    for receipt in receipts {
        let Some(task) = tasks.get(&receipt.task_id) else {
            return Err(Error::InvalidReceipt("receipt task is not in the plan"));
        };
        validate_receipt(plan, task, receipt)?;
        if accepted.insert(receipt.task_id, receipt).is_some() {
            return Err(Error::InvalidReceipt(
                "task has conflicting terminal receipts",
            ));
        }
        cost = cost
            .checked_add(receipt.actual_cost_microusd)
            .ok_or(Error::InvalidReceipt("accounted cost overflow"))?;
        if receipt.outcome == ReceiptOutcome::Succeeded {
            completed.insert(receipt.task_id);
        }
    }
    if cost > plan.max_cost_microusd {
        return Err(Error::InvalidReceipt(
            "accepted receipts exceed plan budget",
        ));
    }
    let next_ready_task_ids = plan
        .tasks
        .iter()
        .filter(|task| {
            !accepted.contains_key(&task.task_id) && task.depends_on.is_subset(&completed)
        })
        .map(|task| task.task_id)
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.orchestration.accepted-receipts.v1\0");
    hasher.update(plan.community_id.as_bytes());
    hasher.update(plan.workspace_id.as_bytes());
    hasher.update(plan.plan_id.as_bytes());
    hasher.update(plan.generation.to_be_bytes());
    for (task_id, receipt) in accepted {
        hasher.update(task_id.as_bytes());
        hasher.update(receipt.lease_generation.to_be_bytes());
        hasher.update(receipt.execution_snapshot_sha256);
        hasher.update(receipt.handoff_manifest_sha256);
        hasher.update(receipt.actual_cost_microusd.to_be_bytes());
        hasher.update([receipt.outcome as u8]);
    }
    Ok(ProgressDigest {
        schema_version: PROGRESS_SCHEMA.into(),
        plan_id: plan.plan_id,
        plan_generation: plan.generation,
        accepted_receipts_sha256: hasher.finalize().into(),
        completed_task_ids: completed,
        next_ready_task_ids,
        accounted_cost_microusd: cost,
    })
}

fn validate_schedule(schedule: &SchedulePolicy) -> Result<(), Error> {
    if !valid_iana_timezone(&schedule.quiet_hours.timezone)
        || schedule.quiet_hours.start_local_minute >= 1_440
        || schedule.quiet_hours.end_local_minute >= 1_440
        || schedule.reminder_offsets_seconds.len() > MAX_REMINDERS
        || schedule
            .reminder_offsets_seconds
            .iter()
            .any(|offset| !(60..=2_592_000).contains(offset))
        || schedule
            .reminder_offsets_seconds
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || schedule
            .recurring_schedule_ref
            .as_deref()
            .is_some_and(|reference| !valid_schedule_ref(reference))
    {
        return Err(Error::InvalidPlan(
            "schedule, timezone, quiet hours, reminders, or recurrence is invalid",
        ));
    }
    Ok(())
}

fn validate_automatic_policy(policy: &AutomaticExecutionPolicy) -> Result<(), Error> {
    if policy.minimum_confidence_basis_points > 10_000
        || policy.minimum_value_basis_points > 10_000
        || policy.maximum_risk_basis_points > 10_000
        || policy.allowed_capabilities.len() > MAX_GRANTS
        || policy
            .allowed_capabilities
            .iter()
            .any(|grant| !valid_capability(grant) || ambient_capability(grant))
        || (policy.enabled
            && (policy.allowed_capabilities.is_empty() || policy.max_task_cost_microusd == 0))
    {
        return Err(Error::InvalidPlan("automatic execution policy is invalid"));
    }
    Ok(())
}

fn validate_dag(tasks: &BTreeMap<Uuid, &OrchestrationTask>) -> Result<(), Error> {
    for task in tasks.values() {
        if task.depends_on.contains(&task.task_id)
            || task
                .depends_on
                .iter()
                .any(|dependency| !tasks.contains_key(dependency))
        {
            return Err(Error::InvalidPlan(
                "task dependency is missing or self-referential",
            ));
        }
    }
    fn visit(
        id: Uuid,
        tasks: &BTreeMap<Uuid, &OrchestrationTask>,
        visiting: &mut BTreeSet<Uuid>,
        visited: &mut BTreeSet<Uuid>,
    ) -> bool {
        if visited.contains(&id) {
            return true;
        }
        if !visiting.insert(id) {
            return false;
        }
        let acyclic = tasks[&id]
            .depends_on
            .iter()
            .all(|dependency| visit(*dependency, tasks, visiting, visited));
        visiting.remove(&id);
        if acyclic {
            visited.insert(id);
        }
        acyclic
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    if tasks
        .keys()
        .all(|id| visit(*id, tasks, &mut visiting, &mut visited))
    {
        Ok(())
    } else {
        Err(Error::InvalidPlan("task graph contains a cycle"))
    }
}

fn validate_receipt(
    plan: &OrchestrationPlan,
    task: &OrchestrationTask,
    receipt: &WorkProductReceipt,
) -> Result<(), Error> {
    if receipt.schema_version != RECEIPT_SCHEMA
        || receipt.community_id != plan.community_id
        || receipt.workspace_id != plan.workspace_id
        || receipt.plan_id != plan.plan_id
        || receipt.plan_generation != plan.generation
        || receipt.lease_generation == 0
        || receipt.execution_snapshot_sha256 == [0; 32]
        || receipt.handoff_manifest_sha256 == [0; 32]
        || !valid_analyst_ref(&receipt.handoff_manifest_ref)
        || receipt.artifact_refs.len() > MAX_REFS
        || receipt.evidence_refs.len() > MAX_REFS
        || receipt.execution_receipt_refs.len() > MAX_REFS
        || receipt
            .artifact_refs
            .iter()
            .chain(receipt.evidence_refs.iter())
            .any(|reference| !valid_analyst_ref(reference))
        || receipt
            .execution_receipt_refs
            .iter()
            .any(|reference| !valid_execution_receipt_ref(reference))
        || receipt.actual_cost_microusd > task.max_cost_microusd
        || (receipt.outcome == ReceiptOutcome::Succeeded
            && (receipt.artifact_refs.is_empty() || receipt.evidence_refs.is_empty()))
        || receipt.completed_at > plan.schedule.deadline_at + chrono::Duration::minutes(5)
    {
        return Err(Error::InvalidReceipt(
            "scope, generation, evidence, handoff, outcome, deadline, or cost is invalid",
        ));
    }
    Ok(())
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn valid_capability(value: &str) -> bool {
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    !first.is_empty()
        && first
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        && segments.clone().next().is_some()
        && segments.all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
        && value.len() <= 128
}

fn ambient_capability(value: &str) -> bool {
    value.ends_with(".all")
        || value.contains('*')
        || matches!(
            value,
            "shell.execute" | "network.unrestricted" | "filesystem.unrestricted"
        )
}

fn valid_analyst_ref(value: &str) -> bool {
    value
        .strip_prefix("analyst360:sha256:")
        .is_some_and(|digest| digest.len() == 64 && hex::decode(digest).is_ok())
}

fn valid_model_route_ref(value: &str) -> bool {
    valid_uuid_generation_ref(value, "snowman:model-route:", ":revision:")
}

fn valid_schedule_ref(value: &str) -> bool {
    valid_uuid_generation_ref(value, "snowman:work-schedule:", ":generation:")
}

fn valid_uuid_generation_ref(value: &str, prefix: &str, separator: &str) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    let Some((id, generation)) = rest.split_once(separator) else {
        return false;
    };
    Uuid::parse_str(id).is_ok() && generation.parse::<u64>().is_ok_and(|value| value > 0)
}

fn valid_execution_receipt_ref(value: &str) -> bool {
    [
        "snowman:agent-job:",
        "snowman:model-generation:",
        "snowman:tool-action:",
    ]
    .iter()
    .any(|prefix| valid_uuid_generation_ref(value, prefix, ":generation:"))
}

fn valid_iana_timezone(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 64
        && value.contains('/')
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn aref(byte: u8) -> String {
        format!("analyst360:sha256:{}", hex::encode(digest(byte)))
    }

    fn persona() -> SpecialistPersona {
        SpecialistPersona {
            persona_id: Uuid::from_u128(10),
            persona_version_sha256: digest(1),
            service_identity_id: Uuid::from_u128(11),
            specialist_role: "governed_analyst".into(),
            model_id: "snowman-analyst-v1".into(),
            model_route_ref: format!("snowman:model-route:{}:revision:1", Uuid::from_u128(12)),
            tool_capability_grants: BTreeSet::from([
                "analyst.query".into(),
                "artifact.create".into(),
            ]),
            maximum_classification: Classification::Restricted,
            max_cost_microusd: 20_000,
            enabled: true,
        }
    }

    fn task(id: u128, depends_on: BTreeSet<Uuid>) -> OrchestrationTask {
        OrchestrationTask {
            task_id: Uuid::from_u128(id),
            persona_id: Uuid::from_u128(10),
            depends_on,
            analyst_context_manifest_refs: BTreeSet::from([aref(2)]),
            required_capabilities: BTreeSet::from(["analyst.query".into()]),
            expected_artifact_types: BTreeSet::from(["analysis_manifest".into()]),
            score: ActionScore {
                confidence_basis_points: 9_000,
                value_basis_points: 8_500,
                risk_basis_points: 500,
                usefulness_sha256: digest(3),
            },
            reversible: true,
            approval_required: false,
            automatic_execution_candidate: true,
            deadline_at: Utc::now() + chrono::Duration::hours(3),
            max_cost_microusd: 5_000,
        }
    }

    fn plan() -> OrchestrationPlan {
        let first = task(20, BTreeSet::new());
        let second = task(21, BTreeSet::from([first.task_id]));
        OrchestrationPlan {
            schema_version: PLAN_SCHEMA.into(),
            plan_id: Uuid::from_u128(1),
            community_id: Uuid::from_u128(2),
            workspace_id: Uuid::from_u128(3),
            request_id: Uuid::from_u128(4),
            project_id: Some(Uuid::from_u128(5)),
            work_kind: WorkKind::Project,
            generation: 1,
            supersedes_plan_id: None,
            state: PlanState::Active,
            objective_sha256: digest(4),
            classification: Classification::Confidential,
            max_cost_microusd: 20_000,
            schedule: SchedulePolicy {
                recurring_schedule_ref: None,
                deadline_at: Utc::now() + chrono::Duration::hours(4),
                reminder_offsets_seconds: vec![900, 3_600],
                quiet_hours: QuietHours {
                    timezone: "America/Denver".into(),
                    start_local_minute: 22 * 60,
                    end_local_minute: 7 * 60,
                    allow_deadline_reminders: false,
                },
            },
            automatic_execution: AutomaticExecutionPolicy {
                enabled: true,
                allowed_capabilities: BTreeSet::from(["analyst.query".into()]),
                minimum_confidence_basis_points: 8_000,
                minimum_value_basis_points: 7_000,
                maximum_risk_basis_points: 1_000,
                max_task_cost_microusd: 6_000,
            },
            personas: vec![persona()],
            tasks: vec![first, second],
        }
    }

    fn receipt(task_id: Uuid) -> WorkProductReceipt {
        WorkProductReceipt {
            schema_version: RECEIPT_SCHEMA.into(),
            community_id: Uuid::from_u128(2),
            workspace_id: Uuid::from_u128(3),
            plan_id: Uuid::from_u128(1),
            plan_generation: 1,
            task_id,
            lease_generation: 1,
            execution_snapshot_sha256: digest(5),
            outcome: ReceiptOutcome::Succeeded,
            artifact_refs: BTreeSet::from([aref(6)]),
            evidence_refs: BTreeSet::from([aref(7)]),
            execution_receipt_refs: BTreeSet::from([format!(
                "snowman:agent-job:{}:generation:1",
                Uuid::from_u128(30)
            )]),
            handoff_manifest_ref: aref(8),
            handoff_manifest_sha256: digest(8),
            actual_cost_microusd: 1_000,
            completed_at: Utc::now(),
        }
    }

    #[test]
    fn accepts_bounded_specialist_plan() {
        validate_plan(&plan()).expect("valid plan");
    }

    #[test]
    fn rejects_raw_or_non_analyst_context_coordinates() {
        let mut value = plan();
        value.tasks[0].analyst_context_manifest_refs = BTreeSet::from([
            "snowman:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
        ]);
        assert!(validate_plan(&value).is_err());
    }

    #[test]
    fn rejects_ambient_tool_grants_and_direct_provider_routes() {
        let mut value = plan();
        value.personas[0]
            .tool_capability_grants
            .insert("shell.execute".into());
        assert!(validate_plan(&value).is_err());
        let mut value = plan();
        value.personas[0].model_route_ref = "https://api.openai.com/v1".into();
        assert!(validate_plan(&value).is_err());
    }

    #[test]
    fn rejects_cycles_and_cross_persona_budget_overcommit() {
        let mut value = plan();
        let second_task_id = value.tasks[1].task_id;
        value.tasks[0].depends_on.insert(second_task_id);
        assert!(validate_plan(&value).is_err());
        let mut value = plan();
        value.personas[0].max_cost_microusd = 9_000;
        assert!(validate_plan(&value).is_err());
    }

    #[test]
    fn automatic_execution_requires_every_safety_and_value_gate() {
        let value = plan();
        let completed = BTreeSet::new();
        let mut context = DispatchContext {
            plan: &value,
            task_id: value.tasks[0].task_id,
            live_plan_generation: 1,
            completed_dependencies: &completed,
            spent_microusd: 0,
            human_approval_present: false,
            now: Utc::now(),
            local_minute: 12 * 60,
        };
        assert_eq!(
            decide_dispatch(&context).expect("decision"),
            DispatchDecision::ExecuteAutomatically
        );
        context.local_minute = 23 * 60;
        assert_eq!(
            decide_dispatch(&context).expect("decision"),
            DispatchDecision::DeferForQuietHours
        );
    }

    #[test]
    fn stale_cancelled_or_superseded_generation_never_dispatches() {
        for state in [
            PlanState::Cancelled,
            PlanState::Superseded,
            PlanState::Paused,
        ] {
            let mut value = plan();
            value.state = state;
            let completed = BTreeSet::new();
            let context = DispatchContext {
                plan: &value,
                task_id: value.tasks[0].task_id,
                live_plan_generation: 1,
                completed_dependencies: &completed,
                spent_microusd: 0,
                human_approval_present: true,
                now: Utc::now(),
                local_minute: 12 * 60,
            };
            assert_eq!(
                decide_dispatch(&context).expect("decision"),
                DispatchDecision::NoLiveAuthority
            );
        }
        let value = plan();
        let completed = BTreeSet::new();
        let context = DispatchContext {
            plan: &value,
            task_id: value.tasks[0].task_id,
            live_plan_generation: 2,
            completed_dependencies: &completed,
            spent_microusd: 0,
            human_approval_present: true,
            now: Utc::now(),
            local_minute: 12 * 60,
        };
        assert_eq!(
            decide_dispatch(&context).expect("decision"),
            DispatchDecision::NoLiveAuthority
        );
        let mut value = plan();
        value.personas[0].enabled = false;
        let context = DispatchContext {
            plan: &value,
            task_id: value.tasks[0].task_id,
            live_plan_generation: 1,
            completed_dependencies: &completed,
            spent_microusd: 0,
            human_approval_present: true,
            now: Utc::now(),
            local_minute: 12 * 60,
        };
        assert_eq!(
            decide_dispatch(&context).expect("decision"),
            DispatchDecision::NoLiveAuthority
        );
    }

    #[test]
    fn dependency_receipt_unlocks_next_specialist_with_handoff_digest() {
        let value = plan();
        let progress =
            aggregate_progress(&value, &[receipt(value.tasks[0].task_id)]).expect("aggregate");
        assert_eq!(
            progress.completed_task_ids,
            BTreeSet::from([value.tasks[0].task_id])
        );
        assert_eq!(
            progress.next_ready_task_ids,
            BTreeSet::from([value.tasks[1].task_id])
        );
        assert_ne!(progress.accepted_receipts_sha256, [0; 32]);
        assert_eq!(progress.accounted_cost_microusd, 1_000);
    }

    #[test]
    fn duplicate_or_stale_receipts_are_rejected() {
        let value = plan();
        let current = receipt(value.tasks[0].task_id);
        assert!(aggregate_progress(&value, &[current.clone(), current]).is_err());
        let mut stale = receipt(value.tasks[0].task_id);
        stale.plan_generation = 2;
        assert!(aggregate_progress(&value, &[stale]).is_err());
    }

    #[test]
    fn lease_fence_is_bounded_and_digest_only() {
        let now = Utc::now();
        let fence = ExecutionFence {
            community_id: Uuid::from_u128(2),
            task_id: Uuid::from_u128(20),
            lease_generation: 4,
            lease_token_sha256: digest(9),
            expires_at: now + chrono::Duration::minutes(5),
        };
        validate_fence(&fence, now).expect("valid fence");
        let mut expired = fence;
        expired.expires_at = now;
        assert!(validate_fence(&expired, now).is_err());
    }

    #[test]
    fn overnight_quiet_hours_are_timezone_local() {
        let quiet = QuietHours {
            timezone: "America/Denver".into(),
            start_local_minute: 22 * 60,
            end_local_minute: 7 * 60,
            allow_deadline_reminders: false,
        };
        assert!(quiet.contains_local_minute(23 * 60));
        assert!(quiet.contains_local_minute(6 * 60));
        assert!(!quiet.contains_local_minute(12 * 60));
    }
}
