//! Policy kernel for the Snowman 360 specialist-agent workforce.
//!
//! This crate does not execute models or tools. It validates that an
//! orchestrator-produced team plan is tenant-bounded, acyclic, budgeted,
//! reviewable, and routed only through Snowman-controlled model gateways. It
//! also makes the safe/proactive/human-gated decision explicit before durable
//! tasks reach workers.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

const MAX_TASKS: usize = 64;
const MAX_CAPABILITIES_PER_TASK: usize = 32;
const MAX_CONTEXT_REFS_PER_TASK: usize = 64;
const MAX_CONTEXT_PACKET_BYTES: u64 = 1_048_576;
const MAX_CONTEXT_PACKET_REFS: usize = 128;
const MAX_CONTEXT_PACKET_DIGESTS: usize = 64;
const MAX_CONTEXT_NEXT_ACTIONS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Moderate,
    High,
    Prohibited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialistRole {
    Lead,
    ClientDelivery,
    ResearchEvidence,
    GovernedAnalyst,
    QualityRiskReviewer,
    DeadlineOperations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRoute {
    pub model_id: String,
    pub gateway_url: String,
    pub suited_roles: BTreeSet<SpecialistRole>,
    pub allowed_classifications: BTreeSet<Classification>,
    /// Relative quality score from the controlled evaluation set (0-1000).
    pub quality_score: u16,
    /// Relative latency score where a larger number is better (0-1000).
    pub latency_score: u16,
    /// Worst-case blended input/output cost used for hard-plan budgeting.
    pub max_cost_microusd_per_million_tokens: u64,
    pub max_context_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedTask {
    pub task_id: Uuid,
    /// Unique tenant-bound service identity used to claim and execute the task.
    pub service_identity_id: Uuid,
    pub specialist_role: SpecialistRole,
    pub depends_on: BTreeSet<Uuid>,
    pub required_capabilities: BTreeSet<String>,
    pub context_packet_refs: BTreeSet<String>,
    /// Explicit operator/persona override. `None` invokes best-fit routing.
    pub requested_model_id: Option<String>,
    pub selected_model_id: Option<String>,
    pub selected_gateway_url: Option<String>,
    pub expected_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_cost_microusd: u64,
    pub risk_tier: RiskTier,
    pub reversible: bool,
    pub approval_required: bool,
    pub expected_artifact_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedTeamPlan {
    pub request_id: Uuid,
    pub community_id: Uuid,
    pub objective_sha256: [u8; 32],
    pub classification: Classification,
    pub client_ready_delivery: bool,
    pub max_cost_microusd: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub tasks: Vec<PlannedTask>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelSelection {
    pub model_id: String,
    pub gateway_url: String,
    pub reserved_cost_microusd: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAuthority {
    Analyst360,
    SnowmanCommandCenter,
}

/// One bounded next-useful-action coordinate carried in a handoff packet.
/// Free-form rationale stays in the content-addressed evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextNextAction {
    pub action_id: Uuid,
    pub capability: String,
    pub risk_tier: RiskTier,
    pub reversible: bool,
    pub approval_required: bool,
    pub expected_cost_microusd: u64,
    pub confidence_basis_points: u16,
    pub usefulness_sha256: [u8; 32],
}

/// Metadata-only, content-addressed context for a replacement specialist.
/// The Command Center never stores the raw Analyst 360 dataset or transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPacketManifest {
    pub context_packet_id: Uuid,
    pub request_id: Uuid,
    pub community_id: Uuid,
    pub classification: Classification,
    pub authority: ContextAuthority,
    pub objective_sha256: [u8; 32],
    pub content_reference: String,
    pub content_sha256: [u8; 32],
    pub source_event_sha256: [u8; 32],
    pub size_bytes: u64,
    pub artifact_references: BTreeSet<String>,
    pub evidence_references: BTreeSet<String>,
    pub decision_digests: BTreeSet<String>,
    pub open_question_digests: BTreeSet<String>,
    pub next_actions: Vec<ContextNextAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProactiveTrigger {
    UserObjective,
    AuthorizedSchedule,
    TenantSignal,
    PolicyReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProactiveAction {
    pub action_id: Uuid,
    pub community_id: Uuid,
    pub objective_id: Uuid,
    pub trigger: ProactiveTrigger,
    pub capability: String,
    pub risk_tier: RiskTier,
    pub reversible: bool,
    pub expected_cost_microusd: u64,
    pub usefulness_basis: String,
    pub confidence_basis_points: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProactiveDecision {
    ExecuteAutomatically,
    AwaitHumanApproval,
    Reject,
}

#[derive(Debug, Clone)]
pub struct ProactivePolicy {
    pub automatic_capabilities: BTreeSet<String>,
    pub max_automatic_cost_microusd: u64,
    pub minimum_confidence_basis_points: u16,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("plan is outside a bounded Snowman workforce contract: {0}")]
    InvalidPlan(String),
    #[error("no approved Snowman model route satisfies task {0}")]
    NoModelRoute(Uuid),
    #[error("requested model route is not allowed for task {0}")]
    DisallowedModelOverride(Uuid),
    #[error("context packet is outside the bounded Snowman handoff contract: {0}")]
    InvalidContextPacket(String),
}

/// Validate that a replacement agent can resume from bounded, evidence-linked
/// state without receiving raw client data, secrets, or an unbounded transcript.
pub fn validate_context_packet(manifest: &ContextPacketManifest) -> Result<(), PolicyError> {
    let invalid = |reason: &str| PolicyError::InvalidContextPacket(reason.into());
    if manifest.context_packet_id.is_nil()
        || manifest.request_id.is_nil()
        || manifest.community_id.is_nil()
        || manifest.objective_sha256 == [0; 32]
        || manifest.content_sha256 == [0; 32]
        || manifest.source_event_sha256 == [0; 32]
        || manifest.size_bytes > MAX_CONTEXT_PACKET_BYTES
        || !is_context_reference(&manifest.content_reference)
    {
        return Err(invalid(
            "tenant, request, objective, content, provenance, and size are required",
        ));
    }
    if manifest.artifact_references.len() > MAX_CONTEXT_PACKET_REFS
        || manifest.evidence_references.len() > MAX_CONTEXT_PACKET_REFS
        || manifest.decision_digests.len() > MAX_CONTEXT_PACKET_DIGESTS
        || manifest.open_question_digests.len() > MAX_CONTEXT_PACKET_DIGESTS
        || manifest.next_actions.len() > MAX_CONTEXT_NEXT_ACTIONS
        || manifest
            .artifact_references
            .iter()
            .chain(manifest.evidence_references.iter())
            .any(|reference| !is_context_reference(reference))
        || manifest
            .decision_digests
            .iter()
            .chain(manifest.open_question_digests.iter())
            .any(|digest| !is_sha256_coordinate(digest))
    {
        return Err(invalid(
            "references, decision/open-question digests, or next actions exceed bounds",
        ));
    }
    let mut action_ids = BTreeSet::new();
    for action in &manifest.next_actions {
        if action.action_id.is_nil()
            || !action_ids.insert(action.action_id)
            || !is_capability(&action.capability)
            || is_dangerous_ambient_capability(&action.capability)
            || action.risk_tier == RiskTier::Prohibited
            || action.confidence_basis_points > 10_000
            || action.usefulness_sha256 == [0; 32]
            || (!action.reversible && !action.approval_required)
            || (action.risk_tier != RiskTier::Low && !action.approval_required)
        {
            return Err(invalid(
                "next action violates identity, capability, risk, evidence, or approval policy",
            ));
        }
    }
    Ok(())
}

/// Validate the task graph and select one policy-approved model for every task.
/// A caller may persist the returned plan only after this function succeeds.
pub fn govern_team_plan(
    mut plan: GovernedTeamPlan,
    catalog: &[ModelRoute],
) -> Result<GovernedTeamPlan, PolicyError> {
    validate_plan_shape(&plan)?;
    validate_graph(&plan.tasks)?;
    validate_independent_review(&plan)?;

    let mut reserved_cost = 0_u64;
    for task in &mut plan.tasks {
        let selection = select_model(task, plan.classification, catalog)?;
        if task.max_cost_microusd < selection.reserved_cost_microusd {
            return Err(PolicyError::InvalidPlan(format!(
                "task {} model reservation exceeds its hard cost ceiling",
                task.task_id
            )));
        }
        reserved_cost = reserved_cost
            .checked_add(task.max_cost_microusd)
            .ok_or_else(|| PolicyError::InvalidPlan("task budget sum overflowed".into()))?;
        task.selected_model_id = Some(selection.model_id);
        task.selected_gateway_url = Some(selection.gateway_url);
    }
    if reserved_cost > plan.max_cost_microusd {
        return Err(PolicyError::InvalidPlan(
            "task cost ceilings exceed the request ceiling".into(),
        ));
    }
    Ok(plan)
}

/// Decide whether a useful proactive action is safe to run without interrupting
/// the user. Moderate/high/irreversible actions remain useful but stop at an
/// expiring approval; prohibited or ungrounded actions are rejected.
pub fn decide_proactive_action(
    action: &ProactiveAction,
    policy: &ProactivePolicy,
) -> ProactiveDecision {
    if action.risk_tier == RiskTier::Prohibited
        || action.usefulness_basis.trim().is_empty()
        || action.confidence_basis_points > 10_000
        || action.objective_id.is_nil()
    {
        return ProactiveDecision::Reject;
    }
    let automatic = action.risk_tier == RiskTier::Low
        && action.reversible
        && policy.automatic_capabilities.contains(&action.capability)
        && action.expected_cost_microusd <= policy.max_automatic_cost_microusd
        && action.confidence_basis_points >= policy.minimum_confidence_basis_points;
    if automatic {
        ProactiveDecision::ExecuteAutomatically
    } else {
        ProactiveDecision::AwaitHumanApproval
    }
}

fn validate_plan_shape(plan: &GovernedTeamPlan) -> Result<(), PolicyError> {
    if plan.request_id.is_nil()
        || plan.community_id.is_nil()
        || plan.objective_sha256 == [0; 32]
        || plan.tasks.is_empty()
        || plan.tasks.len() > MAX_TASKS
    {
        return Err(PolicyError::InvalidPlan(
            "request, tenant, objective digest, and 1-64 tasks are required".into(),
        ));
    }
    let input_sum = plan.tasks.iter().try_fold(0_u64, |total, task| {
        total.checked_add(task.expected_input_tokens)
    });
    let output_sum = plan.tasks.iter().try_fold(0_u64, |total, task| {
        total.checked_add(task.max_output_tokens)
    });
    let (Some(input_sum), Some(output_sum)) = (input_sum, output_sum) else {
        return Err(PolicyError::InvalidPlan("task token sum overflowed".into()));
    };
    if input_sum > plan.max_input_tokens || output_sum > plan.max_output_tokens {
        return Err(PolicyError::InvalidPlan(
            "task token ceilings exceed the request ceiling".into(),
        ));
    }
    let mut service_identities = BTreeSet::new();
    for task in &plan.tasks {
        if task.service_identity_id.is_nil()
            || !service_identities.insert(task.service_identity_id)
            || task.required_capabilities.is_empty()
            || task.required_capabilities.len() > MAX_CAPABILITIES_PER_TASK
            || task.context_packet_refs.len() > MAX_CONTEXT_REFS_PER_TASK
            || task.expected_artifact_type.trim().is_empty()
            || task.expected_artifact_type.len() > 128
            || task.risk_tier == RiskTier::Prohibited
            || (!task.reversible && !task.approval_required)
            || task.required_capabilities.iter().any(|capability| {
                !is_capability(capability) || is_dangerous_ambient_capability(capability)
            })
            || task
                .context_packet_refs
                .iter()
                .any(|reference| !is_context_reference(reference))
        {
            return Err(PolicyError::InvalidPlan(format!(
                "task {} violates identity, capability, context, risk, or artifact bounds",
                task.task_id
            )));
        }
    }
    Ok(())
}

fn validate_graph(tasks: &[PlannedTask]) -> Result<(), PolicyError> {
    let by_id: BTreeMap<Uuid, &PlannedTask> =
        tasks.iter().map(|task| (task.task_id, task)).collect();
    if by_id.len() != tasks.len() || by_id.contains_key(&Uuid::nil()) {
        return Err(PolicyError::InvalidPlan(
            "task IDs must be unique and non-nil".into(),
        ));
    }
    for task in tasks {
        if task.depends_on.contains(&task.task_id)
            || task
                .depends_on
                .iter()
                .any(|dependency| !by_id.contains_key(dependency))
        {
            return Err(PolicyError::InvalidPlan(format!(
                "task {} has an invalid dependency",
                task.task_id
            )));
        }
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    fn visit(
        id: Uuid,
        tasks: &BTreeMap<Uuid, &PlannedTask>,
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
    if !by_id
        .keys()
        .all(|id| visit(*id, &by_id, &mut visiting, &mut visited))
    {
        return Err(PolicyError::InvalidPlan(
            "task graph contains a cycle".into(),
        ));
    }
    Ok(())
}

fn validate_independent_review(plan: &GovernedTeamPlan) -> Result<(), PolicyError> {
    if !plan.client_ready_delivery {
        return Ok(());
    }
    let producer_ids: BTreeSet<_> = plan
        .tasks
        .iter()
        .filter(|task| task.specialist_role != SpecialistRole::QualityRiskReviewer)
        .map(|task| task.task_id)
        .collect();
    let producer_identities: BTreeSet<_> = plan
        .tasks
        .iter()
        .filter(|task| task.specialist_role != SpecialistRole::QualityRiskReviewer)
        .map(|task| task.service_identity_id)
        .collect();
    let has_review = plan.tasks.iter().any(|task| {
        task.specialist_role == SpecialistRole::QualityRiskReviewer
            && producer_ids.is_subset(&task.depends_on)
            && !producer_identities.contains(&task.service_identity_id)
            && task.required_capabilities.contains("artifact.review")
    });
    if !has_review {
        return Err(PolicyError::InvalidPlan(
            "client-ready delivery requires an independent quality/risk review after every producer"
                .into(),
        ));
    }
    Ok(())
}

fn select_model(
    task: &PlannedTask,
    classification: Classification,
    catalog: &[ModelRoute],
) -> Result<ModelSelection, PolicyError> {
    let mut allowed: Vec<_> = catalog
        .iter()
        .filter(|route| {
            route.suited_roles.contains(&task.specialist_role)
                && route.allowed_classifications.contains(&classification)
                && route.max_context_tokens >= task.expected_input_tokens
                && route.quality_score <= 1_000
                && route.latency_score <= 1_000
                && !route.model_id.trim().is_empty()
                && route.model_id.len() <= 256
                && validate_gateway(&route.gateway_url)
        })
        .collect();
    if let Some(requested) = task.requested_model_id.as_deref() {
        allowed.retain(|route| route.model_id == requested);
        if allowed.is_empty() {
            return Err(PolicyError::DisallowedModelOverride(task.task_id));
        }
    }
    allowed.sort_by_key(|route| {
        (
            std::cmp::Reverse(route.quality_score),
            std::cmp::Reverse(route.latency_score),
            route.max_cost_microusd_per_million_tokens,
            &route.model_id,
        )
    });
    let route = allowed
        .first()
        .ok_or(PolicyError::NoModelRoute(task.task_id))?;
    let total_tokens = task
        .expected_input_tokens
        .saturating_add(task.max_output_tokens);
    let reserved_cost_microusd = route
        .max_cost_microusd_per_million_tokens
        .saturating_mul(total_tokens)
        .div_ceil(1_000_000);
    Ok(ModelSelection {
        model_id: route.model_id.clone(),
        gateway_url: route.gateway_url.clone(),
        reserved_cost_microusd,
    })
}

fn validate_gateway(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    url.scheme() == "https"
        && (host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn is_capability(value: &str) -> bool {
    value.len() <= 128
        && value.contains('.')
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_')
        })
}

fn is_context_reference(value: &str) -> bool {
    let digest = value
        .strip_prefix("analyst360:sha256:")
        .or_else(|| value.strip_prefix("snowman:sha256:"));
    digest.is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn is_sha256_coordinate(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_dangerous_ambient_capability(value: &str) -> bool {
    matches!(
        value,
        "admin.all" | "aws.all" | "filesystem.all" | "network.all" | "tool.all"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(role: SpecialistRole, model_id: &str, quality: u16) -> ModelRoute {
        ModelRoute {
            model_id: model_id.into(),
            gateway_url: "https://models.snowmanai.org/v1".into(),
            suited_roles: BTreeSet::from([role]),
            allowed_classifications: BTreeSet::from([
                Classification::Internal,
                Classification::Confidential,
            ]),
            quality_score: quality,
            latency_score: 500,
            max_cost_microusd_per_million_tokens: 1_000_000,
            max_context_tokens: 100_000,
        }
    }

    fn task(role: SpecialistRole) -> PlannedTask {
        PlannedTask {
            task_id: Uuid::new_v4(),
            service_identity_id: Uuid::new_v4(),
            specialist_role: role,
            depends_on: BTreeSet::new(),
            required_capabilities: BTreeSet::from(["artifact.create".into()]),
            context_packet_refs: BTreeSet::from([format!("analyst360:sha256:{}", "a".repeat(64))]),
            requested_model_id: None,
            selected_model_id: None,
            selected_gateway_url: None,
            expected_input_tokens: 10_000,
            max_output_tokens: 2_000,
            max_cost_microusd: 20_000,
            risk_tier: RiskTier::Low,
            reversible: true,
            approval_required: false,
            expected_artifact_type: "client_brief".into(),
        }
    }

    #[test]
    fn routes_each_specialist_to_best_allowed_model() {
        let producer = task(SpecialistRole::ResearchEvidence);
        let mut reviewer = task(SpecialistRole::QualityRiskReviewer);
        reviewer.required_capabilities = BTreeSet::from(["artifact.review".into()]);
        reviewer.depends_on.insert(producer.task_id);
        let plan = GovernedTeamPlan {
            request_id: Uuid::new_v4(),
            community_id: Uuid::new_v4(),
            objective_sha256: [7; 32],
            classification: Classification::Confidential,
            client_ready_delivery: true,
            max_cost_microusd: 50_000,
            max_input_tokens: 30_000,
            max_output_tokens: 10_000,
            tasks: vec![producer, reviewer],
        };
        let governed = govern_team_plan(
            plan,
            &[
                route(SpecialistRole::ResearchEvidence, "research-fast", 700),
                route(SpecialistRole::ResearchEvidence, "research-best", 900),
                route(SpecialistRole::QualityRiskReviewer, "review-best", 850),
            ],
        )
        .unwrap();
        assert_eq!(
            governed.tasks[0].selected_model_id.as_deref(),
            Some("research-best")
        );
        assert_eq!(
            governed.tasks[1].selected_model_id.as_deref(),
            Some("review-best")
        );
        assert_eq!(
            governed.tasks[0].selected_gateway_url.as_deref(),
            Some("https://models.snowmanai.org/v1")
        );
    }

    #[test]
    fn rejects_cycle_and_missing_client_review() {
        let mut first = task(SpecialistRole::Lead);
        let mut second = task(SpecialistRole::ResearchEvidence);
        first.depends_on.insert(second.task_id);
        second.depends_on.insert(first.task_id);
        let plan = GovernedTeamPlan {
            request_id: Uuid::new_v4(),
            community_id: Uuid::new_v4(),
            objective_sha256: [1; 32],
            classification: Classification::Internal,
            client_ready_delivery: true,
            max_cost_microusd: 50_000,
            max_input_tokens: 30_000,
            max_output_tokens: 10_000,
            tasks: vec![first, second],
        };
        assert!(matches!(
            govern_team_plan(plan, &[]),
            Err(PolicyError::InvalidPlan(_))
        ));
    }

    #[test]
    fn proactive_policy_runs_only_safe_useful_reversible_work() {
        let policy = ProactivePolicy {
            automatic_capabilities: BTreeSet::from([
                "deadline.remind".into(),
                "analytics.refresh".into(),
            ]),
            max_automatic_cost_microusd: 50_000,
            minimum_confidence_basis_points: 7_500,
        };
        let mut action = ProactiveAction {
            action_id: Uuid::new_v4(),
            community_id: Uuid::new_v4(),
            objective_id: Uuid::new_v4(),
            trigger: ProactiveTrigger::AuthorizedSchedule,
            capability: "deadline.remind".into(),
            risk_tier: RiskTier::Low,
            reversible: true,
            expected_cost_microusd: 100,
            usefulness_basis: "Project deadline is within the configured reminder window.".into(),
            confidence_basis_points: 9_000,
        };
        assert_eq!(
            decide_proactive_action(&action, &policy),
            ProactiveDecision::ExecuteAutomatically
        );
        action.reversible = false;
        assert_eq!(
            decide_proactive_action(&action, &policy),
            ProactiveDecision::AwaitHumanApproval
        );
        action.risk_tier = RiskTier::Prohibited;
        assert_eq!(
            decide_proactive_action(&action, &policy),
            ProactiveDecision::Reject
        );
    }

    #[test]
    fn rejects_direct_provider_and_ambient_capability() {
        assert!(!validate_gateway("https://api.openai.com/v1"));
        assert!(!validate_gateway("https://snowmanai.org.evil.example/v1"));
        assert!(is_dangerous_ambient_capability("aws.all"));
        assert!(!is_context_reference(&format!(
            "snowman:sha256:{}",
            "A".repeat(64)
        )));
    }

    #[test]
    fn rejects_service_identity_reuse_between_specialists() {
        let first = task(SpecialistRole::ResearchEvidence);
        let mut second = task(SpecialistRole::ClientDelivery);
        second.service_identity_id = first.service_identity_id;
        let plan = GovernedTeamPlan {
            request_id: Uuid::new_v4(),
            community_id: Uuid::new_v4(),
            objective_sha256: [3; 32],
            classification: Classification::Internal,
            client_ready_delivery: false,
            max_cost_microusd: 50_000,
            max_input_tokens: 30_000,
            max_output_tokens: 10_000,
            tasks: vec![first, second],
        };
        assert!(matches!(
            govern_team_plan(plan, &[]),
            Err(PolicyError::InvalidPlan(_))
        ));
    }

    #[test]
    fn accepts_bounded_context_for_replacement_agents() {
        let reference = format!("analyst360:sha256:{}", "a".repeat(64));
        let manifest = ContextPacketManifest {
            context_packet_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            community_id: Uuid::new_v4(),
            classification: Classification::Confidential,
            authority: ContextAuthority::Analyst360,
            objective_sha256: [1; 32],
            content_reference: reference.clone(),
            content_sha256: [2; 32],
            source_event_sha256: [3; 32],
            size_bytes: 64_000,
            artifact_references: BTreeSet::from([reference.clone()]),
            evidence_references: BTreeSet::from([reference]),
            decision_digests: BTreeSet::from([format!("sha256:{}", "b".repeat(64))]),
            open_question_digests: BTreeSet::from([format!("sha256:{}", "c".repeat(64))]),
            next_actions: vec![ContextNextAction {
                action_id: Uuid::new_v4(),
                capability: "analytics.refresh".into(),
                risk_tier: RiskTier::Low,
                reversible: true,
                approval_required: false,
                expected_cost_microusd: 5_000,
                confidence_basis_points: 8_500,
                usefulness_sha256: [4; 32],
            }],
        };
        validate_context_packet(&manifest).expect("bounded context packet");
    }

    #[test]
    fn rejects_raw_or_unsafe_context_handoffs() {
        let mut manifest = ContextPacketManifest {
            context_packet_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            community_id: Uuid::new_v4(),
            classification: Classification::Restricted,
            authority: ContextAuthority::Analyst360,
            objective_sha256: [1; 32],
            content_reference: "https://example.com/raw-client-export.csv".into(),
            content_sha256: [2; 32],
            source_event_sha256: [3; 32],
            size_bytes: MAX_CONTEXT_PACKET_BYTES + 1,
            artifact_references: BTreeSet::new(),
            evidence_references: BTreeSet::new(),
            decision_digests: BTreeSet::new(),
            open_question_digests: BTreeSet::new(),
            next_actions: Vec::new(),
        };
        assert!(matches!(
            validate_context_packet(&manifest),
            Err(PolicyError::InvalidContextPacket(_))
        ));
        manifest.content_reference = format!("analyst360:sha256:{}", "d".repeat(64));
        manifest.size_bytes = 1_000;
        manifest.next_actions.push(ContextNextAction {
            action_id: Uuid::new_v4(),
            capability: "aws.all".into(),
            risk_tier: RiskTier::High,
            reversible: false,
            approval_required: false,
            expected_cost_microusd: 0,
            confidence_basis_points: 9_000,
            usefulness_sha256: [4; 32],
        });
        assert!(matches!(
            validate_context_packet(&manifest),
            Err(PolicyError::InvalidContextPacket(_))
        ));
    }
}
