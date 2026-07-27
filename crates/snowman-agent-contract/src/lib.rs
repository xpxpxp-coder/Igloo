#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Shared, versioned contracts for the private Snowman agent job boundary.
//!
//! These types carry minimized coordination inputs and bounded work products.
//! They never carry relay keys, cloud credentials, provider credentials, raw
//! Analyst datasets, or arbitrary provider endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Job snapshot schema served by the private broker.
pub const JOB_SNAPSHOT_SCHEMA: &str = "snowman.agent.job.snapshot.v1";
/// Job-start receipt schema accepted by the private broker.
pub const JOB_STARTED_SCHEMA: &str = "snowman.agent.job.started.v1";
/// Job-result receipt schema accepted by the private broker.
pub const JOB_RESULT_SCHEMA: &str = "snowman.agent.job.result.v1";
/// Broker acknowledgement schema returned to the executor.
pub const BROKER_ACK_SCHEMA: &str = "snowman.agent.broker.ack.v1";

/// Governed data class assigned before an agent receives a snapshot.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Snowman internal data with no client-confidential content.
    Internal,
    /// Confidential Snowman or client work product.
    Confidential,
    /// Restricted material requiring the narrowest eligible runtime policy.
    Restricted,
}

/// Mandatory handling policy for every executor-visible snapshot.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentDataPolicy {
    /// Must remain true: direct identifiers and PII are not agent inputs.
    pub pii_prohibited: bool,
    /// SHA-256 evidence from the governed minimization/redaction boundary.
    pub minimization_evidence_sha256: String,
}

/// Immutable, tenant- and lease-bound input to one fresh agent process.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobSnapshot {
    /// Exact schema version.
    pub schema_version: String,
    /// Globally unique one-shot job identifier.
    pub job_id: Uuid,
    /// Tenant identifier resolved by the trusted coordinator.
    pub tenant_id: String,
    /// Snowman workspace identifier; never supplied by the runtime.
    pub workspace_id: Uuid,
    /// Parent workforce request.
    pub request_id: Uuid,
    /// Exact fenced workforce task.
    pub task_id: Uuid,
    /// Monotonic lease generation.
    pub generation: u32,
    /// Digest-reviewed runtime profile.
    pub runtime_id: String,
    /// Exact evaluated model catalog ID.
    pub model_id: String,
    /// Specialist role assigned by the governed team plan.
    pub specialist_role: String,
    /// Governed data classification.
    pub classification: Classification,
    /// Evidence-bearing prohibition on PII in the executor projection.
    pub data_policy: AgentDataPolicy,
    /// Trusted Snowman runtime policy, separate from untrusted input.
    pub system_prompt: String,
    /// Minimized request and evidence-reference projection.
    pub prompt: String,
    /// Exact broker capabilities granted for this job generation.
    pub capability_grants: Vec<String>,
    /// Maximum input tokens reserved for the exact task generation.
    pub max_input_tokens: u64,
    /// Maximum output tokens reserved for the exact task generation.
    pub max_output_tokens: u64,
    /// Maximum model spend in millionths of a US dollar.
    pub max_cost_microusd: u64,
    /// Hard expiration for the job and its credential.
    pub deadline_at: DateTime<Utc>,
}

/// Idempotent proof that the one-shot runtime began the exact snapshot.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StartedReceipt {
    /// Exact schema version.
    pub schema_version: String,
    /// Exact job.
    pub job_id: Uuid,
    /// Exact lease generation.
    pub generation: u32,
    /// Digest of the exact snapshot bytes received by the executor.
    pub snapshot_sha256: String,
    /// Exact immutable runtime profile.
    pub runtime_id: String,
    /// Exact evaluated model catalog ID.
    pub model_id: String,
    /// Runtime-observed start time.
    pub started_at: DateTime<Utc>,
}

/// Idempotent terminal result for one job generation.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResultReceipt {
    /// Exact schema version.
    pub schema_version: String,
    /// Exact job.
    pub job_id: Uuid,
    /// Exact lease generation.
    pub generation: u32,
    /// Digest of the exact snapshot bytes received by the executor.
    pub snapshot_sha256: String,
    /// Exact immutable runtime profile.
    pub runtime_id: String,
    /// Exact evaluated model catalog ID.
    pub model_id: String,
    /// Runtime-observed completion time.
    pub completed_at: DateTime<Utc>,
    /// Bounded success or non-sensitive failure.
    pub outcome: RuntimeOutcome,
}

/// Bounded, broker-persistable runtime outcome.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeOutcome {
    /// The model returned a terminal final answer.
    Succeeded {
        /// ACP terminal reason.
        stop_reason: String,
        /// Final-answer chunks only; never thoughts or tool diagnostics.
        output: String,
        /// Whether additional output was discarded at the executor ceiling.
        output_truncated: bool,
        /// Best-effort input-token usage.
        input_tokens: Option<u64>,
        /// Best-effort output-token usage.
        output_tokens: Option<u64>,
    },
    /// The runtime failed without returning raw diagnostic content.
    Failed {
        /// Stable, bounded failure category.
        failure_code: String,
    },
}

/// Minimal response to an idempotent broker receipt.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerAck {
    /// Exact schema version.
    pub schema_version: String,
    /// True only when the receipt was committed or matched an existing digest.
    pub accepted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contracts_reject_unknown_fields_and_preserve_snake_case() {
        let classification = serde_json::to_string(&Classification::Restricted).unwrap();
        assert_eq!(classification, "\"restricted\"");
        assert!(serde_json::from_str::<BrokerAck>(
            r#"{"schema_version":"snowman.agent.broker.ack.v1","accepted":true,"extra":1}"#
        )
        .is_err());
    }
}
