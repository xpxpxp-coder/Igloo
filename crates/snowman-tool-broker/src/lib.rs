#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Fail-closed policy and evidence contracts for Snowman agent actions.
//!
//! An agent may reason broadly, but it can execute only a typed action from an
//! operations-owned registry. Callers cannot supply an executable, shell
//! command, URL, cloud credential, environment variable, or AWS API name.
//! This crate authorizes and canonicalizes actions; an isolated runtime must
//! still enforce the returned plan and pass the staging gates in the runbook.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Exact request contract accepted by the action broker.
pub const ACTION_SCHEMA: &str = "snowman.agent-action.v1";
/// Exact append-only receipt contract.
pub const RECEIPT_SCHEMA: &str = "snowman.agent-action-receipt.v1";
/// Maximum lifetime of a single action authorization.
pub const MAX_ACTION_LIFETIME_SECONDS: i64 = 900;

/// Data sensitivity carried by one minimized action.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    /// Snowman internal data with no client-confidential content.
    Internal,
    /// Confidential Snowman or client work product.
    Confidential,
    /// Restricted material; policy must explicitly opt in.
    Restricted,
}

/// Side-effect risk of a registered action.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    /// Read-only or safely reversible work.
    Low,
    /// External communication or material mutation.
    High,
    /// Destructive, identity, billing, deployment, secret, or export action.
    Critical,
}

/// Approval required by an operations-owned capability definition.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    /// No separate approval is required after live authority is rechecked.
    None,
    /// An expiring approval by a Snowman human identity is required.
    Human,
}

/// File operation available to an agent. There is deliberately no shell form.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    /// Read a regular file.
    Read,
    /// Create a new regular file without replacing an existing object.
    Create,
    /// Replace one regular file using an atomic, broker-controlled write.
    Replace,
    /// Delete one regular file. This must be critical and human-approved.
    Delete,
}

/// Fixed HTTPS methods that an egress policy may expose.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP HEAD.
    Head,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}

/// Caller-selected intent within one fixed registry route.
///
/// Values are identifiers or digests, never raw URLs, executable paths, shell
/// strings, secrets, phone numbers, datasets, or provider credentials.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolIntent {
    /// Access a path relative to one registered filesystem root.
    File {
        /// Registered root identifier, not a host path.
        root_id: String,
        /// Strict relative path. `.`/`..`, prefixes, empty components, and NUL
        /// bytes are prohibited.
        relative_path: String,
        /// Exact operation.
        operation: FileOperation,
        /// Bounded byte count.
        size_bytes: u64,
    },
    /// Call one registered Snowman or approved provider destination.
    Https {
        /// Registered destination identifier; the caller cannot submit a host.
        destination_id: String,
        /// Fixed method.
        method: HttpMethod,
        /// Relative resource template identifier, not a URL or path.
        resource_id: String,
        /// Digest of the separately bounded body, if any.
        body_sha256: Option<String>,
    },
    /// Perform one exact AWS operation from an operations-owned policy.
    Aws {
        /// Registered AWS action policy identifier.
        aws_policy_id: String,
        /// Exact registered resource identifier, not a caller-supplied ARN.
        resource_id: String,
        /// Digest of the bounded service request.
        parameters_sha256: String,
    },
    /// Invoke one reviewed, digest-pinned program without a shell.
    ReviewedProgram {
        /// Registered program identifier.
        program_id: String,
        /// Registered argument-schema identifier.
        input_contract_id: String,
        /// Digest of a bounded input document.
        input_sha256: String,
    },
}

/// Operations-owned route. Request data can select only its stable identifier.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolRoute {
    /// Brokered file operations rooted at a pre-opened directory.
    File {
        /// Registered root identifier.
        root_id: String,
        /// Operations permitted beneath the root.
        operations: BTreeSet<FileOperation>,
        /// Per-action byte ceiling.
        max_bytes: u64,
        /// Runtime must use a descriptor-relative, no-symlink open primitive.
        descriptor_relative_no_symlink: bool,
    },
    /// Fixed egress route. The executor constructs the URL from policy.
    Https {
        /// Registered destination identifier.
        destination_id: String,
        /// Exact lowercase DNS host.
        host: String,
        /// Exact TLS port, normally 443.
        port: u16,
        /// Allowed methods.
        methods: BTreeSet<HttpMethod>,
        /// Allowed resource identifiers mapped to paths in operations config.
        resource_ids: BTreeSet<String>,
        /// Must remain false.
        follow_redirects: bool,
        /// Must remain false.
        inherit_proxy: bool,
    },
    /// Fixed AWS action performed by the trusted broker task role.
    Aws {
        /// Registered policy identifier.
        aws_policy_id: String,
        /// Exact twelve-digit Snowman AWS account.
        account_id: String,
        /// Exact region.
        region: String,
        /// Exact service name.
        service: String,
        /// Exact API action.
        operation: String,
        /// Registered resource identifiers mapped to exact ARNs in IAM/config.
        resource_ids: BTreeSet<String>,
        /// Must remain true: no credential is returned to a child.
        broker_task_role_only: bool,
    },
    /// Digest-pinned program invoked directly with a fixed sandbox profile.
    ReviewedProgram {
        /// Registered program identifier.
        program_id: String,
        /// SHA-256 of the executable artifact.
        executable_sha256: String,
        /// Registered input/argument contract.
        input_contract_id: String,
        /// Registered sandbox profile.
        sandbox_profile_id: String,
        /// Must remain true; a shell is never involved.
        direct_exec_only: bool,
        /// Must remain true; the environment begins empty.
        clear_environment: bool,
        /// Non-secret environment variable names explicitly reconstructed by
        /// the trusted runtime. Credential-bearing names are prohibited.
        environment_allowlist: BTreeSet<String>,
        /// Whether this program receives brokered network access.
        network_access: bool,
    },
}

/// One versioned entry in the operations-owned capability registry.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDefinition {
    /// Stable capability identifier.
    pub capability_id: String,
    /// Stable tool identifier.
    pub tool_id: String,
    /// Immutable registry version digest.
    pub registry_sha256: String,
    /// Exact route.
    pub route: ToolRoute,
    /// Explicit data classes allowed on this route.
    pub classifications: BTreeSet<DataClassification>,
    /// Declared impact.
    pub impact: Impact,
    /// Required approval.
    pub approval: ApprovalRequirement,
    /// Maximum execution duration.
    pub max_duration_seconds: u64,
    /// Operations kill switch.
    pub enabled: bool,
}

/// Complete operations-owned capability registry.
#[derive(Debug, Clone, Default)]
pub struct CapabilityRegistry {
    definitions: BTreeMap<(String, String), CapabilityDefinition>,
}

impl CapabilityRegistry {
    /// Validate and build an exact registry. Duplicate capability/tool tuples
    /// are rejected rather than overwritten.
    pub fn new(definitions: Vec<CapabilityDefinition>) -> Result<Self, Error> {
        let mut entries = BTreeMap::new();
        for definition in definitions {
            validate_definition(&definition)?;
            let key = (definition.capability_id.clone(), definition.tool_id.clone());
            if entries.insert(key, definition).is_some() {
                return Err(Error::InvalidPolicy("duplicate capability/tool route"));
            }
        }
        if entries.is_empty() {
            return Err(Error::InvalidPolicy("registry cannot be empty"));
        }
        Ok(Self {
            definitions: entries,
        })
    }

    fn get(&self, capability: &str, tool: &str) -> Option<&CapabilityDefinition> {
        self.definitions
            .get(&(capability.to_owned(), tool.to_owned()))
    }
}

/// Live job/lease identity reloaded for every authorization.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveAuthority {
    /// Tenant/community boundary.
    pub tenant_id: Uuid,
    /// Workspace boundary from the immutable job snapshot.
    pub workspace_id: Uuid,
    /// Workforce request.
    pub request_id: Uuid,
    /// One-shot agent job.
    pub job_id: Uuid,
    /// Workforce task.
    pub task_id: Uuid,
    /// Agent identity for this runtime/job.
    pub agent_identity_id: Uuid,
    /// Owning Snowman service identity.
    pub service_identity_id: Uuid,
    /// Job generation.
    pub generation: u64,
    /// Current task-lease generation.
    pub lease_generation: u64,
    /// Digest of the current lease fence token.
    pub lease_fence_sha256: String,
    /// Exact grants on the live job.
    pub capability_grants: BTreeSet<String>,
    /// Maximum data classification for this job.
    pub max_classification: DataClassification,
    /// Exact minimization evidence bound at issuance.
    pub minimization_evidence_sha256: String,
    /// Live job/lease deadline.
    pub deadline_at: DateTime<Utc>,
    /// Job state must be `started`.
    pub started: bool,
    /// Completion/cancellation/revocation fence.
    pub revoked: bool,
}

/// Canonical action request. Raw tool content travels out-of-band under its
/// digest and data-minimization contract.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionRequest {
    /// Exact schema.
    pub schema_version: String,
    /// Stable action/idempotency coordinate.
    pub action_id: Uuid,
    /// Tenant boundary copied from the authenticated authority.
    pub tenant_id: Uuid,
    /// Workspace boundary.
    pub workspace_id: Uuid,
    /// Workforce request.
    pub request_id: Uuid,
    /// One-shot agent job.
    pub job_id: Uuid,
    /// Workforce task.
    pub task_id: Uuid,
    /// Agent identity.
    pub agent_identity_id: Uuid,
    /// Service identity.
    pub service_identity_id: Uuid,
    /// Job generation.
    pub generation: u64,
    /// Lease generation.
    pub lease_generation: u64,
    /// Lease fence digest.
    pub lease_fence_sha256: String,
    /// Capability identifier.
    pub capability_id: String,
    /// Tool identifier.
    pub tool_id: String,
    /// Requested classification.
    pub classification: DataClassification,
    /// Exact minimization-evidence digest.
    pub minimization_evidence_sha256: String,
    /// Typed, bounded intent.
    pub intent: ToolIntent,
    /// Digest of the minimized action input.
    pub input_sha256: String,
    /// Requested deadline, bounded by job and policy.
    pub deadline_at: DateTime<Utc>,
    /// Digest of this request with this field empty.
    pub action_sha256: String,
}

impl ActionRequest {
    /// Calculate the canonical action digest. Serialization is deterministic:
    /// structs have fixed field order and all sets/maps use sorted containers.
    pub fn canonical_sha256(&self) -> Result<String, Error> {
        let mut canonical = self.clone();
        canonical.action_sha256.clear();
        let body = serde_json::to_vec(&canonical)
            .map_err(|_| Error::InvalidRequest("request cannot be canonicalized"))?;
        Ok(hex::encode(Sha256::digest(body)))
    }
}

/// Expiring approval bound to one exact action and generation.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// Approval coordinate.
    pub approval_id: Uuid,
    /// Tenant boundary.
    pub tenant_id: Uuid,
    /// Workspace boundary.
    pub workspace_id: Uuid,
    /// Job boundary.
    pub job_id: Uuid,
    /// Task boundary.
    pub task_id: Uuid,
    /// Job generation.
    pub generation: u64,
    /// Exact action digest.
    pub action_sha256: String,
    /// Snowman human identity that decided the action.
    pub approver_identity_id: Uuid,
    /// Approval state.
    pub decision: ApprovalDecision,
    /// Decision time.
    pub decided_at: DateTime<Utc>,
    /// Hard expiration.
    pub expires_at: DateTime<Utc>,
}

/// Human approval decision.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// Action is approved until expiry or revocation.
    Approved,
    /// Action is denied.
    Denied,
    /// An earlier approval was revoked.
    Revoked,
}

/// Durable action state used for idempotent reconciliation.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    /// Policy accepted the action but no side effect has begun.
    Authorized,
    /// Dispatch linearized; outcome may be unknown.
    Indeterminate,
    /// Action completed successfully.
    Succeeded,
    /// Action completed with a known failure.
    Failed,
    /// Action was cancelled before dispatch.
    Cancelled,
    /// Policy denied the action; retained as evidence.
    Denied,
}

/// Minimal prior record used for exact replay detection.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PriorAction {
    /// Action coordinate.
    pub action_id: Uuid,
    /// Exact action digest.
    pub action_sha256: String,
    /// Tenant boundary.
    pub tenant_id: Uuid,
    /// Workspace boundary.
    pub workspace_id: Uuid,
    /// Job boundary.
    pub job_id: Uuid,
    /// Task boundary.
    pub task_id: Uuid,
    /// Generation boundary.
    pub generation: u64,
    /// Durable status.
    pub status: ActionStatus,
    /// Latest append-only receipt digest, if any.
    pub receipt_sha256: Option<String>,
}

/// Fully constrained action plan. It contains no credential or raw secret.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlan {
    /// Action coordinate.
    pub action_id: Uuid,
    /// Exact action digest.
    pub action_sha256: String,
    /// Capability registry digest.
    pub registry_sha256: String,
    /// Operations-owned route.
    pub route: ToolRoute,
    /// Typed caller intent.
    pub intent: ToolIntent,
    /// Deadline.
    pub deadline_at: DateTime<Utc>,
    /// Direct shell execution is always prohibited.
    pub shell_prohibited: bool,
    /// Child environment begins empty.
    pub clear_child_environment: bool,
    /// Provider, relay, model, connector, private-key, and AWS credentials are
    /// never inherited by a child tool.
    pub child_credentials_prohibited: bool,
}

/// Outcome of authorization or exact idempotent reconciliation.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// A new action may be persisted as `authorized`.
    Authorized {
        /// Complete execution plan.
        plan: Box<ExecutionPlan>,
        /// Approval consumed by this action, if required.
        approval_id: Option<Uuid>,
    },
    /// The action already exists. The broker must not dispatch it again.
    Replay {
        /// Existing durable status.
        status: ActionStatus,
        /// Latest receipt digest, if available.
        receipt_sha256: Option<String>,
    },
}

/// Append-only, content-free action evidence.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionReceipt {
    /// Exact receipt schema.
    pub schema_version: String,
    /// Receipt coordinate.
    pub receipt_id: Uuid,
    /// Tenant boundary.
    pub tenant_id: Uuid,
    /// Workspace boundary.
    pub workspace_id: Uuid,
    /// Job boundary.
    pub job_id: Uuid,
    /// Task boundary.
    pub task_id: Uuid,
    /// Job generation.
    pub generation: u64,
    /// Action coordinate.
    pub action_id: Uuid,
    /// Monotonic per-action sequence.
    pub sequence: u64,
    /// State recorded by this event.
    pub status: ActionStatus,
    /// Exact action digest.
    pub action_sha256: String,
    /// Digest of a redacted result envelope, if terminal.
    pub result_sha256: Option<String>,
    /// Evidence that logs/result content were redacted and minimized.
    pub redaction_evidence_sha256: String,
    /// Previous signed receipt digest; absent only for sequence zero.
    pub previous_receipt_sha256: Option<String>,
    /// Exact KMS key ARN used to sign the externally checkpointed receipt.
    pub signing_key_arn: String,
    /// Digest of the KMS signature bytes.
    pub signature_sha256: String,
    /// Digest of the immutable external checkpoint/object reference.
    pub external_checkpoint_sha256: String,
    /// Event time.
    pub occurred_at: DateTime<Utc>,
}

impl ActionReceipt {
    /// Validate bounded receipt evidence and return its canonical digest.
    pub fn canonical_sha256(&self) -> Result<String, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|_| Error::InvalidReceipt("receipt cannot be canonicalized"))?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    /// Validate the chain/signature/checkpoint envelope.
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != RECEIPT_SCHEMA
            || self.receipt_id.is_nil()
            || self.tenant_id.is_nil()
            || self.workspace_id.is_nil()
            || self.job_id.is_nil()
            || self.task_id.is_nil()
            || self.action_id.is_nil()
            || self.generation == 0
            || !is_sha256(&self.action_sha256)
            || !is_sha256(&self.redaction_evidence_sha256)
            || !is_sha256(&self.signature_sha256)
            || !is_sha256(&self.external_checkpoint_sha256)
            || self.result_sha256.as_deref().is_some_and(|v| !is_sha256(v))
            || self
                .previous_receipt_sha256
                .as_deref()
                .is_some_and(|v| !is_sha256(v))
            || (self.sequence == 0) != self.previous_receipt_sha256.is_none()
            || !valid_signing_key_arn(&self.signing_key_arn)
        {
            return Err(Error::InvalidReceipt("receipt evidence is malformed"));
        }
        let terminal = matches!(
            self.status,
            ActionStatus::Succeeded
                | ActionStatus::Failed
                | ActionStatus::Cancelled
                | ActionStatus::Denied
        );
        if terminal != self.result_sha256.is_some() {
            return Err(Error::InvalidReceipt(
                "terminal receipts require one redacted result digest",
            ));
        }
        Ok(())
    }
}

/// Fail-closed policy errors. Messages never include request content.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Operations policy is invalid.
    #[error("Snowman tool policy is invalid: {0}")]
    InvalidPolicy(&'static str),
    /// Request contract is invalid.
    #[error("Snowman tool request is invalid: {0}")]
    InvalidRequest(&'static str),
    /// Live authority does not permit the action.
    #[error("Snowman tool action is not authorized: {0}")]
    NotAuthorized(&'static str),
    /// An action identifier was reused for different content or authority.
    #[error("Snowman tool action conflicts with an existing idempotency record")]
    ReplayConflict,
    /// Receipt contract is invalid.
    #[error("Snowman tool receipt is invalid: {0}")]
    InvalidReceipt(&'static str),
    /// Dedicated database identity violated its boundary.
    #[error("Snowman tool broker database role is invalid")]
    DatabaseRole,
    /// Database verification failed without exposing query/request data.
    #[error("Snowman tool broker database verification failed")]
    Database,
}

/// Authorize a typed action against fresh authority and exact operations
/// policy. This function performs no side effect.
pub fn authorize(
    authority: &LiveAuthority,
    request: &ActionRequest,
    registry: &CapabilityRegistry,
    approval: Option<&Approval>,
    prior: Option<&PriorAction>,
    now: DateTime<Utc>,
) -> Result<Decision, Error> {
    validate_request(request)?;
    bind_authority(authority, request)?;

    if let Some(existing) = prior {
        let exact = existing.action_id == request.action_id
            && existing.action_sha256 == request.action_sha256
            && existing.tenant_id == request.tenant_id
            && existing.workspace_id == request.workspace_id
            && existing.job_id == request.job_id
            && existing.task_id == request.task_id
            && existing.generation == request.generation;
        if !exact {
            return Err(Error::ReplayConflict);
        }
        return Ok(Decision::Replay {
            status: existing.status,
            receipt_sha256: existing.receipt_sha256.clone(),
        });
    }

    if !authority.started || authority.revoked {
        return Err(Error::NotAuthorized("job is not live"));
    }
    if now >= authority.deadline_at || now >= request.deadline_at {
        return Err(Error::NotAuthorized("action deadline has expired"));
    }
    if request.deadline_at > authority.deadline_at
        || request.deadline_at > now + Duration::seconds(MAX_ACTION_LIFETIME_SECONDS)
    {
        return Err(Error::NotAuthorized("action deadline exceeds authority"));
    }
    if !authority.capability_grants.contains(&request.capability_id) {
        return Err(Error::NotAuthorized("capability is not granted"));
    }
    if request.classification > authority.max_classification {
        return Err(Error::NotAuthorized("classification exceeds job authority"));
    }

    let definition = registry
        .get(&request.capability_id, &request.tool_id)
        .ok_or(Error::NotAuthorized("capability route is not registered"))?;
    if !definition.enabled {
        return Err(Error::NotAuthorized("capability route is disabled"));
    }
    if !definition.classifications.contains(&request.classification) {
        return Err(Error::NotAuthorized(
            "classification is not allowed on the route",
        ));
    }
    validate_intent(&request.intent, definition)?;

    let approval_id =
        if definition.approval == ApprovalRequirement::Human || definition.impact >= Impact::High {
            let approval = approval.ok_or(Error::NotAuthorized("human approval is required"))?;
            validate_approval(approval, request, now)?;
            Some(approval.approval_id)
        } else {
            None
        };

    Ok(Decision::Authorized {
        plan: Box::new(ExecutionPlan {
            action_id: request.action_id,
            action_sha256: request.action_sha256.clone(),
            registry_sha256: definition.registry_sha256.clone(),
            route: definition.route.clone(),
            intent: request.intent.clone(),
            deadline_at: request.deadline_at,
            shell_prohibited: true,
            clear_child_environment: true,
            child_credentials_prohibited: true,
        }),
        approval_id,
    })
}

/// Validate a state transition around the dispatch linearization point.
/// `authorized -> indeterminate` must commit before any external side effect.
pub fn validate_transition(from: ActionStatus, to: ActionStatus) -> Result<(), Error> {
    let valid = matches!(
        (from, to),
        (ActionStatus::Authorized, ActionStatus::Indeterminate)
            | (ActionStatus::Authorized, ActionStatus::Cancelled)
            | (ActionStatus::Indeterminate, ActionStatus::Succeeded)
            | (ActionStatus::Indeterminate, ActionStatus::Failed)
    );
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidRequest("invalid action state transition"))
    }
}

/// Bootstrap a login role with only the action ledgers required by the broker.
/// Identifiers are strictly validated before interpolation.
pub async fn install_database_role(
    admin: &PgPool,
    database_name: &str,
    role: &str,
) -> Result<(), Error> {
    if !valid_pg_identifier(database_name) || !valid_pg_identifier(role) {
        return Err(Error::DatabaseRole);
    }
    let sql = format!(
        "DO $role$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role} LOGIN; END IF; END $role$;\n\
         REVOKE ALL ON DATABASE {database_name} FROM {role};\n\
         GRANT CONNECT ON DATABASE {database_name} TO {role};\n\
         REVOKE CREATE ON SCHEMA public FROM {role};\n\
         GRANT USAGE ON SCHEMA public TO {role};\n\
         REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role};\n\
         GRANT SELECT ON TABLE snowman_agent_jobs,snowman_work_requests,snowman_work_tasks,snowman_task_leases,snowman_workforce_identities TO {role};\n\
         GRANT SELECT,INSERT,UPDATE ON TABLE snowman_agent_tool_actions TO {role};\n\
         GRANT SELECT ON TABLE snowman_agent_tool_approvals TO {role};\n\
         GRANT SELECT,INSERT ON TABLE snowman_agent_tool_receipts TO {role};"
    );
    // Both interpolated identifiers passed the strict PostgreSQL identifier
    // grammar above; no other caller-controlled value enters this statement.
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(admin)
        .await
        .map_err(|_| Error::Database)?;
    Ok(())
}

/// Fail closed unless the connected role has only its exact action authority.
pub async fn verify_database_role(pool: &PgPool, expected_role: &str) -> Result<(), Error> {
    if !valid_pg_identifier(expected_role) {
        return Err(Error::DatabaseRole);
    }
    let row = sqlx::query(
        "SELECT current_user=$1 AS exact_role, \
         has_database_privilege(current_user,current_database(),'CONNECT') AS db_connect, \
         NOT has_database_privilege(current_user,current_database(),'CREATE') AS no_db_create, \
         has_schema_privilege(current_user,'public','USAGE') AS schema_use, \
         NOT has_schema_privilege(current_user,'public','CREATE') AS no_schema_create, \
         has_table_privilege(current_user,'snowman_agent_jobs','SELECT') AND \
         NOT has_table_privilege(current_user,'snowman_agent_jobs','INSERT,UPDATE,DELETE,TRUNCATE') AS jobs_read_only, \
         has_table_privilege(current_user,'snowman_agent_tool_actions','SELECT,INSERT,UPDATE') AND \
         NOT has_table_privilege(current_user,'snowman_agent_tool_actions','DELETE,TRUNCATE') AS actions_exact, \
         has_table_privilege(current_user,'snowman_agent_tool_approvals','SELECT') AND \
         NOT has_table_privilege(current_user,'snowman_agent_tool_approvals','INSERT,UPDATE,DELETE,TRUNCATE') AS approvals_read_only, \
         has_table_privilege(current_user,'snowman_agent_tool_receipts','SELECT,INSERT') AND \
         NOT has_table_privilege(current_user,'snowman_agent_tool_receipts','UPDATE,DELETE,TRUNCATE') AS receipts_append_only, \
         NOT has_table_privilege(current_user,'events','SELECT') AND \
         NOT has_table_privilege(current_user,'channels','SELECT') AND \
         NOT has_table_privilege(current_user,'audit_log','SELECT') AND \
         NOT has_table_privilege(current_user,'snowman_agent_model_generations','SELECT,INSERT,UPDATE,DELETE') AND \
         NOT has_table_privilege(current_user,'snowman_meeting_sessions','SELECT,INSERT,UPDATE,DELETE') AS isolated",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await
    .map_err(|_| Error::Database)?;
    for column in [
        "exact_role",
        "db_connect",
        "no_db_create",
        "schema_use",
        "no_schema_create",
        "jobs_read_only",
        "actions_exact",
        "approvals_read_only",
        "receipts_append_only",
        "isolated",
    ] {
        if !row
            .try_get::<bool, _>(column)
            .map_err(|_| Error::Database)?
        {
            return Err(Error::DatabaseRole);
        }
    }
    Ok(())
}

fn validate_definition(definition: &CapabilityDefinition) -> Result<(), Error> {
    if !valid_identifier(&definition.capability_id)
        || !valid_identifier(&definition.tool_id)
        || !is_sha256(&definition.registry_sha256)
        || definition.classifications.is_empty()
        || !(1..=MAX_ACTION_LIFETIME_SECONDS as u64).contains(&definition.max_duration_seconds)
        || (definition.impact >= Impact::High && definition.approval != ApprovalRequirement::Human)
    {
        return Err(Error::InvalidPolicy("capability metadata is invalid"));
    }
    match &definition.route {
        ToolRoute::File {
            root_id,
            operations,
            max_bytes,
            descriptor_relative_no_symlink,
        } => {
            if !valid_identifier(root_id)
                || operations.is_empty()
                || *max_bytes == 0
                || *max_bytes > 100 * 1024 * 1024
                || !descriptor_relative_no_symlink
                || (operations.contains(&FileOperation::Delete)
                    && definition.impact != Impact::Critical)
            {
                return Err(Error::InvalidPolicy("filesystem route is unsafe"));
            }
        }
        ToolRoute::Https {
            destination_id,
            host,
            port,
            methods,
            resource_ids,
            follow_redirects,
            inherit_proxy,
        } => {
            if !valid_identifier(destination_id)
                || !valid_host(host)
                || *port != 443
                || methods.is_empty()
                || resource_ids.is_empty()
                || resource_ids.iter().any(|v| !valid_identifier(v))
                || *follow_redirects
                || *inherit_proxy
            {
                return Err(Error::InvalidPolicy("egress route is unsafe"));
            }
        }
        ToolRoute::Aws {
            aws_policy_id,
            account_id,
            region,
            service,
            operation,
            resource_ids,
            broker_task_role_only,
        } => {
            if !valid_identifier(aws_policy_id)
                || account_id.len() != 12
                || !account_id.bytes().all(|b| b.is_ascii_digit())
                || !valid_identifier(region)
                || !valid_identifier(service)
                || !valid_identifier(operation)
                || resource_ids.is_empty()
                || resource_ids.iter().any(|v| !valid_identifier(v))
                || !broker_task_role_only
                || definition.impact != Impact::Critical
            {
                return Err(Error::InvalidPolicy("AWS route is unsafe"));
            }
        }
        ToolRoute::ReviewedProgram {
            program_id,
            executable_sha256,
            input_contract_id,
            sandbox_profile_id,
            direct_exec_only,
            clear_environment,
            environment_allowlist,
            network_access,
        } => {
            if !valid_identifier(program_id)
                || !is_sha256(executable_sha256)
                || !valid_identifier(input_contract_id)
                || !valid_identifier(sandbox_profile_id)
                || !direct_exec_only
                || !clear_environment
                || *network_access
                || environment_allowlist
                    .iter()
                    .any(|name| !valid_env_name(name) || credential_environment_name(name))
            {
                return Err(Error::InvalidPolicy("reviewed program route is unsafe"));
            }
        }
    }
    Ok(())
}

fn validate_request(request: &ActionRequest) -> Result<(), Error> {
    if request.schema_version != ACTION_SCHEMA
        || request.action_id.is_nil()
        || request.tenant_id.is_nil()
        || request.workspace_id.is_nil()
        || request.request_id.is_nil()
        || request.job_id.is_nil()
        || request.task_id.is_nil()
        || request.agent_identity_id.is_nil()
        || request.service_identity_id.is_nil()
        || request.generation == 0
        || request.lease_generation == 0
        || !is_sha256(&request.lease_fence_sha256)
        || !valid_identifier(&request.capability_id)
        || !valid_identifier(&request.tool_id)
        || !is_sha256(&request.minimization_evidence_sha256)
        || !is_sha256(&request.input_sha256)
        || !is_sha256(&request.action_sha256)
        || request.canonical_sha256()? != request.action_sha256
    {
        return Err(Error::InvalidRequest("request contract is malformed"));
    }
    Ok(())
}

fn bind_authority(authority: &LiveAuthority, request: &ActionRequest) -> Result<(), Error> {
    if authority.tenant_id != request.tenant_id
        || authority.workspace_id != request.workspace_id
        || authority.request_id != request.request_id
        || authority.job_id != request.job_id
        || authority.task_id != request.task_id
        || authority.agent_identity_id != request.agent_identity_id
        || authority.service_identity_id != request.service_identity_id
        || authority.generation != request.generation
        || authority.lease_generation != request.lease_generation
        || authority.lease_fence_sha256 != request.lease_fence_sha256
        || authority.minimization_evidence_sha256 != request.minimization_evidence_sha256
    {
        return Err(Error::NotAuthorized("authority binding does not match"));
    }
    Ok(())
}

fn validate_intent(intent: &ToolIntent, definition: &CapabilityDefinition) -> Result<(), Error> {
    match (intent, &definition.route) {
        (
            ToolIntent::File {
                root_id,
                relative_path,
                operation,
                size_bytes,
            },
            ToolRoute::File {
                root_id: allowed_root,
                operations,
                max_bytes,
                ..
            },
        ) if root_id == allowed_root
            && valid_relative_path(relative_path)
            && operations.contains(operation)
            && *size_bytes <= *max_bytes =>
        {
            Ok(())
        }
        (
            ToolIntent::Https {
                destination_id,
                method,
                resource_id,
                body_sha256,
            },
            ToolRoute::Https {
                destination_id: allowed_destination,
                methods,
                resource_ids,
                ..
            },
        ) if destination_id == allowed_destination
            && methods.contains(method)
            && resource_ids.contains(resource_id)
            && body_sha256.as_deref().is_none_or(is_sha256) =>
        {
            Ok(())
        }
        (
            ToolIntent::Aws {
                aws_policy_id,
                resource_id,
                parameters_sha256,
            },
            ToolRoute::Aws {
                aws_policy_id: allowed_policy,
                resource_ids,
                ..
            },
        ) if aws_policy_id == allowed_policy
            && resource_ids.contains(resource_id)
            && is_sha256(parameters_sha256) =>
        {
            Ok(())
        }
        (
            ToolIntent::ReviewedProgram {
                program_id,
                input_contract_id,
                input_sha256,
            },
            ToolRoute::ReviewedProgram {
                program_id: allowed_program,
                input_contract_id: allowed_contract,
                ..
            },
        ) if program_id == allowed_program
            && input_contract_id == allowed_contract
            && is_sha256(input_sha256) =>
        {
            Ok(())
        }
        _ => Err(Error::NotAuthorized(
            "tool intent does not match the registered route",
        )),
    }
}

fn validate_approval(
    approval: &Approval,
    request: &ActionRequest,
    now: DateTime<Utc>,
) -> Result<(), Error> {
    if approval.approval_id.is_nil()
        || approval.tenant_id != request.tenant_id
        || approval.workspace_id != request.workspace_id
        || approval.job_id != request.job_id
        || approval.task_id != request.task_id
        || approval.generation != request.generation
        || approval.action_sha256 != request.action_sha256
        || approval.approver_identity_id.is_nil()
        || approval.decision != ApprovalDecision::Approved
        || approval.decided_at > now
        || approval.expires_at <= now
        || approval.expires_at > request.deadline_at
    {
        return Err(Error::NotAuthorized("approval is not live and exact"));
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index > 0,
            _ => false,
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\0')
        && !value.contains('\\')
        && !value.contains(':')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && (value.ends_with(".snowmanai.org")
            || value == "snowmanai.org"
            || value.ends_with(".amazonaws.com")
            || value.ends_with(".googleapis.com")
            || value.ends_with(".twilio.com")
            || value.ends_with(".openai.com")
            || value.ends_with(".elevenlabs.io"))
}

fn valid_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_uppercase() || (index > 0 && byte.is_ascii_digit())
        })
}

fn credential_environment_name(value: &str) -> bool {
    let value = value.to_ascii_uppercase();
    [
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "CREDENTIAL",
        "COOKIE",
        "AUTH",
        "AWS_",
        "GOOGLE_",
        "OPENAI_",
        "ANTHROPIC_",
        "NOSTR_",
        "BUZZ_",
        "SNOWMAN_AGENT_JOB_TOKEN",
    ]
    .iter()
    .any(|needle| value.contains(needle))
}

fn valid_signing_key_arn(value: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts[0] == "arn"
        && parts[1] == "aws"
        && parts[2] == "kms"
        && valid_identifier(parts[3])
        && parts[4].len() == 12
        && parts[4].bytes().all(|b| b.is_ascii_digit())
        && parts[5].starts_with("key/")
        && valid_identifier(&parts[5][4..])
}

fn valid_pg_identifier(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_lowercase() || (i > 0 && b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn ids() -> [Uuid; 7] {
        [
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            Uuid::from_u128(4),
            Uuid::from_u128(5),
            Uuid::from_u128(6),
            Uuid::from_u128(7),
        ]
    }

    fn authority(now: DateTime<Utc>) -> LiveAuthority {
        let [tenant, workspace, request, job, task, agent, service] = ids();
        LiveAuthority {
            tenant_id: tenant,
            workspace_id: workspace,
            request_id: request,
            job_id: job,
            task_id: task,
            agent_identity_id: agent,
            service_identity_id: service,
            generation: 3,
            lease_generation: 9,
            lease_fence_sha256: digest('a'),
            capability_grants: BTreeSet::from(["workspace.files.read".into()]),
            max_classification: DataClassification::Confidential,
            minimization_evidence_sha256: digest('b'),
            deadline_at: now + Duration::minutes(20),
            started: true,
            revoked: false,
        }
    }

    fn definition() -> CapabilityDefinition {
        CapabilityDefinition {
            capability_id: "workspace.files.read".into(),
            tool_id: "file.read.v1".into(),
            registry_sha256: digest('c'),
            route: ToolRoute::File {
                root_id: "task-workspace".into(),
                operations: BTreeSet::from([FileOperation::Read]),
                max_bytes: 1024,
                descriptor_relative_no_symlink: true,
            },
            classifications: BTreeSet::from([
                DataClassification::Internal,
                DataClassification::Confidential,
            ]),
            impact: Impact::Low,
            approval: ApprovalRequirement::None,
            max_duration_seconds: 60,
            enabled: true,
        }
    }

    fn request(now: DateTime<Utc>) -> ActionRequest {
        let authority = authority(now);
        let mut request = ActionRequest {
            schema_version: ACTION_SCHEMA.into(),
            action_id: Uuid::from_u128(8),
            tenant_id: authority.tenant_id,
            workspace_id: authority.workspace_id,
            request_id: authority.request_id,
            job_id: authority.job_id,
            task_id: authority.task_id,
            agent_identity_id: authority.agent_identity_id,
            service_identity_id: authority.service_identity_id,
            generation: authority.generation,
            lease_generation: authority.lease_generation,
            lease_fence_sha256: authority.lease_fence_sha256,
            capability_id: "workspace.files.read".into(),
            tool_id: "file.read.v1".into(),
            classification: DataClassification::Confidential,
            minimization_evidence_sha256: authority.minimization_evidence_sha256,
            intent: ToolIntent::File {
                root_id: "task-workspace".into(),
                relative_path: "reports/final.md".into(),
                operation: FileOperation::Read,
                size_bytes: 512,
            },
            input_sha256: digest('d'),
            deadline_at: now + Duration::minutes(5),
            action_sha256: String::new(),
        };
        request.action_sha256 = request.canonical_sha256().expect("canonical digest");
        request
    }

    #[test]
    fn exact_scoped_file_action_is_authorized_without_shell_or_credentials() {
        let now = Utc::now();
        let registry = CapabilityRegistry::new(vec![definition()]).expect("registry");
        let decision = authorize(&authority(now), &request(now), &registry, None, None, now)
            .expect("authorized");
        let Decision::Authorized { plan, .. } = decision else {
            panic!("expected authorization")
        };
        assert!(plan.shell_prohibited);
        assert!(plan.clear_child_environment);
        assert!(plan.child_credentials_prohibited);
    }

    #[test]
    fn absent_capability_defaults_to_denial() {
        let now = Utc::now();
        let mut authority = authority(now);
        authority.capability_grants.clear();
        let registry = CapabilityRegistry::new(vec![definition()]).expect("registry");
        assert_eq!(
            authorize(&authority, &request(now), &registry, None, None, now),
            Err(Error::NotAuthorized("capability is not granted"))
        );
    }

    #[test]
    fn cross_tenant_workspace_and_identity_substitutions_are_denied() {
        let now = Utc::now();
        let registry = CapabilityRegistry::new(vec![definition()]).expect("registry");
        for mutate in 0..3 {
            let mut candidate = request(now);
            match mutate {
                0 => candidate.tenant_id = Uuid::new_v4(),
                1 => candidate.workspace_id = Uuid::new_v4(),
                _ => candidate.agent_identity_id = Uuid::new_v4(),
            }
            candidate.action_sha256 = candidate.canonical_sha256().expect("digest");
            assert_eq!(
                authorize(&authority(now), &candidate, &registry, None, None, now),
                Err(Error::NotAuthorized("authority binding does not match"))
            );
        }
    }

    #[test]
    fn stale_generation_and_lease_fence_are_denied() {
        let now = Utc::now();
        let registry = CapabilityRegistry::new(vec![definition()]).expect("registry");
        let mut candidate = request(now);
        candidate.lease_generation -= 1;
        candidate.action_sha256 = candidate.canonical_sha256().expect("digest");
        assert!(matches!(
            authorize(&authority(now), &candidate, &registry, None, None, now),
            Err(Error::NotAuthorized(_))
        ));
    }

    #[test]
    fn revoked_cancelled_or_expired_authority_is_denied() {
        let now = Utc::now();
        let registry = CapabilityRegistry::new(vec![definition()]).expect("registry");
        let mut inactive = authority(now);
        inactive.revoked = true;
        assert!(authorize(&inactive, &request(now), &registry, None, None, now).is_err());
        let mut stopped = authority(now);
        stopped.started = false;
        assert!(authorize(&stopped, &request(now), &registry, None, None, now).is_err());
        let later = now + Duration::hours(1);
        assert!(authorize(&authority(now), &request(now), &registry, None, None, later).is_err());
    }

    #[test]
    fn minimization_and_classification_cannot_be_escalated() {
        let now = Utc::now();
        let registry = CapabilityRegistry::new(vec![definition()]).expect("registry");
        let mut candidate = request(now);
        candidate.minimization_evidence_sha256 = digest('e');
        candidate.action_sha256 = candidate.canonical_sha256().expect("digest");
        assert!(authorize(&authority(now), &candidate, &registry, None, None, now).is_err());
        let mut classified = request(now);
        classified.classification = DataClassification::Restricted;
        classified.action_sha256 = classified.canonical_sha256().expect("digest");
        assert!(authorize(&authority(now), &classified, &registry, None, None, now).is_err());
    }

    #[test]
    fn traversal_absolute_windows_and_nul_paths_are_denied() {
        let now = Utc::now();
        let registry = CapabilityRegistry::new(vec![definition()]).expect("registry");
        for path in [
            "../secret",
            "/etc/passwd",
            "C:/secret",
            "a//b",
            "a/./b",
            "a\0b",
        ] {
            let mut candidate = request(now);
            let ToolIntent::File { relative_path, .. } = &mut candidate.intent else {
                panic!("file intent")
            };
            *relative_path = path.into();
            candidate.action_sha256 = candidate.canonical_sha256().expect("digest");
            assert!(
                authorize(&authority(now), &candidate, &registry, None, None, now).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn symlink_unsafe_and_delete_without_critical_policy_are_rejected_at_boot() {
        let mut unsafe_policy = definition();
        let ToolRoute::File {
            descriptor_relative_no_symlink,
            operations: _,
            ..
        } = &mut unsafe_policy.route
        else {
            panic!("file route")
        };
        *descriptor_relative_no_symlink = false;
        assert!(CapabilityRegistry::new(vec![unsafe_policy]).is_err());

        let mut delete = definition();
        let ToolRoute::File { operations, .. } = &mut delete.route else {
            panic!("file route")
        };
        operations.insert(FileOperation::Delete);
        assert!(CapabilityRegistry::new(vec![delete]).is_err());
    }

    #[test]
    fn egress_rejects_ips_redirects_proxies_and_unapproved_hosts() {
        for host in ["127.0.0.1", "metadata.google.internal", "evil.example"] {
            let mut route = definition();
            route.route = ToolRoute::Https {
                destination_id: "analyst-api".into(),
                host: host.into(),
                port: 443,
                methods: BTreeSet::from([HttpMethod::Post]),
                resource_ids: BTreeSet::from(["artifact-create".into()]),
                follow_redirects: false,
                inherit_proxy: false,
            };
            assert!(CapabilityRegistry::new(vec![route]).is_err(), "{host}");
        }
        let mut route = definition();
        route.route = ToolRoute::Https {
            destination_id: "analyst-api".into(),
            host: "analyst.snowmanai.org".into(),
            port: 443,
            methods: BTreeSet::from([HttpMethod::Post]),
            resource_ids: BTreeSet::from(["artifact-create".into()]),
            follow_redirects: true,
            inherit_proxy: false,
        };
        assert!(CapabilityRegistry::new(vec![route]).is_err());
    }

    #[test]
    fn arbitrary_or_credentialed_program_policy_is_rejected() {
        for env in [
            "OPENAI_API_KEY",
            "AWS_SESSION_TOKEN",
            "BUZZ_PRIVATE_KEY",
            "SAFE_TOKEN",
        ] {
            let mut route = definition();
            route.route = ToolRoute::ReviewedProgram {
                program_id: "report-renderer".into(),
                executable_sha256: digest('f'),
                input_contract_id: "report.v1".into(),
                sandbox_profile_id: "offline-renderer-v1".into(),
                direct_exec_only: true,
                clear_environment: true,
                environment_allowlist: BTreeSet::from([env.into()]),
                network_access: false,
            };
            assert!(CapabilityRegistry::new(vec![route]).is_err(), "{env}");
        }
    }

    #[test]
    fn safe_nonsecret_program_environment_can_be_registered() {
        let mut route = definition();
        route.route = ToolRoute::ReviewedProgram {
            program_id: "report-renderer".into(),
            executable_sha256: digest('f'),
            input_contract_id: "report.v1".into(),
            sandbox_profile_id: "offline-renderer-v1".into(),
            direct_exec_only: true,
            clear_environment: true,
            environment_allowlist: BTreeSet::from(["LANG".into(), "TZ".into()]),
            network_access: false,
        };
        assert!(CapabilityRegistry::new(vec![route]).is_ok());
    }

    #[test]
    fn high_impact_requires_exact_live_human_approval() {
        let now = Utc::now();
        let mut high = definition();
        high.impact = Impact::High;
        high.approval = ApprovalRequirement::Human;
        let registry = CapabilityRegistry::new(vec![high]).expect("registry");
        let request = request(now);
        assert_eq!(
            authorize(&authority(now), &request, &registry, None, None, now),
            Err(Error::NotAuthorized("human approval is required"))
        );
        let approval = Approval {
            approval_id: Uuid::new_v4(),
            tenant_id: request.tenant_id,
            workspace_id: request.workspace_id,
            job_id: request.job_id,
            task_id: request.task_id,
            generation: request.generation,
            action_sha256: request.action_sha256.clone(),
            approver_identity_id: Uuid::new_v4(),
            decision: ApprovalDecision::Approved,
            decided_at: now,
            expires_at: request.deadline_at,
        };
        assert!(authorize(
            &authority(now),
            &request,
            &registry,
            Some(&approval),
            None,
            now
        )
        .is_ok());
    }

    #[test]
    fn mismatched_expired_denied_and_revoked_approvals_fail_closed() {
        let now = Utc::now();
        let mut high = definition();
        high.impact = Impact::High;
        high.approval = ApprovalRequirement::Human;
        let registry = CapabilityRegistry::new(vec![high]).expect("registry");
        let request = request(now);
        let mut approval = Approval {
            approval_id: Uuid::new_v4(),
            tenant_id: request.tenant_id,
            workspace_id: request.workspace_id,
            job_id: request.job_id,
            task_id: request.task_id,
            generation: request.generation,
            action_sha256: request.action_sha256.clone(),
            approver_identity_id: Uuid::new_v4(),
            decision: ApprovalDecision::Approved,
            decided_at: now,
            expires_at: request.deadline_at,
        };
        for mode in 0..4 {
            let mut invalid = approval.clone();
            match mode {
                0 => invalid.action_sha256 = digest('1'),
                1 => invalid.expires_at = now,
                2 => invalid.decision = ApprovalDecision::Denied,
                _ => invalid.decision = ApprovalDecision::Revoked,
            }
            assert!(authorize(
                &authority(now),
                &request,
                &registry,
                Some(&invalid),
                None,
                now
            )
            .is_err());
        }
        approval.approver_identity_id = Uuid::nil();
        assert!(authorize(
            &authority(now),
            &request,
            &registry,
            Some(&approval),
            None,
            now
        )
        .is_err());
    }

    #[test]
    fn exact_replay_reconciles_without_redispatch_and_conflict_is_denied() {
        let now = Utc::now();
        let request = request(now);
        let prior = PriorAction {
            action_id: request.action_id,
            action_sha256: request.action_sha256.clone(),
            tenant_id: request.tenant_id,
            workspace_id: request.workspace_id,
            job_id: request.job_id,
            task_id: request.task_id,
            generation: request.generation,
            status: ActionStatus::Indeterminate,
            receipt_sha256: Some(digest('9')),
        };
        let registry = CapabilityRegistry::new(vec![definition()]).expect("registry");
        assert!(matches!(
            authorize(
                &authority(now),
                &request,
                &registry,
                None,
                Some(&prior),
                now
            ),
            Ok(Decision::Replay {
                status: ActionStatus::Indeterminate,
                ..
            })
        ));
        let mut conflict = prior;
        conflict.action_sha256 = digest('8');
        assert_eq!(
            authorize(
                &authority(now),
                &request,
                &registry,
                None,
                Some(&conflict),
                now
            ),
            Err(Error::ReplayConflict)
        );
    }

    #[test]
    fn only_linearized_state_transitions_are_allowed() {
        assert!(validate_transition(ActionStatus::Authorized, ActionStatus::Indeterminate).is_ok());
        assert!(validate_transition(ActionStatus::Authorized, ActionStatus::Cancelled).is_ok());
        assert!(validate_transition(ActionStatus::Indeterminate, ActionStatus::Succeeded).is_ok());
        assert!(validate_transition(ActionStatus::Indeterminate, ActionStatus::Failed).is_ok());
        assert!(validate_transition(ActionStatus::Cancelled, ActionStatus::Indeterminate).is_err());
        assert!(validate_transition(ActionStatus::Succeeded, ActionStatus::Indeterminate).is_err());
    }

    #[test]
    fn receipts_require_external_signature_checkpoint_and_exact_chain_shape() {
        let mut receipt = ActionReceipt {
            schema_version: RECEIPT_SCHEMA.into(),
            receipt_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            job_id: Uuid::new_v4(),
            task_id: Uuid::new_v4(),
            generation: 1,
            action_id: Uuid::new_v4(),
            sequence: 0,
            status: ActionStatus::Authorized,
            action_sha256: digest('a'),
            result_sha256: None,
            redaction_evidence_sha256: digest('b'),
            previous_receipt_sha256: None,
            signing_key_arn: "arn:aws:kms:us-west-2:625242091862:key/receipt-key-v1".into(),
            signature_sha256: digest('c'),
            external_checkpoint_sha256: digest('d'),
            occurred_at: Utc::now(),
        };
        assert!(receipt.canonical_sha256().is_ok());
        receipt.sequence = 1;
        assert!(receipt.validate().is_err());
        receipt.previous_receipt_sha256 = Some(digest('e'));
        receipt.status = ActionStatus::Succeeded;
        assert!(receipt.validate().is_err());
        receipt.result_sha256 = Some(digest('f'));
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn database_identifiers_are_not_injectable() {
        for valid in ["snowman_tool_broker", "snowman360", "_tool"] {
            assert!(valid_pg_identifier(valid), "{valid}");
        }
        for invalid in ["", "2tool", "Tool", "tool-role", "tool;drop role x"] {
            assert!(!valid_pg_identifier(invalid), "{invalid}");
        }
    }
}
