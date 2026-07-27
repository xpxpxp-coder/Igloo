#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Trusted Snowman coordinator for crash-fenced one-shot agent launches.
//!
//! The coordinator is the only component allowed to turn a governed workforce
//! lease into an ECS task. It never gives the task AWS credentials, a database
//! credential, a model-provider credential, or an arbitrary network target.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use aws_sdk_ecs::types::{
    AssignPublicIp, AwsVpcConfiguration, ContainerOverride, KeyValuePair, LaunchType,
    NetworkConfiguration, TaskOverride,
};
use aws_sdk_kms::{primitives::Blob, types::MacAlgorithmSpec};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snowman_agent_broker::{issue_job_in_transaction, IssueError, IssueJob};
use snowman_agent_contract::JobSnapshot;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Private authenticated HTTP service that owns coordinator activation.
pub mod service;

/// Coordinator contract version.
pub const COORDINATOR_SCHEMA: &str = "snowman.agent.coordinator.v1";
const TOKEN_DOMAIN: &[u8] = b"snowman.agent.job-token.v1\0";
const CLIENT_TOKEN_DOMAIN: &[u8] = b"snowman.agent.ecs-client-token.v1\0";
const MAX_LAUNCH_ATTEMPTS: i32 = 20;

/// Immutable executor image and container selected by a reviewed policy.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProfile {
    /// Stable policy identifier, such as `native-acp` or a reviewed adapter.
    pub runtime_id: String,
    /// Fully qualified, revision-pinned ECS task definition ARN.
    pub task_definition_arn: String,
    /// Exact container receiving the three purpose-bound job coordinates.
    pub container_name: String,
}

/// Exact private placement and reviewed runtime catalog.
#[derive(Clone, Debug)]
pub struct CoordinatorConfig {
    /// Fully qualified ECS cluster ARN.
    pub cluster_arn: String,
    /// Private subnet IDs only.
    pub private_subnet_ids: Vec<String>,
    /// Sole security group assigned to one-shot executors.
    pub executor_security_group_id: String,
    /// Runtime profiles keyed by the snapshot runtime ID.
    pub runtime_profiles: BTreeMap<String, RuntimeProfile>,
}

impl CoordinatorConfig {
    /// Fail closed unless every placement and runtime value is exact and pinned.
    pub fn validate(&self) -> Result<(), CoordinatorError> {
        if !valid_cluster_arn(&self.cluster_arn)
            || self.private_subnet_ids.is_empty()
            || self.private_subnet_ids.len() > 16
            || self.executor_security_group_id.len() < 4
            || !self.executor_security_group_id.starts_with("sg-")
            || !self
                .executor_security_group_id
                .bytes()
                .skip(3)
                .all(|byte| byte.is_ascii_hexdigit())
            || self.runtime_profiles.is_empty()
            || self.runtime_profiles.len() > 16
        {
            return Err(CoordinatorError::InvalidConfiguration);
        }
        let subnet_set: BTreeSet<_> = self.private_subnet_ids.iter().collect();
        if subnet_set.len() != self.private_subnet_ids.len()
            || self.private_subnet_ids.iter().any(|subnet| {
                !subnet.starts_with("subnet-")
                    || !subnet.bytes().skip(7).all(|byte| byte.is_ascii_hexdigit())
            })
        {
            return Err(CoordinatorError::InvalidConfiguration);
        }
        for (key, profile) in &self.runtime_profiles {
            if key != &profile.runtime_id
                || !valid_runtime_id(key)
                || !valid_task_definition_arn(&profile.task_definition_arn)
                || !valid_container_name(&profile.container_name)
                || !same_ecs_authority(&self.cluster_arn, &profile.task_definition_arn)
            {
                return Err(CoordinatorError::InvalidConfiguration);
            }
        }
        Ok(())
    }
}

/// Evidence from an already verified Snowman NIP-98 request.
///
/// Construction belongs to the private authenticated API layer. The event ID
/// is recorded before launch and cannot be replayed for another request body.
pub struct VerifiedLaunchRequest {
    /// Minimized, immutable job snapshot.
    pub snapshot: JobSnapshot,
    /// SHA-256 of the canonical authenticated request body.
    pub request_sha256: [u8; 32],
    /// Workforce-bound Nostr public key that signed the request.
    pub requester_pubkey: [u8; 32],
    /// Verified NIP-98 event identifier.
    pub auth_event_id: [u8; 32],
    /// Time at which the verifier accepted the event.
    pub auth_observed_at: DateTime<Utc>,
    /// Hard replay-evidence expiry.
    pub auth_expires_at: DateTime<Utc>,
}

/// Non-secret coordinates used for deterministic credential derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobCoordinates {
    /// Tenant UUID.
    pub tenant_id: Uuid,
    /// One-shot job UUID.
    pub job_id: Uuid,
    /// Governed workforce task UUID.
    pub task_id: Uuid,
    /// Fencing generation from the active lease.
    pub generation: u32,
    /// Hard job deadline.
    pub deadline_at: DateTime<Utc>,
}

impl JobCoordinates {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut value = Vec::with_capacity(16 * 3 + 12);
        value.extend_from_slice(self.tenant_id.as_bytes());
        value.extend_from_slice(self.job_id.as_bytes());
        value.extend_from_slice(self.task_id.as_bytes());
        value.extend_from_slice(&self.generation.to_be_bytes());
        value.extend_from_slice(&self.deadline_at.timestamp_micros().to_be_bytes());
        value
    }
}

/// Exact request passed to the ECS launch authority, excluding the secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchSpec {
    /// Durable launch evidence identifier.
    pub launch_id: Uuid,
    /// Job coordinates.
    pub coordinates: JobCoordinates,
    /// Exact ECS cluster.
    pub cluster_arn: String,
    /// Exact task-definition revision.
    pub task_definition_arn: String,
    /// Exact target container.
    pub container_name: String,
    /// Exact private subnet set.
    pub private_subnet_ids: Vec<String>,
    /// Sole executor security group.
    pub executor_security_group_id: String,
    /// Stable ECS idempotency token.
    pub client_token: String,
}

/// Durable result of a launch or idempotent replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchReceipt {
    /// Durable launch ID.
    pub launch_id: Uuid,
    /// Exact one-shot job ID.
    pub job_id: Uuid,
    /// ECS task ARN returned by the exact cluster.
    pub ecs_task_arn: String,
    /// Whether this call performed the successful ECS transition.
    pub launched: bool,
}

/// Minimal ECS lifecycle observation; no container diagnostics are retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskObservation {
    /// ECS lifecycle state such as `PROVISIONING`, `RUNNING`, or `STOPPED`.
    pub last_status: String,
}

/// Stable, non-sensitive coordinator failure classes.
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    /// Static placement or runtime configuration is not exact.
    #[error("agent coordinator configuration is invalid")]
    InvalidConfiguration,
    /// A verified launch envelope or snapshot violates the boundary.
    #[error("agent coordinator launch request is invalid")]
    InvalidRequest,
    /// The authenticated event was already used for different content.
    #[error("agent coordinator authentication evidence conflicts")]
    AuthenticationConflict,
    /// The task generation or launch already has different durable evidence.
    #[error("agent coordinator launch evidence conflicts")]
    Conflict,
    /// KMS could not derive the one-job credential.
    #[error("agent coordinator credential derivation failed")]
    TokenDerivation,
    /// The governed job could not be issued.
    #[error("agent coordinator job issuance failed")]
    Issue,
    /// Durable state could not be read or committed.
    #[error("agent coordinator database operation failed")]
    Database,
    /// ECS did not accept or return the exact one-task launch.
    #[error("agent coordinator ECS operation failed")]
    Ecs,
    /// Another coordinator currently owns the short launch claim.
    #[error("agent coordinator launch is already being reconciled")]
    Busy,
}

impl From<IssueError> for CoordinatorError {
    fn from(_: IssueError) -> Self {
        Self::Issue
    }
}

/// Derive a recoverable one-job secret without persisting it.
#[async_trait]
pub trait TokenDeriver: Send + Sync {
    /// Return the same secret for the same immutable job coordinates.
    async fn derive(
        &self,
        coordinates: &JobCoordinates,
    ) -> Result<Zeroizing<String>, CoordinatorError>;
}

/// AWS KMS HMAC-backed token derivation.
pub struct KmsTokenDeriver {
    client: aws_sdk_kms::Client,
    key_arn: String,
}

impl KmsTokenDeriver {
    /// Bind derivation to one exact HMAC KMS key ARN.
    pub fn new(client: aws_sdk_kms::Client, key_arn: String) -> Result<Self, CoordinatorError> {
        if !valid_hmac_key_arn(&key_arn) {
            return Err(CoordinatorError::InvalidConfiguration);
        }
        Ok(Self { client, key_arn })
    }
}

#[async_trait]
impl TokenDeriver for KmsTokenDeriver {
    async fn derive(
        &self,
        coordinates: &JobCoordinates,
    ) -> Result<Zeroizing<String>, CoordinatorError> {
        let mut message = Vec::with_capacity(TOKEN_DOMAIN.len() + 64);
        message.extend_from_slice(TOKEN_DOMAIN);
        message.extend_from_slice(&coordinates.canonical_bytes());
        let output = self
            .client
            .generate_mac()
            .key_id(&self.key_arn)
            .mac_algorithm(MacAlgorithmSpec::HmacSha256)
            .message(Blob::new(message))
            .send()
            .await
            .map_err(|_| CoordinatorError::TokenDerivation)?;
        let mac = output.mac().ok_or(CoordinatorError::TokenDerivation)?;
        if mac.as_ref().len() != 32 {
            return Err(CoordinatorError::TokenDerivation);
        }
        Ok(Zeroizing::new(format!(
            "sj1_{}",
            URL_SAFE_NO_PAD.encode(mac.as_ref())
        )))
    }
}

/// Narrow ECS authority used by production and deterministic tests.
#[async_trait]
pub trait EcsControl: Send + Sync {
    /// Start exactly one private task using only the three allowed overrides.
    async fn run_task(
        &self,
        spec: &LaunchSpec,
        job_token: &str,
    ) -> Result<String, CoordinatorError>;

    /// Observe only the lifecycle state of the exact task.
    async fn describe_task(
        &self,
        cluster_arn: &str,
        task_arn: &str,
    ) -> Result<TaskObservation, CoordinatorError>;

    /// Stop the exact task after cancellation, expiry, or revocation.
    async fn stop_task(
        &self,
        cluster_arn: &str,
        task_arn: &str,
        reason: &str,
    ) -> Result<(), CoordinatorError>;
}

/// Production AWS ECS implementation with no ambient launch options.
pub struct AwsEcsControl {
    client: aws_sdk_ecs::Client,
}

impl AwsEcsControl {
    /// Construct around the coordinator task's least-privilege AWS client.
    pub fn new(client: aws_sdk_ecs::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EcsControl for AwsEcsControl {
    async fn run_task(
        &self,
        spec: &LaunchSpec,
        job_token: &str,
    ) -> Result<String, CoordinatorError> {
        if !(32..=2048).contains(&job_token.len())
            || !job_token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(CoordinatorError::InvalidRequest);
        }
        let environment = [
            (
                "SNOWMAN_AGENT_TENANT_ID",
                spec.coordinates.tenant_id.to_string(),
            ),
            ("SNOWMAN_AGENT_JOB_ID", spec.coordinates.job_id.to_string()),
            ("SNOWMAN_AGENT_JOB_TOKEN", job_token.to_owned()),
        ]
        .into_iter()
        .map(|(name, value)| KeyValuePair::builder().name(name).value(value).build())
        .collect::<Vec<_>>();
        let container = ContainerOverride::builder()
            .name(&spec.container_name)
            .set_environment(Some(environment))
            .build();
        let overrides = TaskOverride::builder()
            .container_overrides(container)
            .build();
        let vpc = AwsVpcConfiguration::builder()
            .set_subnets(Some(spec.private_subnet_ids.clone()))
            .security_groups(&spec.executor_security_group_id)
            .assign_public_ip(AssignPublicIp::Disabled)
            .build()
            .map_err(|_| CoordinatorError::InvalidConfiguration)?;
        let network = NetworkConfiguration::builder()
            .awsvpc_configuration(vpc)
            .build();
        let output = self
            .client
            .run_task()
            .cluster(&spec.cluster_arn)
            .task_definition(&spec.task_definition_arn)
            .client_token(&spec.client_token)
            .launch_type(LaunchType::Fargate)
            .count(1)
            .enable_execute_command(false)
            .enable_ecs_managed_tags(true)
            .propagate_tags(aws_sdk_ecs::types::PropagateTags::TaskDefinition)
            .started_by(started_by(spec.launch_id))
            .group(format!("snowman-agent-{}", spec.coordinates.job_id))
            .network_configuration(network)
            .overrides(overrides)
            .send()
            .await
            .map_err(|_| CoordinatorError::Ecs)?;
        if !output.failures().is_empty() || output.tasks().len() != 1 {
            return Err(CoordinatorError::Ecs);
        }
        let task_arn = output.tasks()[0]
            .task_arn()
            .filter(|value| valid_task_arn_for_cluster(value, &spec.cluster_arn))
            .ok_or(CoordinatorError::Ecs)?;
        Ok(task_arn.to_owned())
    }

    async fn describe_task(
        &self,
        cluster_arn: &str,
        task_arn: &str,
    ) -> Result<TaskObservation, CoordinatorError> {
        if !valid_cluster_arn(cluster_arn) || !valid_task_arn_for_cluster(task_arn, cluster_arn) {
            return Err(CoordinatorError::InvalidRequest);
        }
        let output = self
            .client
            .describe_tasks()
            .cluster(cluster_arn)
            .tasks(task_arn)
            .send()
            .await
            .map_err(|_| CoordinatorError::Ecs)?;
        if !output.failures().is_empty() || output.tasks().len() != 1 {
            return Err(CoordinatorError::Ecs);
        }
        let task = &output.tasks()[0];
        if task.task_arn() != Some(task_arn) {
            return Err(CoordinatorError::Ecs);
        }
        let last_status = task
            .last_status()
            .filter(|value| valid_ecs_status(value))
            .ok_or(CoordinatorError::Ecs)?;
        Ok(TaskObservation {
            last_status: last_status.to_owned(),
        })
    }

    async fn stop_task(
        &self,
        cluster_arn: &str,
        task_arn: &str,
        reason: &str,
    ) -> Result<(), CoordinatorError> {
        if !valid_cluster_arn(cluster_arn)
            || !valid_task_arn_for_cluster(task_arn, cluster_arn)
            || !valid_stop_reason(reason)
        {
            return Err(CoordinatorError::InvalidRequest);
        }
        self.client
            .stop_task()
            .cluster(cluster_arn)
            .task(task_arn)
            .reason(reason)
            .send()
            .await
            .map_err(|_| CoordinatorError::Ecs)?;
        Ok(())
    }
}

/// Trusted launch orchestrator over an exact database, KMS derivation, and ECS authority.
pub struct Coordinator<D, E> {
    pool: PgPool,
    config: CoordinatorConfig,
    token_deriver: D,
    ecs: E,
}

impl<D: TokenDeriver, E: EcsControl> Coordinator<D, E> {
    /// Validate static policy before accepting any launch request.
    pub fn new(
        pool: PgPool,
        config: CoordinatorConfig,
        token_deriver: D,
        ecs: E,
    ) -> Result<Self, CoordinatorError> {
        config.validate()?;
        Ok(Self {
            pool,
            config,
            token_deriver,
            ecs,
        })
    }

    /// Atomically issue a job and its launch record, then idempotently start ECS.
    pub async fn submit(
        &self,
        request: VerifiedLaunchRequest,
    ) -> Result<LaunchReceipt, CoordinatorError> {
        self.validate_request(&request)?;
        let tenant_id = Uuid::parse_str(&request.snapshot.tenant_id)
            .map_err(|_| CoordinatorError::InvalidRequest)?;
        let profile = self
            .config
            .runtime_profiles
            .get(&request.snapshot.runtime_id)
            .ok_or(CoordinatorError::InvalidRequest)?;
        let coordinates = JobCoordinates {
            tenant_id,
            job_id: request.snapshot.job_id,
            task_id: request.snapshot.task_id,
            generation: request.snapshot.generation,
            deadline_at: request.snapshot.deadline_at,
        };
        let spec = build_launch_spec(&self.config, profile, coordinates);
        let token = self.token_deriver.derive(&spec.coordinates).await?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| CoordinatorError::Database)?;
        authorize_requester(&mut transaction, tenant_id, &request).await?;
        record_auth_event(&mut transaction, tenant_id, &request).await?;
        issue_job_in_transaction(
            &mut transaction,
            IssueJob {
                snapshot: request.snapshot.clone(),
                job_token: token.to_string(),
            },
        )
        .await?;
        persist_launch(&mut transaction, &spec, &request).await?;
        transaction
            .commit()
            .await
            .map_err(|_| CoordinatorError::Database)?;
        self.launch(spec, token).await
    }

    /// Retry due pending launches using the same KMS-derived job token and ECS
    /// client token. A crash after `RunTask` therefore cannot create a second
    /// task with different authority.
    pub async fn reconcile_due_launches(&self, limit: u32) -> Result<usize, CoordinatorError> {
        if !(1..=100).contains(&limit) {
            return Err(CoordinatorError::InvalidRequest);
        }
        let rows = sqlx::query(
            "SELECT l.community_id,l.job_id,l.task_id,l.generation,l.launch_attempt_count,\
             l.runtime_profile,l.ecs_cluster_arn,l.task_definition_arn,l.client_token_sha256,\
             j.deadline_at FROM snowman_agent_launches l JOIN snowman_agent_jobs j \
             ON j.community_id=l.community_id AND j.job_id=l.job_id \
             WHERE l.status IN ('pending','launching') AND l.reconcile_after<=NOW() \
             AND (l.claim_id IS NULL OR l.claim_expires_at<NOW()) \
             ORDER BY l.reconcile_after,l.community_id,l.launch_id LIMIT $1",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|_| CoordinatorError::Database)?;
        let mut reconciled = 0;
        for row in rows {
            let tenant_id: Uuid = row
                .try_get("community_id")
                .map_err(|_| CoordinatorError::Database)?;
            let job_id: Uuid = row
                .try_get("job_id")
                .map_err(|_| CoordinatorError::Database)?;
            let task_id: Uuid = row
                .try_get("task_id")
                .map_err(|_| CoordinatorError::Database)?;
            let generation: i64 = row
                .try_get("generation")
                .map_err(|_| CoordinatorError::Database)?;
            let attempts: i32 = row
                .try_get("launch_attempt_count")
                .map_err(|_| CoordinatorError::Database)?;
            let runtime_id: String = row
                .try_get("runtime_profile")
                .map_err(|_| CoordinatorError::Database)?;
            let deadline_at: DateTime<Utc> = row
                .try_get("deadline_at")
                .map_err(|_| CoordinatorError::Database)?;
            let generation = u32::try_from(generation).map_err(|_| CoordinatorError::Conflict)?;
            let profile = self
                .config
                .runtime_profiles
                .get(&runtime_id)
                .ok_or(CoordinatorError::Conflict)?;
            let coordinates = JobCoordinates {
                tenant_id,
                job_id,
                task_id,
                generation,
                deadline_at,
            };
            let spec = build_launch_spec(&self.config, profile, coordinates);
            verify_stored_launch_policy(&row, &spec)?;
            if attempts >= MAX_LAUNCH_ATTEMPTS {
                exhaust_launch(&self.pool, &spec).await?;
                reconciled += 1;
                continue;
            }
            let token = self.token_deriver.derive(&spec.coordinates).await?;
            if deadline_at <= Utc::now() + Duration::seconds(30) {
                expire_unobserved_launch(&self.pool, &self.ecs, &spec, token.as_str()).await?;
                reconciled += 1;
                continue;
            }
            match self.launch(spec, token).await {
                Ok(_) => reconciled += 1,
                Err(CoordinatorError::Busy) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(reconciled)
    }

    /// Recheck active job/lease authority, stop revoked work, and synchronize
    /// terminal ECS lifecycle state with the durable launch evidence.
    pub async fn reconcile_running_tasks(&self, limit: u32) -> Result<usize, CoordinatorError> {
        if !(1..=100).contains(&limit) {
            return Err(CoordinatorError::InvalidRequest);
        }
        let rows = sqlx::query(
            "SELECT l.community_id,l.job_id,l.ecs_cluster_arn,l.ecs_task_arn,l.status launch_status,\
             j.status job_status,j.deadline_at,j.token_revoked_at,t.status task_status,\
             r.status request_status,l.generation,lease.generation lease_generation,\
             lease.expires_at lease_expires_at FROM snowman_agent_launches l \
             JOIN snowman_agent_jobs j ON j.community_id=l.community_id AND j.job_id=l.job_id \
             JOIN snowman_work_tasks t ON t.community_id=l.community_id AND t.task_id=l.task_id \
             JOIN snowman_work_requests r ON r.community_id=l.community_id AND r.request_id=l.request_id \
             LEFT JOIN snowman_task_leases lease \
               ON lease.community_id=l.community_id AND lease.task_id=l.task_id \
             WHERE l.status IN ('running','stopping') AND l.reconcile_after<=NOW() \
             ORDER BY l.reconcile_after,l.community_id,l.launch_id LIMIT $1",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|_| CoordinatorError::Database)?;
        let mut reconciled = 0;
        for row in rows {
            let tenant_id: Uuid = row
                .try_get("community_id")
                .map_err(|_| CoordinatorError::Database)?;
            let job_id: Uuid = row
                .try_get("job_id")
                .map_err(|_| CoordinatorError::Database)?;
            let cluster_arn: String = row
                .try_get("ecs_cluster_arn")
                .map_err(|_| CoordinatorError::Database)?;
            let task_arn: String = row
                .try_get("ecs_task_arn")
                .map_err(|_| CoordinatorError::Database)?;
            if !valid_task_arn_for_cluster(&task_arn, &cluster_arn) {
                return Err(CoordinatorError::Conflict);
            }
            let launch_status: String = row
                .try_get("launch_status")
                .map_err(|_| CoordinatorError::Database)?;
            let job_status: String = row
                .try_get("job_status")
                .map_err(|_| CoordinatorError::Database)?;
            let task_status: String = row
                .try_get("task_status")
                .map_err(|_| CoordinatorError::Database)?;
            let request_status: String = row
                .try_get("request_status")
                .map_err(|_| CoordinatorError::Database)?;
            let deadline_at: DateTime<Utc> = row
                .try_get("deadline_at")
                .map_err(|_| CoordinatorError::Database)?;
            let token_revoked_at: Option<DateTime<Utc>> = row
                .try_get("token_revoked_at")
                .map_err(|_| CoordinatorError::Database)?;
            let generation: i64 = row
                .try_get("generation")
                .map_err(|_| CoordinatorError::Database)?;
            let lease_generation: Option<i64> = row
                .try_get("lease_generation")
                .map_err(|_| CoordinatorError::Database)?;
            let lease_expires_at: Option<DateTime<Utc>> = row
                .try_get("lease_expires_at")
                .map_err(|_| CoordinatorError::Database)?;
            let deadline_expired = deadline_at <= Utc::now();
            let authority_revoked = launch_status == "stopping"
                || token_revoked_at.is_some()
                || !matches!(job_status.as_str(), "issued" | "started")
                || !matches!(task_status.as_str(), "leased" | "running")
                || !matches!(request_status.as_str(), "running" | "reviewing")
                || lease_generation != Some(generation)
                || lease_expires_at.is_none_or(|expiry| expiry <= Utc::now());
            if deadline_expired || authority_revoked {
                stop_revoked_task(
                    &self.pool,
                    &self.ecs,
                    tenant_id,
                    job_id,
                    &cluster_arn,
                    &task_arn,
                    deadline_expired,
                )
                .await?;
                reconciled += 1;
                continue;
            }
            let observation = self.ecs.describe_task(&cluster_arn, &task_arn).await?;
            if observation.last_status == "STOPPED" {
                synchronize_stopped_task(&self.pool, tenant_id, job_id, &job_status).await?;
            } else {
                sqlx::query(
                    "UPDATE snowman_agent_launches SET last_observed_at=NOW(),\
                     reconcile_after=NOW()+INTERVAL '30 seconds',updated_at=NOW() \
                     WHERE community_id=$1 AND job_id=$2 AND status='running'",
                )
                .bind(tenant_id)
                .bind(job_id)
                .execute(&self.pool)
                .await
                .map_err(|_| CoordinatorError::Database)?;
            }
            reconciled += 1;
        }
        Ok(reconciled)
    }

    /// Revoke one active job and stop its exact recorded ECS task. The caller
    /// must already have passed the private authorization/approval layer.
    pub async fn cancel_job(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        reason: &str,
    ) -> Result<bool, CoordinatorError> {
        if tenant_id.is_nil() || job_id.is_nil() || !valid_failure_code(reason) {
            return Err(CoordinatorError::InvalidRequest);
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| CoordinatorError::Database)?;
        let row = sqlx::query(
            "SELECT ecs_cluster_arn,ecs_task_arn,status FROM snowman_agent_launches \
             WHERE community_id=$1 AND job_id=$2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| CoordinatorError::Database)?;
        let Some(row) = row else {
            transaction
                .rollback()
                .await
                .map_err(|_| CoordinatorError::Database)?;
            return Ok(false);
        };
        let cluster_arn: String = row
            .try_get("ecs_cluster_arn")
            .map_err(|_| CoordinatorError::Database)?;
        let task_arn: Option<String> = row
            .try_get("ecs_task_arn")
            .map_err(|_| CoordinatorError::Database)?;
        let status: String = row
            .try_get("status")
            .map_err(|_| CoordinatorError::Database)?;
        if matches!(
            status.as_str(),
            "cancelled" | "expired" | "succeeded" | "failed" | "stopped" | "launch_failed"
        ) {
            transaction
                .rollback()
                .await
                .map_err(|_| CoordinatorError::Database)?;
            return Ok(false);
        }
        sqlx::query(
            "UPDATE snowman_agent_jobs SET status='cancelled',token_revoked_at=NOW(),\
             updated_at=NOW() WHERE community_id=$1 AND job_id=$2 \
             AND status IN ('issued','started')",
        )
        .bind(tenant_id)
        .bind(job_id)
        .execute(&mut *transaction)
        .await
        .map_err(|_| CoordinatorError::Database)?;
        sqlx::query(
            "UPDATE snowman_agent_launches SET status=$3,stop_requested_at=NOW(),\
             failure_code=$4,claim_id=NULL,claim_expires_at=NULL,reconcile_after=NOW(),\
             updated_at=NOW() WHERE community_id=$1 AND job_id=$2",
        )
        .bind(tenant_id)
        .bind(job_id)
        .bind(if task_arn.is_some() {
            "stopping"
        } else {
            "cancelled"
        })
        .bind(reason)
        .execute(&mut *transaction)
        .await
        .map_err(|_| CoordinatorError::Database)?;
        transaction
            .commit()
            .await
            .map_err(|_| CoordinatorError::Database)?;
        if let Some(task_arn) = task_arn {
            self.ecs
                .stop_task(&cluster_arn, &task_arn, "Snowman governed cancellation")
                .await?;
            sqlx::query(
                "UPDATE snowman_agent_launches SET status='cancelled',stopped_at=NOW(),\
                 last_observed_at=NOW(),updated_at=NOW() \
                 WHERE community_id=$1 AND job_id=$2 AND status='stopping'",
            )
            .bind(tenant_id)
            .bind(job_id)
            .execute(&self.pool)
            .await
            .map_err(|_| CoordinatorError::Database)?;
        }
        Ok(true)
    }

    fn validate_request(&self, request: &VerifiedLaunchRequest) -> Result<(), CoordinatorError> {
        let now = Utc::now();
        if request.snapshot.job_id.is_nil()
            || request.auth_event_id == [0; 32]
            || request.request_sha256 == [0; 32]
            || request.requester_pubkey == [0; 32]
            || request.auth_observed_at > now + Duration::seconds(30)
            || request.auth_observed_at < now - Duration::minutes(5)
            || request.auth_expires_at <= now
            || request.auth_expires_at > request.auth_observed_at + Duration::minutes(10)
            || !self
                .config
                .runtime_profiles
                .contains_key(&request.snapshot.runtime_id)
        {
            return Err(CoordinatorError::InvalidRequest);
        }
        Ok(())
    }

    async fn launch(
        &self,
        spec: LaunchSpec,
        token: Zeroizing<String>,
    ) -> Result<LaunchReceipt, CoordinatorError> {
        let claim_id = Uuid::new_v4();
        let claimed = sqlx::query(
            "UPDATE snowman_agent_launches SET status='launching',claim_id=$3,\
             claim_expires_at=NOW()+INTERVAL '2 minutes',launch_attempt_count=launch_attempt_count+1,\
             updated_at=NOW() WHERE community_id=$1 AND job_id=$2 \
             AND status IN ('pending','launching') \
             AND (claim_id IS NULL OR claim_expires_at<NOW()) \
             AND launch_attempt_count<$4 RETURNING launch_id",
        )
        .bind(spec.coordinates.tenant_id)
        .bind(spec.coordinates.job_id)
        .bind(claim_id)
        .bind(MAX_LAUNCH_ATTEMPTS)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| CoordinatorError::Database)?;
        if claimed.is_none() {
            return existing_launch_receipt(&self.pool, &spec).await;
        }
        let task_arn = match self.ecs.run_task(&spec, token.as_str()).await {
            Ok(value) => value,
            Err(error) => {
                release_launch_claim(&self.pool, &spec, claim_id).await?;
                return Err(error);
            }
        };
        let updated = sqlx::query(
            "UPDATE snowman_agent_launches SET status='running',ecs_task_arn=$4,\
             claim_id=NULL,claim_expires_at=NULL,last_observed_at=NOW(),\
             reconcile_after=NOW()+INTERVAL '30 seconds',updated_at=NOW() \
             WHERE community_id=$1 AND job_id=$2 AND claim_id=$3 AND status='launching'",
        )
        .bind(spec.coordinates.tenant_id)
        .bind(spec.coordinates.job_id)
        .bind(claim_id)
        .bind(&task_arn)
        .execute(&self.pool)
        .await
        .map_err(|_| CoordinatorError::Database)?;
        if updated.rows_affected() != 1 {
            return Err(CoordinatorError::Database);
        }
        Ok(LaunchReceipt {
            launch_id: spec.launch_id,
            job_id: spec.coordinates.job_id,
            ecs_task_arn: task_arn,
            launched: true,
        })
    }
}

async fn authorize_requester(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    request: &VerifiedLaunchRequest,
) -> Result<(), CoordinatorError> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM snowman_work_tasks t \
         JOIN snowman_workforce_identities i \
           ON i.community_id=t.community_id AND i.identity_id=t.service_identity_id \
         JOIN snowman_workforce_key_bindings k \
           ON k.community_id=i.community_id AND k.identity_id=i.identity_id \
         WHERE t.community_id=$1 AND t.request_id=$2 AND t.task_id=$3 \
           AND k.pubkey=$4 AND k.binding_type='service_runtime' \
           AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>NOW()) \
           AND i.identity_type='service' AND i.status='active' \
           AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at>NOW()))",
    )
    .bind(tenant_id)
    .bind(request.snapshot.request_id)
    .bind(request.snapshot.task_id)
    .bind(request.requester_pubkey.as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    if !authorized {
        return Err(CoordinatorError::InvalidRequest);
    }
    Ok(())
}

async fn record_auth_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    request: &VerifiedLaunchRequest,
) -> Result<(), CoordinatorError> {
    let inserted = sqlx::query(
        "INSERT INTO snowman_agent_coordinator_auth_events \
         (community_id,auth_event_id,request_sha256,requester_pubkey,observed_at,expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(request.auth_event_id.as_slice())
    .bind(request.request_sha256.as_slice())
    .bind(request.requester_pubkey.as_slice())
    .bind(request.auth_observed_at)
    .bind(request.auth_expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    if inserted.rows_affected() != 1 {
        // A retry must carry a freshly signed NIP-98 event. Accepting the same
        // event twice would contradict the recorded authentication freshness.
        return Err(CoordinatorError::AuthenticationConflict);
    }
    let row = sqlx::query(
        "SELECT request_sha256,requester_pubkey FROM snowman_agent_coordinator_auth_events \
         WHERE community_id=$1 AND auth_event_id=$2",
    )
    .bind(tenant_id)
    .bind(request.auth_event_id.as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    let digest: Vec<u8> = row
        .try_get("request_sha256")
        .map_err(|_| CoordinatorError::Database)?;
    let pubkey: Vec<u8> = row
        .try_get("requester_pubkey")
        .map_err(|_| CoordinatorError::Database)?;
    if digest != request.request_sha256 || pubkey != request.requester_pubkey {
        return Err(CoordinatorError::AuthenticationConflict);
    }
    Ok(())
}

async fn persist_launch(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    spec: &LaunchSpec,
    request: &VerifiedLaunchRequest,
) -> Result<(), CoordinatorError> {
    let client_digest: [u8; 32] = Sha256::digest(spec.client_token.as_bytes()).into();
    sqlx::query(
        "INSERT INTO snowman_agent_launches \
         (community_id,launch_id,job_id,request_id,task_id,generation,runtime_profile,\
          ecs_cluster_arn,task_definition_arn,client_token_sha256,requester_pubkey,\
          auth_event_id,status,reconcile_after) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',NOW()) \
         ON CONFLICT DO NOTHING",
    )
    .bind(spec.coordinates.tenant_id)
    .bind(spec.launch_id)
    .bind(spec.coordinates.job_id)
    .bind(request.snapshot.request_id)
    .bind(spec.coordinates.task_id)
    .bind(i64::from(spec.coordinates.generation))
    .bind(&request.snapshot.runtime_id)
    .bind(&spec.cluster_arn)
    .bind(&spec.task_definition_arn)
    .bind(client_digest.as_slice())
    .bind(request.requester_pubkey.as_slice())
    .bind(request.auth_event_id.as_slice())
    .execute(&mut **transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    let row = sqlx::query(
        "SELECT launch_id,task_id,generation,runtime_profile,ecs_cluster_arn,\
         task_definition_arn,client_token_sha256,requester_pubkey \
         FROM snowman_agent_launches WHERE community_id=$1 AND job_id=$2",
    )
    .bind(spec.coordinates.tenant_id)
    .bind(spec.coordinates.job_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?
    .ok_or(CoordinatorError::Conflict)?;
    let matches = row.try_get::<Uuid, _>("launch_id").ok() == Some(spec.launch_id)
        && row.try_get::<Uuid, _>("task_id").ok() == Some(spec.coordinates.task_id)
        && row.try_get::<i64, _>("generation").ok() == Some(i64::from(spec.coordinates.generation))
        && row.try_get::<String, _>("runtime_profile").ok().as_deref()
            == Some(request.snapshot.runtime_id.as_str())
        && row.try_get::<String, _>("ecs_cluster_arn").ok().as_deref()
            == Some(spec.cluster_arn.as_str())
        && row
            .try_get::<String, _>("task_definition_arn")
            .ok()
            .as_deref()
            == Some(spec.task_definition_arn.as_str())
        && row
            .try_get::<Vec<u8>, _>("client_token_sha256")
            .ok()
            .as_deref()
            == Some(client_digest.as_slice())
        && row
            .try_get::<Vec<u8>, _>("requester_pubkey")
            .ok()
            .as_deref()
            == Some(request.requester_pubkey.as_slice());
    if !matches {
        return Err(CoordinatorError::Conflict);
    }
    Ok(())
}

fn verify_stored_launch_policy(
    row: &sqlx::postgres::PgRow,
    spec: &LaunchSpec,
) -> Result<(), CoordinatorError> {
    let client_digest: [u8; 32] = Sha256::digest(spec.client_token.as_bytes()).into();
    let cluster: String = row
        .try_get("ecs_cluster_arn")
        .map_err(|_| CoordinatorError::Database)?;
    let task_definition: String = row
        .try_get("task_definition_arn")
        .map_err(|_| CoordinatorError::Database)?;
    let stored_digest: Vec<u8> = row
        .try_get("client_token_sha256")
        .map_err(|_| CoordinatorError::Database)?;
    if cluster != spec.cluster_arn
        || task_definition != spec.task_definition_arn
        || stored_digest != client_digest
    {
        return Err(CoordinatorError::Conflict);
    }
    Ok(())
}

async fn exhaust_launch(pool: &PgPool, spec: &LaunchSpec) -> Result<(), CoordinatorError> {
    let mut transaction = pool.begin().await.map_err(|_| CoordinatorError::Database)?;
    sqlx::query(
        "UPDATE snowman_agent_jobs SET status='failed',token_revoked_at=NOW(),updated_at=NOW() \
         WHERE community_id=$1 AND job_id=$2 AND status IN ('issued','started')",
    )
    .bind(spec.coordinates.tenant_id)
    .bind(spec.coordinates.job_id)
    .execute(&mut *transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    sqlx::query(
        "UPDATE snowman_agent_launches SET status='launch_failed',failure_code='attempts_exhausted',\
         claim_id=NULL,claim_expires_at=NULL,last_observed_at=NOW(),updated_at=NOW() \
         WHERE community_id=$1 AND job_id=$2 AND status IN ('pending','launching') \
         AND launch_attempt_count>=$3",
    )
    .bind(spec.coordinates.tenant_id)
    .bind(spec.coordinates.job_id)
    .bind(MAX_LAUNCH_ATTEMPTS)
    .execute(&mut *transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    transaction
        .commit()
        .await
        .map_err(|_| CoordinatorError::Database)?;
    Ok(())
}

async fn expire_unobserved_launch<E: EcsControl>(
    pool: &PgPool,
    ecs: &E,
    spec: &LaunchSpec,
    token: &str,
) -> Result<(), CoordinatorError> {
    sqlx::query(
        "UPDATE snowman_agent_jobs SET status='expired',token_revoked_at=NOW(),updated_at=NOW() \
         WHERE community_id=$1 AND job_id=$2 AND status IN ('issued','started')",
    )
    .bind(spec.coordinates.tenant_id)
    .bind(spec.coordinates.job_id)
    .execute(pool)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    // Replaying the exact idempotent RunTask call is the only reliable way to
    // recover a task ARN after a crash between ECS acceptance and DB commit.
    // Revocation commits first, so a newly created task cannot fetch its
    // snapshot during the brief interval before StopTask completes.
    let task_arn = ecs.run_task(spec, token).await?;
    let mut transaction = pool.begin().await.map_err(|_| CoordinatorError::Database)?;
    sqlx::query(
        "UPDATE snowman_agent_launches SET status='stopping',ecs_task_arn=$3,\
         stop_requested_at=NOW(),failure_code='deadline_expired',claim_id=NULL,\
         claim_expires_at=NULL,last_observed_at=NOW(),updated_at=NOW() \
         WHERE community_id=$1 AND job_id=$2 AND status IN ('pending','launching')",
    )
    .bind(spec.coordinates.tenant_id)
    .bind(spec.coordinates.job_id)
    .bind(&task_arn)
    .execute(&mut *transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    transaction
        .commit()
        .await
        .map_err(|_| CoordinatorError::Database)?;
    ecs.stop_task(&spec.cluster_arn, &task_arn, "Snowman job deadline expired")
        .await?;
    sqlx::query(
        "UPDATE snowman_agent_launches SET status='expired',stopped_at=NOW(),updated_at=NOW() \
         WHERE community_id=$1 AND job_id=$2 AND status='stopping'",
    )
    .bind(spec.coordinates.tenant_id)
    .bind(spec.coordinates.job_id)
    .execute(pool)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    Ok(())
}

async fn stop_revoked_task<E: EcsControl>(
    pool: &PgPool,
    ecs: &E,
    tenant_id: Uuid,
    job_id: Uuid,
    cluster_arn: &str,
    task_arn: &str,
    deadline_expired: bool,
) -> Result<(), CoordinatorError> {
    let mut transaction = pool.begin().await.map_err(|_| CoordinatorError::Database)?;
    sqlx::query(
        "UPDATE snowman_agent_jobs SET status=$3,token_revoked_at=COALESCE(token_revoked_at,NOW()),\
         updated_at=NOW() WHERE community_id=$1 AND job_id=$2 AND status IN ('issued','started')",
    )
    .bind(tenant_id)
    .bind(job_id)
    .bind(if deadline_expired { "expired" } else { "cancelled" })
    .execute(&mut *transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    sqlx::query(
        "UPDATE snowman_agent_launches SET status='stopping',stop_requested_at=COALESCE(stop_requested_at,NOW()),\
         failure_code=$3,reconcile_after=NOW(),updated_at=NOW() \
         WHERE community_id=$1 AND job_id=$2 AND status IN ('running','stopping')",
    )
    .bind(tenant_id)
    .bind(job_id)
    .bind(if deadline_expired {
        "deadline_expired"
    } else {
        "authority_revoked"
    })
    .execute(&mut *transaction)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    transaction
        .commit()
        .await
        .map_err(|_| CoordinatorError::Database)?;
    ecs.stop_task(
        cluster_arn,
        task_arn,
        if deadline_expired {
            "Snowman job deadline expired"
        } else {
            "Snowman job authority revoked"
        },
    )
    .await?;
    let job_status: String = sqlx::query_scalar(
        "SELECT status FROM snowman_agent_jobs WHERE community_id=$1 AND job_id=$2",
    )
    .bind(tenant_id)
    .bind(job_id)
    .fetch_one(pool)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    synchronize_stopped_task(pool, tenant_id, job_id, &job_status).await
}

async fn synchronize_stopped_task(
    pool: &PgPool,
    tenant_id: Uuid,
    job_id: Uuid,
    observed_job_status: &str,
) -> Result<(), CoordinatorError> {
    let launch_status = match observed_job_status {
        "succeeded" => "succeeded",
        "failed" => "failed",
        "cancelled" => "cancelled",
        "expired" => "expired",
        _ => {
            sqlx::query(
                "UPDATE snowman_agent_jobs SET status='failed',token_revoked_at=COALESCE(token_revoked_at,NOW()),\
                 updated_at=NOW() WHERE community_id=$1 AND job_id=$2 AND status IN ('issued','started')",
            )
            .bind(tenant_id)
            .bind(job_id)
            .execute(pool)
            .await
            .map_err(|_| CoordinatorError::Database)?;
            "failed"
        }
    };
    let broker_terminal = matches!(observed_job_status, "succeeded" | "failed");
    sqlx::query(
        "UPDATE snowman_agent_launches SET status=$3,stopped_at=COALESCE(stopped_at,NOW()),\
         last_observed_at=NOW(),failure_code=CASE WHEN $4 THEN NULL \
         WHEN $3='failed' AND failure_code IS NULL THEN 'unexpected_task_stop' \
         ELSE failure_code END,updated_at=NOW() \
         WHERE community_id=$1 AND job_id=$2 AND status IN ('running','stopping')",
    )
    .bind(tenant_id)
    .bind(job_id)
    .bind(launch_status)
    .bind(broker_terminal)
    .execute(pool)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    Ok(())
}

async fn release_launch_claim(
    pool: &PgPool,
    spec: &LaunchSpec,
    claim_id: Uuid,
) -> Result<(), CoordinatorError> {
    sqlx::query(
        "UPDATE snowman_agent_launches SET claim_id=NULL,claim_expires_at=NULL,\
         failure_code='ecs_launch_error',reconcile_after=NOW()+INTERVAL '30 seconds',\
         updated_at=NOW() WHERE community_id=$1 AND job_id=$2 AND claim_id=$3",
    )
    .bind(spec.coordinates.tenant_id)
    .bind(spec.coordinates.job_id)
    .bind(claim_id)
    .execute(pool)
    .await
    .map_err(|_| CoordinatorError::Database)?;
    Ok(())
}

async fn existing_launch_receipt(
    pool: &PgPool,
    spec: &LaunchSpec,
) -> Result<LaunchReceipt, CoordinatorError> {
    let row = sqlx::query(
        "SELECT launch_id,status,ecs_task_arn FROM snowman_agent_launches \
         WHERE community_id=$1 AND job_id=$2",
    )
    .bind(spec.coordinates.tenant_id)
    .bind(spec.coordinates.job_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| CoordinatorError::Database)?
    .ok_or(CoordinatorError::Conflict)?;
    let launch_id: Uuid = row
        .try_get("launch_id")
        .map_err(|_| CoordinatorError::Database)?;
    let status: String = row
        .try_get("status")
        .map_err(|_| CoordinatorError::Database)?;
    let task_arn: Option<String> = row
        .try_get("ecs_task_arn")
        .map_err(|_| CoordinatorError::Database)?;
    if launch_id == spec.launch_id && status == "running" {
        let ecs_task_arn = task_arn
            .filter(|value| valid_task_arn_for_cluster(value, &spec.cluster_arn))
            .ok_or(CoordinatorError::Conflict)?;
        return Ok(LaunchReceipt {
            launch_id,
            job_id: spec.coordinates.job_id,
            ecs_task_arn,
            launched: false,
        });
    }
    Err(CoordinatorError::Busy)
}

fn build_launch_spec(
    config: &CoordinatorConfig,
    profile: &RuntimeProfile,
    coordinates: JobCoordinates,
) -> LaunchSpec {
    let mut digest = Sha256::new();
    digest.update(CLIENT_TOKEN_DOMAIN);
    digest.update(coordinates.canonical_bytes());
    digest.update(config.cluster_arn.as_bytes());
    digest.update([0]);
    digest.update(profile.task_definition_arn.as_bytes());
    digest.update([0]);
    digest.update(profile.container_name.as_bytes());
    for subnet in &config.private_subnet_ids {
        digest.update([0]);
        digest.update(subnet.as_bytes());
    }
    digest.update([0]);
    digest.update(config.executor_security_group_id.as_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let launch_id = uuid_from_digest(bytes);
    LaunchSpec {
        launch_id,
        coordinates,
        cluster_arn: config.cluster_arn.clone(),
        task_definition_arn: profile.task_definition_arn.clone(),
        container_name: profile.container_name.clone(),
        private_subnet_ids: config.private_subnet_ids.clone(),
        executor_security_group_id: config.executor_security_group_id.clone(),
        client_token: hex::encode(bytes),
    }
}

fn uuid_from_digest(mut digest: [u8; 32]) -> Uuid {
    digest[6] = (digest[6] & 0x0f) | 0x40;
    digest[8] = (digest[8] & 0x3f) | 0x80;
    Uuid::from_slice(&digest[..16]).expect("fixed UUID digest length")
}

fn started_by(launch_id: Uuid) -> String {
    let simple = launch_id.simple().to_string();
    format!("snowman-{}", &simple[..28])
}

fn valid_runtime_id(value: &str) -> bool {
    (3..=32).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || (index > 0 && byte.is_ascii_digit())
                || (index > 0 && byte == b'-')
        })
}

fn valid_container_name(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_cluster_arn(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 6
        && parts[0] == "arn"
        && parts[1].starts_with("aws")
        && parts[2] == "ecs"
        && !parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
        && parts[5].starts_with("cluster/")
        && parts[5].len() > 8
}

fn valid_task_definition_arn(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 7
        && parts[0] == "arn"
        && parts[1].starts_with("aws")
        && parts[2] == "ecs"
        && !parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
        && parts[5].starts_with("task-definition/")
        && parts[5].len() > 16
        && parts[6].parse::<u32>().is_ok_and(|revision| revision > 0)
}

fn same_ecs_authority(left: &str, right: &str) -> bool {
    let left: Vec<_> = left.split(':').collect();
    let right: Vec<_> = right.split(':').collect();
    left.get(1) == right.get(1) && left.get(3) == right.get(3) && left.get(4) == right.get(4)
}

fn valid_task_arn_for_cluster(task: &str, cluster: &str) -> bool {
    let task_parts: Vec<_> = task.split(':').collect();
    valid_cluster_arn(cluster)
        && task_parts.len() == 6
        && task_parts[0] == "arn"
        && task_parts[2] == "ecs"
        && same_ecs_authority(cluster, task)
        && task_parts[5].starts_with("task/")
        && task_parts[5].len() > 5
}

fn valid_hmac_key_arn(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 6
        && parts[0] == "arn"
        && parts[1].starts_with("aws")
        && parts[2] == "kms"
        && !parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
        && parts[5].starts_with("key/")
        && parts[5].len() > 4
}

fn valid_stop_reason(value: &str) -> bool {
    (3..=255).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

fn valid_ecs_status(value: &str) -> bool {
    (3..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
}

fn valid_failure_code(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || (index > 0 && byte.is_ascii_digit()) || byte == b'_'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CoordinatorConfig {
        CoordinatorConfig {
            cluster_arn: "arn:aws:ecs:us-east-1:123456789012:cluster/snowman-staging".into(),
            private_subnet_ids: vec!["subnet-0123456789abcdef0".into()],
            executor_security_group_id: "sg-0123456789abcdef0".into(),
            runtime_profiles: BTreeMap::from([(
                "native-acp".into(),
                RuntimeProfile {
                    runtime_id: "native-acp".into(),
                    task_definition_arn:
                        "arn:aws:ecs:us-east-1:123456789012:task-definition/snowman-agent:7".into(),
                    container_name: "snowman-agent-executor".into(),
                },
            )]),
        }
    }

    fn coordinates() -> JobCoordinates {
        JobCoordinates {
            tenant_id: Uuid::parse_str("018f95d6-f628-7c84-b7c9-17186398b702").unwrap(),
            job_id: Uuid::parse_str("018f95d6-f628-7c84-b7c9-17186398b703").unwrap(),
            task_id: Uuid::parse_str("018f95d6-f628-7c84-b7c9-17186398b704").unwrap(),
            generation: 4,
            deadline_at: DateTime::parse_from_rfc3339("2026-07-26T23:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[test]
    fn launch_identity_is_deterministic_and_sensitive_to_the_fence() {
        let config = config();
        config.validate().unwrap();
        let profile = config.runtime_profiles.get("native-acp").unwrap();
        let first = build_launch_spec(&config, profile, coordinates());
        let second = build_launch_spec(&config, profile, coordinates());
        assert_eq!(first, second);
        assert_eq!(first.client_token.len(), 64);
        let mut changed = coordinates();
        changed.generation += 1;
        assert_ne!(
            first.client_token,
            build_launch_spec(&config, profile, changed).client_token
        );
    }

    #[test]
    fn runtime_catalog_rejects_unpinned_or_cross_account_authority() {
        let mut candidate = config();
        candidate
            .runtime_profiles
            .get_mut("native-acp")
            .unwrap()
            .task_definition_arn =
            "arn:aws:ecs:us-east-1:999999999999:task-definition/snowman-agent:7".into();
        assert!(candidate.validate().is_err());
        candidate = config();
        candidate
            .runtime_profiles
            .get_mut("native-acp")
            .unwrap()
            .task_definition_arn =
            "arn:aws:ecs:us-east-1:123456789012:task-definition/snowman-agent".into();
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn public_or_ambient_placement_values_are_not_representable() {
        let config = config();
        let profile = config.runtime_profiles.get("native-acp").unwrap();
        let spec = build_launch_spec(&config, profile, coordinates());
        assert_eq!(spec.private_subnet_ids, config.private_subnet_ids);
        assert_eq!(
            spec.executor_security_group_id,
            config.executor_security_group_id
        );
        assert!(!spec.task_definition_arn.ends_with(":latest"));
        assert_eq!(started_by(spec.launch_id).len(), 36);
    }

    #[test]
    fn ecs_task_arn_must_match_the_exact_cluster_authority() {
        let cluster = &config().cluster_arn;
        assert!(valid_task_arn_for_cluster(
            "arn:aws:ecs:us-east-1:123456789012:task/snowman-staging/abc123",
            cluster
        ));
        assert!(!valid_task_arn_for_cluster(
            "arn:aws:ecs:us-east-1:999999999999:task/snowman-staging/abc123",
            cluster
        ));
    }

    #[test]
    fn production_ecs_call_has_no_public_or_ambient_authority() {
        let source = include_str!("lib.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains(".assign_public_ip(AssignPublicIp::Disabled)"));
        assert!(production.contains(".enable_execute_command(false)"));
        assert!(production.contains(".launch_type(LaunchType::Fargate)"));
        assert!(!production.contains(".task_role_arn("));
        assert!(!production.contains(".execution_role_arn("));
        assert!(!production.contains(".command("));
    }

    #[test]
    fn cancellation_reason_is_a_bounded_evidence_code() {
        assert!(valid_failure_code("operator_cancelled"));
        for invalid in ["no", "UPPER", "contains space", "delete;drop"] {
            assert!(!valid_failure_code(invalid));
        }
    }
}
