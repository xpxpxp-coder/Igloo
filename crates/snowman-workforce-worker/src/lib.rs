#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Always-on, identity-scoped Snowman workforce execution.
//!
//! One process owns exactly one tenant-bound service identity. It leases only
//! tasks assigned to that identity over NIP-98, keeps the lease fenced with
//! heartbeats, delegates governed intelligence and artifact work through the
//! private Analyst 360 KMS boundary, publishes a metadata-only context handoff,
//! and completes only after digest-verified terminal evidence exists.

use std::{collections::BTreeSet, env, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag};
use reqwest::{header, redirect::Policy, Client};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use snowman_analyst_client::{
    AnalystClient, ArtifactReference, Capability, Classification, Command, JobStatusEvent,
};
use url::Url;
use uuid::Uuid;

const CLAIM_PATH: &str = "/internal/snowman/v1/workforce/tasks/claim";
const MAINTENANCE_PATH: &str = "/internal/snowman/v1/workforce/maintenance/tick";
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// Bounded worker failures contain no objective, artifact body, key, or remote
/// response content and are therefore safe for centralized logs.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Environment configuration violates a Snowman boundary.
    #[error("workforce worker configuration is invalid: {0}")]
    Configuration(&'static str),
    /// NIP-98 signing failed.
    #[error("workforce request signing failed")]
    Signing,
    /// Private relay transport failed.
    #[error("workforce relay transport failed")]
    Transport,
    /// Private relay rejected a request.
    #[error("workforce relay rejected the operation with HTTP {0}")]
    RelayRejected(u16),
    /// Private relay returned an invalid contract.
    #[error("workforce relay response is invalid: {0}")]
    RelayContract(&'static str),
    /// Analyst command/status processing failed.
    #[error("governed Analyst operation failed")]
    Analyst(#[from] snowman_analyst_client::Error),
}

/// Exact identities used by the deterministic default specialist team.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamIdentities {
    /// Governed analytics specialist identity.
    pub governed_analyst: Uuid,
    /// Client-ready artifact specialist identity.
    pub client_delivery: Uuid,
    /// Independent quality/risk reviewer identity.
    pub quality_risk_reviewer: Uuid,
    /// Optional operator-selected model IDs. Every override is still rejected
    /// unless the server-side evaluated catalog allows it for the role/class.
    #[serde(default)]
    pub model_overrides: TeamModelOverrides,
}

/// Optional per-specialist model choices. Omitted values invoke automatic
/// best-fit selection by the Command Center policy kernel.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamModelOverrides {
    /// Governed analytics model ID.
    pub governed_analyst: Option<String>,
    /// Client-delivery model ID.
    pub client_delivery: Option<String>,
    /// Quality/risk review model ID.
    pub quality_risk_reviewer: Option<String>,
}

/// Runtime configuration for one identity-isolated worker process.
pub struct Config {
    relay_url: Url,
    private_key: Keys,
    identity_id: Uuid,
    analyst: snowman_analyst_client::Config,
    team: TeamIdentities,
    claim_interval: Duration,
    status_interval: Duration,
    once: bool,
}

impl Config {
    /// Load the exact worker boundary from environment variables.
    pub fn from_env() -> Result<Self, Error> {
        let relay_url = parse_snowman_origin(&required("SNOWMAN_WORKFORCE_RELAY_URL")?)?;
        let private_key = Keys::parse(&required("SNOWMAN_WORKFORCE_NOSTR_PRIVATE_KEY")?)
            .map_err(|_| Error::Configuration("worker Nostr private key is invalid"))?;
        let identity_id = parse_uuid("SNOWMAN_WORKFORCE_IDENTITY_ID")?;
        let team: TeamIdentities =
            serde_json::from_str(&required("SNOWMAN_WORKFORCE_TEAM_IDENTITIES_JSON")?)
                .map_err(|_| Error::Configuration("team identity map is invalid"))?;
        validate_team(&team)?;
        let analyst = snowman_analyst_client::Config {
            endpoint: parse_snowman_origin(&required("SNOWMAN_ANALYST_ENDPOINT")?)?,
            service_principal: required("SNOWMAN_ANALYST_SERVICE_PRINCIPAL")?,
            signing_key_arn: required("SNOWMAN_ANALYST_SIGNING_KEY_ARN")?,
            tenant_id: required("SNOWMAN_ANALYST_TENANT_ID")?,
            client_id: required("SNOWMAN_ANALYST_CLIENT_ID")?,
            project_id: required("SNOWMAN_ANALYST_PROJECT_ID")?,
            timeout: Duration::from_secs(parse_seconds("SNOWMAN_ANALYST_TIMEOUT_SECONDS", 30, 60)?),
        };
        Ok(Self {
            relay_url,
            private_key,
            identity_id,
            analyst,
            team,
            claim_interval: Duration::from_secs(parse_seconds(
                "SNOWMAN_WORKFORCE_CLAIM_INTERVAL_SECONDS",
                15,
                300,
            )?),
            status_interval: Duration::from_secs(parse_seconds(
                "SNOWMAN_WORKFORCE_STATUS_INTERVAL_SECONDS",
                15,
                60,
            )?),
            once: env::var("SNOWMAN_WORKFORCE_ONCE").is_ok_and(|value| value == "true"),
        })
    }
}

/// Runtime configuration for the dedicated, non-executing maintenance
/// scheduler. It deliberately has no Analyst endpoint or AWS signing key.
pub struct SchedulerConfig {
    relay_url: Url,
    private_key: Keys,
    identity_id: Uuid,
    interval: Duration,
    once: bool,
}

impl SchedulerConfig {
    /// Load the exact scheduler boundary from environment variables.
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self {
            relay_url: parse_snowman_origin(&required("SNOWMAN_WORKFORCE_RELAY_URL")?)?,
            private_key: Keys::parse(&required("SNOWMAN_WORKFORCE_SCHEDULER_NOSTR_PRIVATE_KEY")?)
                .map_err(|_| {
                Error::Configuration("scheduler Nostr private key is invalid")
            })?,
            identity_id: parse_uuid("SNOWMAN_WORKFORCE_SCHEDULER_IDENTITY_ID")?,
            interval: Duration::from_secs(parse_seconds(
                "SNOWMAN_WORKFORCE_MAINTENANCE_INTERVAL_SECONDS",
                30,
                300,
            )?),
            once: env::var("SNOWMAN_WORKFORCE_SCHEDULER_ONCE").is_ok_and(|value| value == "true"),
        })
    }
}

/// Always-on scheduler for deadline enforcement and abandoned-lease recovery.
/// It cannot claim tasks, invoke models, read Analyst data, or execute proactive
/// actions because its only runtime credential is a separately bound relay key.
pub struct Scheduler {
    relay: RelayClient,
    identity_id: Uuid,
    interval: Duration,
    once: bool,
}

impl Scheduler {
    /// Construct the scheduler's private relay client.
    pub fn new(config: SchedulerConfig) -> Result<Self, Error> {
        Ok(Self {
            relay: RelayClient::new(config.relay_url, config.private_key)?,
            identity_id: config.identity_id,
            interval: config.interval,
            once: config.once,
        })
    }

    /// Run maintenance continuously. A failed request retains the same tick ID
    /// and request time on retry, so a lost success response cannot duplicate or
    /// misreport a committed transition.
    pub async fn run(&self) -> Result<(), Error> {
        loop {
            let tick_id = Uuid::new_v4();
            let requested_at = Utc::now();
            loop {
                match self.tick(tick_id, requested_at).await {
                    Ok(result) => {
                        tracing::info!(
                            %tick_id,
                            identity_id = %self.identity_id,
                            expired_requests = result.expired_requests,
                            expired_tasks = result.expired_tasks,
                            expired_proactive_actions = result.expired_proactive_actions,
                            requeued_tasks = result.requeued_tasks,
                            dead_lettered_tasks = result.dead_lettered_tasks,
                            "governed workforce maintenance completed"
                        );
                        break;
                    }
                    Err(error) if self.once => return Err(error),
                    Err(error) => {
                        tracing::error!(
                            %error,
                            %tick_id,
                            identity_id = %self.identity_id,
                            "governed workforce maintenance retrying"
                        );
                        tokio::time::sleep(self.interval).await;
                    }
                }
            }
            if self.once {
                return Ok(());
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    async fn tick(
        &self,
        tick_id: Uuid,
        requested_at: DateTime<Utc>,
    ) -> Result<MaintenanceResponse, Error> {
        let response: MaintenanceResponse = self
            .relay
            .post_json(
                MAINTENANCE_PATH,
                &json!({
                    "schema_version": "snowman.workforce.maintenance.tick.v1",
                    "tick_id": tick_id,
                    "requested_at": requested_at,
                }),
            )
            .await?;
        if response.schema_version != "snowman.workforce.maintenance.result.v1"
            || response.tick_id != tick_id
            || response.observed_at < requested_at - chrono::Duration::minutes(5)
            || response.observed_at > Utc::now() + chrono::Duration::minutes(5)
        {
            return Err(Error::RelayContract(
                "maintenance response identity or time is invalid",
            ));
        }
        Ok(response)
    }
}

/// One always-on Snowman specialist worker.
pub struct Worker {
    relay: RelayClient,
    analyst: AnalystClient,
    identity_id: Uuid,
    team: TeamIdentities,
    claim_interval: Duration,
    status_interval: Duration,
    once: bool,
}

impl Worker {
    /// Construct clients without exposing either service credential to another
    /// process or tool runtime.
    pub async fn new(config: Config) -> Result<Self, Error> {
        let relay = RelayClient::new(config.relay_url, config.private_key)?;
        let analyst = AnalystClient::new(config.analyst).await?;
        Ok(Self {
            relay,
            analyst,
            identity_id: config.identity_id,
            team: config.team,
            claim_interval: config.claim_interval,
            status_interval: config.status_interval,
            once: config.once,
        })
    }

    /// Claim and execute tasks until shutdown. `SNOWMAN_WORKFORCE_ONCE=true`
    /// performs exactly one claim cycle for controlled smoke tests.
    pub async fn run(&self) -> Result<(), Error> {
        loop {
            match self.run_once().await {
                Ok(true) => {}
                Ok(false) if !self.once => tokio::time::sleep(self.claim_interval).await,
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, identity_id = %self.identity_id, "governed work cycle failed");
                    if self.once {
                        return Err(error);
                    }
                    tokio::time::sleep(self.claim_interval).await;
                }
            }
            if self.once {
                return Ok(());
            }
        }
    }

    async fn run_once(&self) -> Result<bool, Error> {
        let lease = self.relay.claim(Uuid::new_v4()).await?;
        let Some(lease) = lease else {
            return Ok(false);
        };
        if lease.task.service_identity_id != self.identity_id {
            return Err(Error::RelayContract(
                "leased task does not match configured service identity",
            ));
        }
        tracing::info!(
            request_id = %lease.task.request_id,
            task_id = %lease.task.task_id,
            role = %lease.task.specialist_role,
            model_id = %lease.task.model_id,
            "governed task leased"
        );
        if lease.task.specialist_role == "lead" {
            self.commit_default_team(&lease).await?;
        } else {
            self.execute_analyst_task(&lease).await?;
        }
        Ok(true)
    }

    async fn commit_default_team(&self, lease: &Lease) -> Result<(), Error> {
        let plan = build_default_team_plan(lease, &self.team)?;
        let path = format!(
            "/internal/snowman/v1/workforce/tasks/{}/plan",
            lease.task.task_id
        );
        let _: Value = self.relay.post_json(&path, &plan).await?;
        tracing::info!(
            request_id = %lease.task.request_id,
            lead_task_id = %lease.task.task_id,
            "governed specialist team committed"
        );
        Ok(())
    }

    async fn execute_analyst_task(&self, lease: &Lease) -> Result<(), Error> {
        let capability = analyst_capability(&lease.task)?;
        let command_id = format!("work-task-{}", lease.task.task_id);
        let correlation_id = format!("work-request-{}", lease.task.request_id);
        let expiry = command_expiry(&lease.task);
        if expiry <= Utc::now() {
            self.finish_failure(lease, "analyst_command_expired")
                .await?;
            return Ok(());
        }
        let input_refs = self.resolve_input_refs(lease).await?;
        let command = Command {
            command_id: command_id.clone(),
            correlation_id: correlation_id.clone(),
            idempotency_key: format!("work-task-{}", lease.task.task_id),
            capability,
            model_id: lease.task.model_id.clone(),
            specialist_role: lease.task.specialist_role.clone(),
            expected_artifact_type: lease
                .task
                .expected_artifact_contract
                .get("artifact_type")
                .and_then(Value::as_str)
                .unwrap_or("governed_work_product")
                .to_string(),
            max_cost_microusd: nonnegative(lease.task.task_max_cost_microusd)?,
            expected_input_tokens: nonnegative(lease.task.expected_input_tokens)?,
            max_output_tokens: nonnegative(lease.task.task_max_output_tokens)?,
            risk_tier: lease.task.risk_tier.clone(),
            reversible: lease.task.reversible,
            approval_required: lease.task.approval_required,
            context_refs: lease.task.context_references.clone(),
            instruction: specialist_instruction(&lease.task),
            input_refs,
            delegated_agent_id: Some(lease.task.service_identity_id.to_string()),
            classification: analyst_classification(&lease.task.classification)?,
            submitted_at: lease.task.request_created_at,
            expires_at: expiry,
        };
        let accepted = self.analyst.submit(&command).await?;
        let mut event = accepted.status_event;
        loop {
            match event.status.as_str() {
                "succeeded" => {
                    if event.output_refs.is_empty() {
                        return Err(Error::RelayContract(
                            "successful Analyst job has no immutable artifact reference",
                        ));
                    }
                    self.publish_context(lease, &event).await?;
                    self.finish_success(lease, &event).await?;
                    return Ok(());
                }
                "failed" | "cancelled" | "expired" => {
                    self.finish_failure(lease, terminal_failure_code(&event.status))
                        .await?;
                    return Ok(());
                }
                "accepted" | "queued" | "running" | "awaiting_approval" => {}
                _ => return Err(Error::RelayContract("Analyst status is not allowlisted")),
            }
            self.heartbeat(lease).await?;
            tokio::time::sleep(self.status_interval).await;
            event = self
                .analyst
                .read_status(&accepted.job_id, &command_id, &correlation_id)
                .await?;
        }
    }

    async fn heartbeat(&self, lease: &Lease) -> Result<(), Error> {
        let path = format!(
            "/internal/snowman/v1/workforce/tasks/{}/heartbeat",
            lease.task.task_id
        );
        let body = json!({
            "generation": lease.lease_generation,
            "lease_token": lease.lease_token,
        });
        let _: Value = self.relay.post_json(&path, &body).await?;
        Ok(())
    }

    async fn resolve_input_refs(&self, lease: &Lease) -> Result<Vec<ArtifactReference>, Error> {
        if lease.task.context_references.is_empty() {
            return Ok(Vec::new());
        }
        let path = format!(
            "/internal/snowman/v1/workforce/requests/{}/context-packets",
            lease.task.request_id
        );
        let response: ContextListResponse = self.relay.get_json(&path).await?;
        if response.schema_version != "snowman.workforce.context.list.v1"
            || response.request_id != lease.task.request_id
        {
            return Err(Error::RelayContract("context list binding is invalid"));
        }
        let expected: BTreeSet<_> = lease.task.context_references.iter().cloned().collect();
        let mut matched = BTreeSet::new();
        let mut resolved = Vec::new();
        for packet in response.packets {
            validate_context_packet(&packet, lease)?;
            if !expected.contains(&packet.content_reference)
                || packet.authority != "analyst360"
                || packet.classification != lease.task.classification
                || packet.content_reference
                    != format!("analyst360:sha256:{}", packet.content_sha256)
            {
                continue;
            }
            matched.insert(packet.content_reference.clone());
            resolved.push(ArtifactReference {
                artifact_id: packet.artifact_id,
                artifact_type: packet.artifact_type,
                authority: "analyst360".into(),
                classification: analyst_classification(&packet.classification)?,
                created_at: packet.created_at.to_rfc3339(),
                sha256: packet.content_sha256,
                version_id: packet.artifact_version,
            });
        }
        resolved.sort_by(|left, right| left.sha256.cmp(&right.sha256));
        resolved.dedup_by(|left, right| left.sha256 == right.sha256);
        if resolved.len() > 50 {
            return Err(Error::RelayContract(
                "specialist dependency context exceeds the Analyst artifact limit",
            ));
        }
        if matched != expected {
            return Err(Error::RelayContract(
                "specialist dependency context did not resolve exactly to Analyst artifacts",
            ));
        }
        Ok(resolved)
    }

    async fn publish_context(&self, lease: &Lease, event: &JobStatusEvent) -> Result<(), Error> {
        let first = &event.output_refs[0];
        let artifact_references: Vec<_> = event
            .output_refs
            .iter()
            .map(|reference| format!("analyst360:sha256:{}", reference.sha256))
            .collect();
        let context_packet_id = deterministic_uuid(
            "context",
            &format!("{}:{}", lease.task.task_id, event.event_sha256),
        );
        let path = format!(
            "/internal/snowman/v1/workforce/requests/{}/context-packets",
            lease.task.request_id
        );
        let body = json!({
            "schema_version": "snowman.workforce.context.publish.v1",
            "context_packet_id": context_packet_id,
            "source_task_id": lease.task.task_id,
            "generation": lease.lease_generation,
            "lease_token": lease.lease_token,
            "classification": lease.task.classification,
            "authority": "analyst360",
            "objective_sha256": sha256_hex(lease.task.objective.as_bytes()),
            "content_reference": format!("analyst360:sha256:{}", first.sha256),
            "content_sha256": first.sha256,
            "source_event_sha256": event.event_sha256,
            "size_bytes": 0,
            "artifact_references": artifact_references,
            "evidence_references": [],
            "decision_digests": [],
            "open_question_digests": [],
            "next_actions": [],
            "artifact_id": first.artifact_id,
            "artifact_version": first.version_id,
            "artifact_type": first.artifact_type,
            "expires_at": command_expiry(&lease.task),
            "occurred_at": Utc::now(),
        });
        let _: Value = self.relay.post_json(&path, &body).await?;
        Ok(())
    }

    async fn finish_success(&self, lease: &Lease, event: &JobStatusEvent) -> Result<(), Error> {
        let refs: Vec<_> = event
            .output_refs
            .iter()
            .map(|reference| format!("analyst360:sha256:{}", reference.sha256))
            .collect();
        self.finish(lease, true, &event.event_sha256, refs, None)
            .await
    }

    async fn finish_failure(&self, lease: &Lease, code: &str) -> Result<(), Error> {
        let digest = sha256_hex(
            format!(
                "{}\x1f{}\x1f{code}",
                lease.task.request_id, lease.task.task_id
            )
            .as_bytes(),
        );
        self.finish(lease, false, &digest, Vec::new(), Some(code))
            .await
    }

    async fn finish(
        &self,
        lease: &Lease,
        succeeded: bool,
        result_sha256: &str,
        artifact_references: Vec<String>,
        failure_code: Option<&str>,
    ) -> Result<(), Error> {
        let path = format!(
            "/internal/snowman/v1/workforce/tasks/{}/finish",
            lease.task.task_id
        );
        let completion_id = deterministic_uuid(
            "completion",
            &format!("{}:{result_sha256}", lease.task.task_id),
        );
        let body = json!({
            "generation": lease.lease_generation,
            "lease_token": lease.lease_token,
            "completion_id": completion_id,
            "succeeded": succeeded,
            "result_sha256": result_sha256,
            "artifact_references": artifact_references,
            "failure_code": failure_code,
            "occurred_at": Utc::now(),
        });
        let _: Value = self.relay.post_json(&path, &body).await?;
        tracing::info!(
            request_id = %lease.task.request_id,
            task_id = %lease.task.task_id,
            succeeded,
            "governed task completed"
        );
        Ok(())
    }
}

struct RelayClient {
    base_url: Url,
    keys: Keys,
    http: Client,
}

impl RelayClient {
    fn new(base_url: Url, keys: Keys) -> Result<Self, Error> {
        let http = Client::builder()
            .timeout(Duration::from_secs(45))
            .connect_timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .no_proxy()
            .https_only(true)
            .build()
            .map_err(|_| Error::Configuration("relay HTTP client could not be built"))?;
        Ok(Self {
            base_url,
            keys,
            http,
        })
    }

    async fn claim(&self, claim_id: Uuid) -> Result<Option<Lease>, Error> {
        let response: ClaimResponse = self
            .post_json(CLAIM_PATH, &json!({ "claim_id": claim_id }))
            .await?;
        if response.schema_version != "snowman.work.lease.v1" {
            return Err(Error::RelayContract("claim schema version is invalid"));
        }
        match response.task {
            None => {
                if response.lease_token.is_some()
                    || response.lease_generation.is_some()
                    || response.lease_expires_at.is_some()
                    || response
                        .retry_after_seconds
                        .is_none_or(|seconds| seconds == 0 || seconds > 300)
                {
                    return Err(Error::RelayContract("empty claim response is inconsistent"));
                }
                Ok(None)
            }
            Some(task) => {
                let lease_token = response
                    .lease_token
                    .ok_or(Error::RelayContract("leased task has no lease token"))?;
                let lease_generation = response
                    .lease_generation
                    .filter(|generation| *generation > 0)
                    .ok_or(Error::RelayContract("lease generation is invalid"))?;
                response
                    .lease_expires_at
                    .filter(|expires_at| *expires_at > Utc::now())
                    .ok_or(Error::RelayContract("lease expiry is invalid"))?;
                validate_leased_task(&task)?;
                Ok(Some(Lease {
                    lease_token,
                    lease_generation,
                    task,
                }))
            }
        }
    }

    async fn post_json<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let bytes = serde_json::to_vec(body)
            .map_err(|_| Error::RelayContract("request JSON could not be serialized"))?;
        let url = self.url(path)?;
        let auth = sign_nip98(&self.keys, "POST", url.as_str(), Some(&bytes))?;
        let response = self
            .http
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(header::AUTHORIZATION, auth)
            .body(bytes)
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        decode_response(response).await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let url = self.url(path)?;
        let auth = sign_nip98(&self.keys, "GET", url.as_str(), None)?;
        let response = self
            .http
            .get(url)
            .header(header::ACCEPT, "application/json")
            .header(header::AUTHORIZATION, auth)
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        decode_response(response).await
    }

    fn url(&self, path: &str) -> Result<Url, Error> {
        if !path.starts_with('/') || path.contains('?') || path.contains('#') {
            return Err(Error::Configuration("relay path is invalid"));
        }
        self.base_url
            .join(path)
            .map_err(|_| Error::Configuration("relay URL could not be built"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimResponse {
    schema_version: String,
    #[serde(default)]
    lease_token: Option<String>,
    #[serde(default)]
    lease_generation: Option<i64>,
    #[serde(default)]
    lease_expires_at: Option<DateTime<Utc>>,
    task: Option<LeasedTask>,
    #[serde(default)]
    retry_after_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceResponse {
    schema_version: String,
    tick_id: Uuid,
    observed_at: DateTime<Utc>,
    expired_requests: u64,
    expired_tasks: u64,
    expired_proactive_actions: u64,
    requeued_tasks: u64,
    dead_lettered_tasks: u64,
}

struct Lease {
    lease_token: String,
    lease_generation: i64,
    task: LeasedTask,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeasedTask {
    request_id: Uuid,
    task_id: Uuid,
    claim_id: Uuid,
    objective: String,
    request_contract_sha256: String,
    classification: String,
    request_created_at: DateTime<Utc>,
    request_deadline_at: Option<DateTime<Utc>>,
    max_cost_microusd: i64,
    max_input_tokens: i64,
    max_output_tokens: i64,
    specialist_role: String,
    service_identity_id: Uuid,
    required_capabilities: Vec<String>,
    model_gateway_route: String,
    model_id: String,
    task_max_cost_microusd: i64,
    expected_input_tokens: i64,
    task_max_output_tokens: i64,
    execution_snapshot_sha256: String,
    expected_artifact_contract: Value,
    context_references: Vec<String>,
    context_packet_id: Option<Uuid>,
    risk_tier: String,
    reversible: bool,
    approval_required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextListResponse {
    schema_version: String,
    request_id: Uuid,
    packets: Vec<ContextPacket>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextPacket {
    context_packet_id: Uuid,
    request_id: Uuid,
    classification: String,
    authority: String,
    objective_sha256: String,
    content_reference: String,
    content_sha256: String,
    source_event_sha256: String,
    manifest_sha256: String,
    size_bytes: u64,
    artifact_id: String,
    artifact_version: String,
    artifact_type: String,
    artifact_references: Vec<String>,
    evidence_references: Vec<String>,
    decision_digests: Vec<String>,
    open_question_digests: Vec<String>,
    next_actions: Vec<Value>,
    created_by_identity_id: Uuid,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

fn validate_context_packet(packet: &ContextPacket, lease: &Lease) -> Result<(), Error> {
    let valid_reference = |value: &str| {
        value
            .strip_prefix("analyst360:sha256:")
            .or_else(|| value.strip_prefix("snowman:sha256:"))
            .is_some_and(is_sha256)
    };
    if packet.context_packet_id.is_nil()
        || packet.request_id != lease.task.request_id
        || packet.created_by_identity_id.is_nil()
        || !matches!(
            packet.classification.as_str(),
            "internal" | "confidential" | "restricted"
        )
        || !matches!(
            packet.authority.as_str(),
            "analyst360" | "snowman-command-center"
        )
        || !is_sha256(&packet.objective_sha256)
        || !valid_reference(&packet.content_reference)
        || !is_sha256(&packet.content_sha256)
        || !is_sha256(&packet.source_event_sha256)
        || !is_sha256(&packet.manifest_sha256)
        || packet.size_bytes > 1_048_576
        || packet.artifact_id.is_empty()
        || packet.artifact_id.len() > 512
        || packet.artifact_version.is_empty()
        || packet.artifact_version.len() > 256
        || packet.artifact_type.is_empty()
        || packet.artifact_type.len() > 128
        || packet.artifact_references.len() > 128
        || packet
            .artifact_references
            .iter()
            .any(|value| !valid_reference(value))
        || packet.evidence_references.len() > 128
        || packet
            .evidence_references
            .iter()
            .any(|value| !valid_reference(value))
        || packet.decision_digests.len() > 128
        || packet
            .decision_digests
            .iter()
            .any(|value| !value.strip_prefix("sha256:").is_some_and(is_sha256))
        || packet.open_question_digests.len() > 128
        || packet
            .open_question_digests
            .iter()
            .any(|value| !value.strip_prefix("sha256:").is_some_and(is_sha256))
        || packet.next_actions.len() > 32
        || packet.next_actions.iter().any(|value| !value.is_object())
        || packet.expires_at.is_some_and(|value| value <= Utc::now())
        || packet.created_at > Utc::now() + chrono::Duration::minutes(5)
    {
        return Err(Error::RelayContract(
            "context packet violates the worker handoff contract",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct TeamPlan<'a> {
    schema_version: &'static str,
    plan_id: Uuid,
    request_id: Uuid,
    generation: i64,
    lease_token: &'a str,
    tasks: Vec<PlanTask>,
}

#[derive(Serialize)]
struct PlanTask {
    task_id: Uuid,
    service_identity_id: Uuid,
    specialist_role: &'static str,
    depends_on: BTreeSet<Uuid>,
    required_capabilities: BTreeSet<String>,
    context_references: BTreeSet<String>,
    requested_model_id: Option<String>,
    expected_input_tokens: u64,
    max_output_tokens: u64,
    max_cost_microusd: u64,
    risk_tier: &'static str,
    reversible: bool,
    approval_required: bool,
    expected_artifact_type: &'static str,
}

fn build_default_team_plan<'a>(
    lease: &'a Lease,
    team: &TeamIdentities,
) -> Result<TeamPlan<'a>, Error> {
    validate_team(team)?;
    let task = &lease.task;
    if task.context_references.len() > 62 {
        return Err(Error::RelayContract(
            "team requests reserve two context slots for dependency handoffs",
        ));
    }
    let analyst_id = deterministic_uuid("governed-analyst", &task.request_id.to_string());
    let delivery_id = deterministic_uuid("client-delivery", &task.request_id.to_string());
    let review_id = deterministic_uuid("quality-review", &task.request_id.to_string());
    let max_input = nonnegative(task.max_input_tokens)?;
    let max_output = nonnegative(task.max_output_tokens)?;
    let max_cost = nonnegative(task.max_cost_microusd)?;
    let contexts: BTreeSet<_> = task.context_references.iter().cloned().collect();
    let make = |task_id,
                service_identity_id,
                specialist_role,
                depends_on,
                required_capabilities,
                requested_model_id,
                input,
                output,
                cost,
                artifact_type| PlanTask {
        task_id,
        service_identity_id,
        specialist_role,
        depends_on,
        required_capabilities,
        context_references: contexts.clone(),
        requested_model_id,
        expected_input_tokens: input,
        max_output_tokens: output,
        max_cost_microusd: cost,
        risk_tier: "low",
        reversible: true,
        approval_required: false,
        expected_artifact_type: artifact_type,
    };
    let analyst = make(
        analyst_id,
        team.governed_analyst,
        "governed_analyst",
        BTreeSet::new(),
        BTreeSet::from([
            "analytics.query".to_string(),
            "workforce.context.write".to_string(),
        ]),
        team.model_overrides.governed_analyst.clone(),
        max_input * 45 / 100,
        max_output * 35 / 100,
        max_cost * 45 / 100,
        "governed_analysis",
    );
    let delivery = make(
        delivery_id,
        team.client_delivery,
        "client_delivery",
        BTreeSet::from([analyst_id]),
        BTreeSet::from([
            "artifact.build".to_string(),
            "workforce.context.write".to_string(),
        ]),
        team.model_overrides.client_delivery.clone(),
        max_input * 35 / 100,
        max_output * 45 / 100,
        max_cost * 35 / 100,
        "client_ready_work_product",
    );
    let review = make(
        review_id,
        team.quality_risk_reviewer,
        "quality_risk_reviewer",
        BTreeSet::from([analyst_id, delivery_id]),
        BTreeSet::from([
            "artifact.build".to_string(),
            "artifact.review".to_string(),
            "workforce.context.write".to_string(),
        ]),
        team.model_overrides.quality_risk_reviewer.clone(),
        max_input.saturating_sub(analyst.expected_input_tokens + delivery.expected_input_tokens),
        max_output.saturating_sub(analyst.max_output_tokens + delivery.max_output_tokens),
        max_cost.saturating_sub(analyst.max_cost_microusd + delivery.max_cost_microusd),
        "quality_risk_review",
    );
    Ok(TeamPlan {
        schema_version: "snowman.team_plan.proposal.v1",
        plan_id: deterministic_uuid("team-plan", &task.request_id.to_string()),
        request_id: task.request_id,
        generation: lease.lease_generation,
        lease_token: &lease.lease_token,
        tasks: vec![analyst, delivery, review],
    })
}

fn analyst_capability(task: &LeasedTask) -> Result<Capability, Error> {
    let capabilities: BTreeSet<_> = task
        .required_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    match task.specialist_role.as_str() {
        "governed_analyst" if capabilities.contains("analytics.query") => {
            Ok(Capability::AnalyticsQuery)
        }
        "client_delivery" | "quality_risk_reviewer" if capabilities.contains("artifact.build") => {
            Ok(Capability::ArtifactBuild)
        }
        "research_evidence" if capabilities.contains("evidence.manifest.read") => {
            Ok(Capability::EvidenceManifestRead)
        }
        _ => Err(Error::RelayContract(
            "specialist role has no exact Analyst capability",
        )),
    }
}

fn validate_leased_task(task: &LeasedTask) -> Result<(), Error> {
    let valid_context = |reference: &str| {
        reference
            .strip_prefix("analyst360:sha256:")
            .or_else(|| reference.strip_prefix("snowman:sha256:"))
            .is_some_and(is_sha256)
    };
    if task.request_id.is_nil()
        || task.task_id.is_nil()
        || task.claim_id.is_nil()
        || task.objective.is_empty()
        || task.objective.len() > 8_000
        || !is_sha256(&task.request_contract_sha256)
        || !is_sha256(&task.execution_snapshot_sha256)
        || !matches!(
            task.classification.as_str(),
            "internal" | "confidential" | "restricted"
        )
        || task.service_identity_id.is_nil()
        || task.required_capabilities.is_empty()
        || task.model_id.is_empty()
        || task.model_id.len() > 256
        || !valid_snowman_service_url(&task.model_gateway_route)
        || nonnegative(task.max_cost_microusd).is_err()
        || nonnegative(task.max_input_tokens).is_err()
        || nonnegative(task.max_output_tokens).is_err()
        || nonnegative(task.task_max_cost_microusd).is_err()
        || nonnegative(task.expected_input_tokens).is_err()
        || nonnegative(task.task_max_output_tokens).is_err()
        || task.task_max_cost_microusd > task.max_cost_microusd
        || task.expected_input_tokens > task.max_input_tokens
        || task.task_max_output_tokens > task.max_output_tokens
        || !task.expected_artifact_contract.is_object()
        || task.context_references.len() > 64
        || task
            .context_references
            .iter()
            .any(|reference| !valid_context(reference))
        || task.context_packet_id.is_some_and(|id| id.is_nil())
        || !matches!(task.risk_tier.as_str(), "low" | "moderate" | "high")
        || (!task.reversible && !task.approval_required)
    {
        return Err(Error::RelayContract(
            "leased task violates the worker contract",
        ));
    }
    Ok(())
}

fn specialist_instruction(task: &LeasedTask) -> String {
    let role = match task.specialist_role.as_str() {
        "governed_analyst" => "Produce a governed, evidence-linked analysis",
        "client_delivery" => "Build a polished client-ready work product using prior governed outputs",
        "quality_risk_reviewer" => {
            "Independently review prior outputs for correctness, evidence, risk, and client readiness; produce the reviewed work product"
        }
        "research_evidence" => "Build an evidence manifest for the objective",
        _ => "Perform the assigned governed operation",
    };
    let prefix = format!(
        "{role}. Snowman workforce request {}. Use only server-authorized Analyst 360 data and artifacts for this tenant/project. Objective: ",
        task.request_id
    );
    bounded_concat(&prefix, &task.objective, 4_000)
}

fn command_expiry(task: &LeasedTask) -> DateTime<Utc> {
    task.request_deadline_at
        .unwrap_or(task.request_created_at + chrono::Duration::days(365))
}

fn analyst_classification(value: &str) -> Result<Classification, Error> {
    match value {
        "internal" => Ok(Classification::Internal),
        "confidential" => Ok(Classification::Confidential),
        "restricted" => Ok(Classification::Restricted),
        _ => Err(Error::RelayContract("task classification is invalid")),
    }
}

fn terminal_failure_code(status: &str) -> &'static str {
    match status {
        "cancelled" => "analyst_job_cancelled",
        "expired" => "analyst_job_expired",
        _ => "analyst_job_failed",
    }
}

fn sign_nip98(keys: &Keys, method: &str, url: &str, body: Option<&[u8]>) -> Result<String, Error> {
    let mut tags = vec![
        Tag::parse(["u", url]).map_err(|_| Error::Signing)?,
        Tag::parse(["method", method]).map_err(|_| Error::Signing)?,
        Tag::parse(["nonce", &Uuid::new_v4().to_string()]).map_err(|_| Error::Signing)?,
    ];
    if let Some(body) = body {
        let digest = sha256_hex(body);
        tags.push(Tag::parse(["payload", &digest]).map_err(|_| Error::Signing)?);
    }
    let event = EventBuilder::new(Kind::Custom(27235), "")
        .tags(tags)
        .sign_with_keys(keys)
        .map_err(|_| Error::Signing)?;
    Ok(format!(
        "Nostr {}",
        STANDARD.encode(event.as_json().as_bytes())
    ))
}

async fn decode_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    let status = response.status();
    if !status.is_success() {
        return Err(Error::RelayRejected(status.as_u16()));
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("");
    if content_type != "application/json" {
        return Err(Error::RelayContract("response content type is invalid"));
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Transport)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(Error::RelayContract("response exceeds 512 KiB"));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| Error::RelayContract("response JSON is invalid"))
}

fn parse_snowman_origin(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| Error::Configuration("service URL is invalid"))?;
    let host = url.host_str().unwrap_or("");
    if url.scheme() != "https"
        || !(host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || !matches!(url.port(), None | Some(443))
    {
        return Err(Error::Configuration(
            "service URL must be an exact HTTPS snowmanai.org origin",
        ));
    }
    Ok(url)
}

fn valid_snowman_service_url(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    let host = url.host_str().unwrap_or("");
    url.scheme() == "https"
        && (host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn validate_team(team: &TeamIdentities) -> Result<(), Error> {
    let identities = [
        team.governed_analyst,
        team.client_delivery,
        team.quality_risk_reviewer,
    ];
    if identities.iter().any(Uuid::is_nil)
        || identities.iter().collect::<BTreeSet<_>>().len() != identities.len()
        || [
            team.model_overrides.governed_analyst.as_deref(),
            team.model_overrides.client_delivery.as_deref(),
            team.model_overrides.quality_risk_reviewer.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|model| {
            model.is_empty()
                || model.len() > 256
                || model.contains("://")
                || model.chars().any(char::is_control)
        })
    {
        return Err(Error::Configuration(
            "team identities or model overrides are invalid",
        ));
    }
    Ok(())
}

fn required(name: &'static str) -> Result<String, Error> {
    let value = env::var(name).map_err(|_| Error::Configuration(name))?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return Err(Error::Configuration(name));
    }
    Ok(value)
}

fn parse_uuid(name: &'static str) -> Result<Uuid, Error> {
    Uuid::parse_str(&required(name)?).map_err(|_| Error::Configuration(name))
}

fn parse_seconds(name: &'static str, default: u64, maximum: u64) -> Result<u64, Error> {
    let value = match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| Error::Configuration(name))?,
        Err(_) => default,
    };
    if value == 0 || value > maximum {
        return Err(Error::Configuration(name));
    }
    Ok(value)
}

fn nonnegative(value: i64) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::RelayContract("task budget is negative"))
}

fn deterministic_uuid(domain: &str, material: &str) -> Uuid {
    let digest = Sha256::digest(format!("snowman-workforce\x1f{domain}\x1f{material}"));
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_concat(prefix: &str, value: &str, maximum: usize) -> String {
    let remaining = maximum.saturating_sub(prefix.len());
    let mut end = value.len().min(remaining);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{prefix}{}", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> LeasedTask {
        LeasedTask {
            request_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            task_id: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
            claim_id: Uuid::new_v4(),
            objective: "Create a strong evidence-grounded client deliverable.".into(),
            request_contract_sha256: "a".repeat(64),
            classification: "confidential".into(),
            request_created_at: "2026-07-26T18:00:00Z".parse().unwrap(),
            request_deadline_at: Some("2026-07-27T18:00:00Z".parse().unwrap()),
            max_cost_microusd: 1_000_000,
            max_input_tokens: 100_000,
            max_output_tokens: 20_000,
            specialist_role: "lead".into(),
            service_identity_id: Uuid::new_v4(),
            required_capabilities: vec!["workforce.plan".into()],
            model_gateway_route: "https://models.snowmanai.org/v1".into(),
            model_id: "snowman-planner".into(),
            task_max_cost_microusd: 1_000_000,
            expected_input_tokens: 100_000,
            task_max_output_tokens: 20_000,
            execution_snapshot_sha256: "b".repeat(64),
            expected_artifact_contract: json!({}),
            context_references: vec![format!("analyst360:sha256:{}", "c".repeat(64))],
            context_packet_id: None,
            risk_tier: "low".into(),
            reversible: true,
            approval_required: false,
        }
    }

    fn team() -> TeamIdentities {
        TeamIdentities {
            governed_analyst: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            client_delivery: Uuid::parse_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap(),
            quality_risk_reviewer: Uuid::parse_str("cccccccc-cccc-4ccc-8ccc-cccccccccccc").unwrap(),
            model_overrides: TeamModelOverrides {
                governed_analyst: Some("snowman-analysis-best".into()),
                client_delivery: None,
                quality_risk_reviewer: Some("snowman-review-best".into()),
            },
        }
    }

    #[test]
    fn default_team_is_deterministic_budgeted_and_independently_reviewed() {
        let lease = Lease {
            lease_token: "lease-token".into(),
            lease_generation: 2,
            task: task(),
        };
        let first = build_default_team_plan(&lease, &team()).unwrap();
        let second = build_default_team_plan(&lease, &team()).unwrap();
        assert_eq!(first.plan_id, second.plan_id);
        assert_eq!(first.tasks.len(), 3);
        assert_eq!(
            first.tasks[0].requested_model_id.as_deref(),
            Some("snowman-analysis-best")
        );
        assert_eq!(
            first
                .tasks
                .iter()
                .map(|task| task.max_cost_microusd)
                .sum::<u64>(),
            1_000_000
        );
        let reviewer = &first.tasks[2];
        assert_eq!(reviewer.specialist_role, "quality_risk_reviewer");
        assert!(reviewer.required_capabilities.contains("artifact.review"));
        assert_eq!(reviewer.depends_on.len(), 2);
        assert_ne!(
            reviewer.service_identity_id,
            first.tasks[0].service_identity_id
        );
        assert_ne!(
            reviewer.service_identity_id,
            first.tasks[1].service_identity_id
        );
    }

    #[test]
    fn team_reserves_context_slots_for_dependency_handoffs() {
        let mut value = task();
        value.context_references = (0..62)
            .map(|index| format!("analyst360:sha256:{index:064x}"))
            .collect();
        let lease = Lease {
            lease_token: "lease-token".into(),
            lease_generation: 2,
            task: value,
        };
        assert!(build_default_team_plan(&lease, &team()).is_ok());

        let mut overflow = task();
        overflow.context_references = (0..63)
            .map(|index| format!("analyst360:sha256:{index:064x}"))
            .collect();
        let lease = Lease {
            lease_token: "lease-token".into(),
            lease_generation: 2,
            task: overflow,
        };
        assert!(matches!(
            build_default_team_plan(&lease, &team()),
            Err(Error::RelayContract(_))
        ));
    }

    #[test]
    fn every_specialist_gets_only_an_exact_analyst_capability() {
        let mut value = task();
        value.specialist_role = "governed_analyst".into();
        value.required_capabilities = vec!["analytics.query".into()];
        assert_eq!(
            analyst_capability(&value).unwrap(),
            Capability::AnalyticsQuery
        );
        value.specialist_role = "quality_risk_reviewer".into();
        value.required_capabilities = vec!["artifact.review".into()];
        assert!(analyst_capability(&value).is_err());
        value.required_capabilities.push("artifact.build".into());
        assert_eq!(
            analyst_capability(&value).unwrap(),
            Capability::ArtifactBuild
        );
    }

    #[test]
    fn service_origins_are_snowman_only_and_instruction_is_utf8_bounded() {
        assert!(parse_snowman_origin("https://worker.aptive.snowmanai.org").is_ok());
        assert!(parse_snowman_origin("https://relay.block.xyz").is_err());
        assert!(parse_snowman_origin("https://user@worker.snowmanai.org").is_err());
        let value = bounded_concat("prefix:", &"☃".repeat(2_000), 4_000);
        assert!(value.len() <= 4_000);
        assert!(value.is_char_boundary(value.len()));
    }

    #[test]
    fn deterministic_ids_are_domain_separated() {
        let first = deterministic_uuid("plan", "request");
        assert_eq!(first, deterministic_uuid("plan", "request"));
        assert_ne!(first, deterministic_uuid("completion", "request"));
        assert_eq!(first.get_version_num(), 5);
    }
}
