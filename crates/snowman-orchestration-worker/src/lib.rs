#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Long-running private scheduler and delivery worker for Snowman orchestration.
//!
//! The worker has one tenant/workspace/service identity, a Nostr signing key,
//! and three fixed Snowman-internal HTTPS origins. It owns no database,
//! Analyst, model-provider, tool, AWS, mail, or client-data credential. Every
//! claim and receipt is NIP-98 signed over its exact URL and body. Stable
//! dispatch/outbox coordinates make a lost destination response safe to retry.

use std::{env, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use reqwest::{header, redirect::Policy, Client};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snowman_orchestration_service::{
    ApiReceipt, ControlClaimRequest, ControlCommandKind, ControlDeliveryOutcome,
    ControlDeliveryResultCommand, ControlLease, DeliveryOutcome, DeliveryResultCommand,
    DispatchLease, SchedulerClaimRequest, SchedulerCycleReceipt, SchedulerCycleRequest,
    CLAIM_SCHEMA, CONTROL_CLAIM_SCHEMA, CONTROL_DELIVERY_SCHEMA, DELIVERY_SCHEMA, LIFECYCLE_SCHEMA,
};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const DESTINATION_RECEIPT_SCHEMA: &str = "snowman.orchestration.destination-receipt.v1";
const COORDINATOR_DISPATCH_SCHEMA: &str = "snowman.orchestration.coordinator-dispatch.v1";
const CONTROL_COMMAND_SCHEMA: &str = "snowman.orchestration.control-command.v1";
const FIXED_REMINDER_TEXT: &str =
    "Snowman deadline reminder: governed work is due. Open the Command Center for details.";

/// Non-sensitive worker failures safe for centralized logs.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Static configuration violates the private Snowman boundary.
    #[error("orchestration worker configuration is invalid: {0}")]
    Configuration(&'static str),
    /// NIP-98 signing failed.
    #[error("orchestration worker request signing failed")]
    Signing,
    /// A private transport failed without a durable acceptance response.
    #[error("orchestration worker private transport failed")]
    Transport,
    /// A private service returned a bounded rejection.
    #[error("orchestration worker private service rejected the request with HTTP {0}")]
    Rejected(u16),
    /// A response violated its exact digest-only contract.
    #[error("orchestration worker response contract is invalid: {0}")]
    Contract(&'static str),
}

/// One exact tenant/workspace scheduler and delivery identity.
pub struct Config {
    orchestration_origin: Url,
    coordinator_origin: Url,
    reminder_origin: Url,
    keys: Keys,
    reminder_keys: Keys,
    reminder_channel_id: Uuid,
    tenant_id: Uuid,
    workspace_id: Uuid,
    service_identity_id: Uuid,
    service_principal: String,
    policy_generation: u64,
    interval: Duration,
    request_timeout: Duration,
    max_records: u16,
    lease_seconds: u16,
    submitted_timeout_seconds: u16,
    once: bool,
}

impl Config {
    /// Load a fail-closed worker boundary from environment variables.
    pub fn from_env() -> Result<Self, Error> {
        let interval_seconds = parse_u16("SNOWMAN_ORCHESTRATION_WORKER_INTERVAL_SECONDS", 5, 300)?;
        let request_timeout_seconds = parse_u16(
            "SNOWMAN_ORCHESTRATION_WORKER_REQUEST_TIMEOUT_SECONDS",
            5,
            60,
        )?;
        let lease_seconds = parse_u16("SNOWMAN_ORCHESTRATION_WORKER_LEASE_SECONDS", 30, 900)?;
        if u32::from(request_timeout_seconds) * 2 >= u32::from(lease_seconds) {
            return Err(Error::Configuration(
                "request timeout must leave room to record a lease result",
            ));
        }
        let service_principal = required("SNOWMAN_ORCHESTRATION_WORKER_SERVICE_PRINCIPAL")?;
        if !valid_principal(&service_principal) {
            return Err(Error::Configuration("service principal is invalid"));
        }
        Ok(Self {
            orchestration_origin: parse_private_origin(&required(
                "SNOWMAN_ORCHESTRATION_WORKER_ORIGIN",
            )?)?,
            coordinator_origin: parse_private_origin(&required(
                "SNOWMAN_ORCHESTRATION_COORDINATOR_ORIGIN",
            )?)?,
            reminder_origin: parse_private_origin(&required(
                "SNOWMAN_ORCHESTRATION_REMINDER_ORIGIN",
            )?)?,
            keys: Keys::parse(&required("SNOWMAN_ORCHESTRATION_WORKER_NOSTR_PRIVATE_KEY")?)
                .map_err(|_| Error::Configuration("Nostr private key is invalid"))?,
            reminder_keys: Keys::parse(&required(
                "SNOWMAN_ORCHESTRATION_REMINDER_NOSTR_PRIVATE_KEY",
            )?)
            .map_err(|_| Error::Configuration("reminder Nostr private key is invalid"))?,
            reminder_channel_id: parse_uuid("SNOWMAN_ORCHESTRATION_REMINDER_CHANNEL_ID")?,
            tenant_id: parse_uuid("SNOWMAN_ORCHESTRATION_WORKER_TENANT_ID")?,
            workspace_id: parse_uuid("SNOWMAN_ORCHESTRATION_WORKER_WORKSPACE_ID")?,
            service_identity_id: parse_uuid("SNOWMAN_ORCHESTRATION_WORKER_IDENTITY_ID")?,
            service_principal,
            policy_generation: parse_u64(
                "SNOWMAN_ORCHESTRATION_WORKER_POLICY_GENERATION",
                1,
                i64::MAX as u64,
            )?,
            interval: Duration::from_secs(u64::from(interval_seconds)),
            request_timeout: Duration::from_secs(u64::from(request_timeout_seconds)),
            max_records: parse_u16("SNOWMAN_ORCHESTRATION_WORKER_MAX_RECORDS", 1, 32)?,
            lease_seconds,
            submitted_timeout_seconds: parse_u16(
                "SNOWMAN_ORCHESTRATION_WORKER_SUBMITTED_TIMEOUT_SECONDS",
                30,
                900,
            )?,
            once: env::var("SNOWMAN_ORCHESTRATION_WORKER_ONCE").is_ok_and(|value| value == "true"),
        })
    }
}

/// Long-running scheduler/coordinator/control delivery process.
pub struct Worker {
    orchestration: SignedClient,
    coordinator: SignedClient,
    reminder: SignedClient,
    reminder_channel_id: Uuid,
    tenant_id: Uuid,
    workspace_id: Uuid,
    service_identity_id: Uuid,
    service_principal: String,
    policy_generation: u64,
    interval: Duration,
    max_records: u16,
    lease_seconds: u16,
    submitted_timeout_seconds: u16,
    once: bool,
}

impl Worker {
    /// Construct three no-proxy, no-redirect, HTTPS-only private clients.
    pub fn new(config: Config) -> Result<Self, Error> {
        Ok(Self {
            orchestration: SignedClient::new(
                config.orchestration_origin,
                config.keys.clone(),
                config.request_timeout,
            )?,
            coordinator: SignedClient::new(
                config.coordinator_origin,
                config.keys.clone(),
                config.request_timeout,
            )?,
            reminder: SignedClient::new(
                config.reminder_origin,
                config.reminder_keys,
                config.request_timeout,
            )?,
            reminder_channel_id: config.reminder_channel_id,
            tenant_id: config.tenant_id,
            workspace_id: config.workspace_id,
            service_identity_id: config.service_identity_id,
            service_principal: config.service_principal,
            policy_generation: config.policy_generation,
            interval: config.interval,
            max_records: config.max_records,
            lease_seconds: config.lease_seconds,
            submitted_timeout_seconds: config.submitted_timeout_seconds,
            once: config.once,
        })
    }

    /// Run bounded cycles until graceful shutdown. Shutdown stops new claims;
    /// the current bounded cycle finishes so its destination result can be
    /// durably recorded before the process exits.
    pub async fn run(self, shutdown: CancellationToken) {
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut expected_tick = tokio::time::Instant::now();
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {}
            }
            let now = tokio::time::Instant::now();
            let scheduler_lag_seconds = now
                .checked_duration_since(expected_tick)
                .unwrap_or_default()
                .as_secs();
            expected_tick = now + self.interval;
            if let Err(error) = self.run_cycle(scheduler_lag_seconds).await {
                tracing::error!(
                    error_class = error_class(&error),
                    "orchestration worker cycle failed"
                );
            }
            if self.once {
                break;
            }
        }
        tracing::info!("orchestration worker shutdown complete");
    }

    async fn run_cycle(&self, scheduler_lag_seconds: u64) -> Result<(), Error> {
        let cycle_path = self.scoped_path("scheduler/cycle");
        let cycle_request = SchedulerCycleRequest {
            schema_version: LIFECYCLE_SCHEMA.into(),
            request_id: Uuid::new_v4(),
            service_identity_id: self.service_identity_id,
            service_principal: self.service_principal.clone(),
            policy_generation: self.policy_generation,
            max_records: self.max_records,
            submitted_timeout_seconds: self.submitted_timeout_seconds,
        };
        let cycle: SchedulerCycleReceipt = self
            .orchestration
            .post_json(&cycle_path, &cycle_request)
            .await?;
        if cycle.request_id != cycle_request.request_id {
            return Err(Error::Contract(
                "scheduler receipt request binding is invalid",
            ));
        }
        tracing::info!(
            metric = "snowman_orchestration_cycle",
            scheduler_lag_seconds,
            recurrences_processed = cycle.recurrences_processed,
            occurrences_materialized = cycle.occurrences_materialized,
            dispatches_recovered = cycle.dispatches_recovered,
            dead_letter_count = cycle.dispatches_dead_lettered,
            reminders_enqueued = cycle.reminders_enqueued,
            "orchestration scheduler cycle committed"
        );
        self.deliver_dispatches().await?;
        self.deliver_controls().await?;
        Ok(())
    }

    async fn deliver_dispatches(&self) -> Result<(), Error> {
        let claim_path = self.scoped_path("scheduler/claims");
        let request = SchedulerClaimRequest {
            schema_version: CLAIM_SCHEMA.into(),
            request_id: Uuid::new_v4(),
            service_identity_id: self.service_identity_id,
            service_principal: self.service_principal.clone(),
            policy_generation: self.policy_generation,
            max_claims: self.max_records,
            lease_seconds: self.lease_seconds,
        };
        let leases: Vec<DispatchLease> =
            self.orchestration.post_json(&claim_path, &request).await?;
        let reserved_cost_microusd = leases.iter().fold(0_u64, |sum, lease| {
            sum.saturating_add(lease.reserved_cost_microusd)
        });
        tracing::info!(
            metric = "snowman_orchestration_dispatch_claim",
            claimed_dispatches = leases.len(),
            reserved_cost_microusd,
            "orchestration dispatch batch claimed"
        );
        for lease in leases {
            self.deliver_dispatch(&lease).await?;
        }
        Ok(())
    }

    async fn deliver_dispatch(&self, lease: &DispatchLease) -> Result<(), Error> {
        let destination_path = format!(
            "/v1/tenants/{}/workspaces/{}/orchestration/dispatches/{}",
            self.tenant_id, self.workspace_id, lease.dispatch_id
        );
        let envelope = CoordinatorDispatchEnvelope {
            schema_version: COORDINATOR_DISPATCH_SCHEMA.into(),
            community_id: self.tenant_id,
            workspace_id: self.workspace_id,
            dispatch_id: lease.dispatch_id,
            plan_id: lease.plan_id,
            plan_generation: lease.plan_generation,
            task_id: lease.task_id,
            request_id: lease.request_id,
            execution_snapshot_sha256: lease.execution_snapshot_sha256.clone(),
            model_id: lease.model_id.clone(),
            specialist_role: lease.specialist_role.clone(),
            classification: lease.classification,
            lease_generation: lease.lease_generation,
            cancellation_generation: lease.cancellation_generation,
            coordinator_job_reference: lease.coordinator_job_reference.clone(),
            model_route_reference: lease.model_route_reference.clone(),
            analyst_context_references: lease.analyst_context_references.clone(),
            required_capabilities: lease.required_capabilities.clone(),
            reserved_cost_microusd: lease.reserved_cost_microusd,
            deadline_at: lease.deadline_at,
            lease_expires_at: lease.lease_expires_at,
        };
        let result = self
            .coordinator
            .post_json::<DestinationReceipt, _>(&destination_path, &envelope)
            .await;
        let command = match result {
            Ok(receipt) => {
                validate_destination_receipt(
                    &receipt,
                    &lease.coordinator_job_reference,
                    lease.dispatch_id,
                )?;
                DeliveryResultCommand {
                    schema_version: DELIVERY_SCHEMA.into(),
                    service_identity_id: self.service_identity_id,
                    service_principal: self.service_principal.clone(),
                    policy_generation: self.policy_generation,
                    lease_generation: lease.lease_generation,
                    cancellation_generation: lease.cancellation_generation,
                    outcome: DeliveryOutcome::Submitted,
                    coordinator_receipt_reference: Some(receipt.delivery_reference),
                    response_sha256: Some(receipt.response_sha256),
                    failure_sha256: None,
                    retry_after_seconds: None,
                }
            }
            Err(error) => DeliveryResultCommand {
                schema_version: DELIVERY_SCHEMA.into(),
                service_identity_id: self.service_identity_id,
                service_principal: self.service_principal.clone(),
                policy_generation: self.policy_generation,
                lease_generation: lease.lease_generation,
                cancellation_generation: lease.cancellation_generation,
                outcome: DeliveryOutcome::RetryableFailure,
                coordinator_receipt_reference: None,
                response_sha256: None,
                failure_sha256: Some(failure_digest(&error)),
                retry_after_seconds: Some(30),
            },
        };
        let delivery_path = self.scoped_path(&format!("dispatches/{}/delivery", lease.dispatch_id));
        let receipt: ApiReceipt = self
            .orchestration
            .post_json(&delivery_path, &command)
            .await?;
        if receipt.command_id != lease.dispatch_id
            || receipt.community_id != self.tenant_id
            || receipt.workspace_id != self.workspace_id
            || receipt.plan_id != lease.plan_id
            || receipt.plan_generation != lease.plan_generation
        {
            return Err(Error::Contract(
                "dispatch delivery receipt binding is invalid",
            ));
        }
        tracing::info!(
            metric = "snowman_orchestration_dispatch_delivery",
            dispatch_id = %lease.dispatch_id,
            status = %receipt.status,
            reserved_cost_microusd = lease.reserved_cost_microusd,
            "orchestration dispatch delivery recorded"
        );
        Ok(())
    }

    async fn deliver_controls(&self) -> Result<(), Error> {
        let claim_path = self.scoped_path("scheduler/control-claims");
        let request = ControlClaimRequest {
            schema_version: CONTROL_CLAIM_SCHEMA.into(),
            request_id: Uuid::new_v4(),
            service_identity_id: self.service_identity_id,
            service_principal: self.service_principal.clone(),
            policy_generation: self.policy_generation,
            command_kinds: [
                ControlCommandKind::CancelDispatch,
                ControlCommandKind::DeliverReminder,
            ]
            .into_iter()
            .collect(),
            max_claims: self.max_records,
            lease_seconds: self.lease_seconds,
        };
        let leases: Vec<ControlLease> = self.orchestration.post_json(&claim_path, &request).await?;
        tracing::info!(
            metric = "snowman_orchestration_control_claim",
            claimed_controls = leases.len(),
            "orchestration control batch claimed"
        );
        for lease in leases {
            self.deliver_control(&lease).await?;
        }
        Ok(())
    }

    async fn deliver_control(&self, lease: &ControlLease) -> Result<(), Error> {
        if lease.community_id != self.tenant_id || lease.workspace_id != self.workspace_id {
            return Err(Error::Contract("control lease scope is invalid"));
        }
        let destination = ControlDestinationCommand {
            schema_version: CONTROL_COMMAND_SCHEMA.into(),
            community_id: lease.community_id,
            workspace_id: lease.workspace_id,
            outbox_id: lease.outbox_id,
            command_kind: lease.command_kind,
            plan_id: lease.plan_id,
            plan_generation: lease.plan_generation,
            dispatch_id: lease.dispatch_id,
            occurrence_id: lease.occurrence_id,
            command_sha256: lease.command_sha256.clone(),
            coordinator_job_reference: lease.coordinator_job_reference.clone(),
            lease_generation: lease.lease_generation,
            lease_expires_at: lease.lease_expires_at,
        };
        let result = match lease.command_kind {
            ControlCommandKind::CancelDispatch => {
                let expected_reference =
                    lease
                        .coordinator_job_reference
                        .clone()
                        .ok_or(Error::Contract(
                            "cancellation has no coordinator job reference",
                        ))?;
                let destination_path = format!(
                    "/v1/tenants/{}/workspaces/{}/orchestration/cancellations/{}",
                    self.tenant_id, self.workspace_id, lease.outbox_id
                );
                let receipt = self
                    .coordinator
                    .post_json::<DestinationReceipt, _>(&destination_path, &destination)
                    .await?;
                validate_destination_receipt(&receipt, &expected_reference, lease.outbox_id)?;
                Ok(receipt)
            }
            ControlCommandKind::DeliverReminder => self.deliver_reminder(lease).await,
        };
        let command = match result {
            Ok(receipt) => ControlDeliveryResultCommand {
                schema_version: CONTROL_DELIVERY_SCHEMA.into(),
                service_identity_id: self.service_identity_id,
                service_principal: self.service_principal.clone(),
                policy_generation: self.policy_generation,
                lease_generation: lease.lease_generation,
                command_sha256: lease.command_sha256.clone(),
                outcome: ControlDeliveryOutcome::Delivered,
                delivery_reference: Some(receipt.delivery_reference),
                response_sha256: Some(receipt.response_sha256),
                failure_sha256: None,
                retry_after_seconds: None,
            },
            Err(error) => ControlDeliveryResultCommand {
                schema_version: CONTROL_DELIVERY_SCHEMA.into(),
                service_identity_id: self.service_identity_id,
                service_principal: self.service_principal.clone(),
                policy_generation: self.policy_generation,
                lease_generation: lease.lease_generation,
                command_sha256: lease.command_sha256.clone(),
                outcome: ControlDeliveryOutcome::RetryableFailure,
                delivery_reference: None,
                response_sha256: None,
                failure_sha256: Some(failure_digest(&error)),
                retry_after_seconds: Some(30),
            },
        };
        let delivery_path = self.scoped_path(&format!("control/{}/delivery", lease.outbox_id));
        let receipt: ApiReceipt = self
            .orchestration
            .post_json(&delivery_path, &command)
            .await?;
        if receipt.command_id != lease.outbox_id
            || receipt.community_id != lease.community_id
            || receipt.workspace_id != lease.workspace_id
            || receipt.plan_id != lease.plan_id
            || receipt.plan_generation != lease.plan_generation
        {
            return Err(Error::Contract(
                "control delivery receipt binding is invalid",
            ));
        }
        tracing::info!(
            metric = "snowman_orchestration_control_delivery",
            outbox_id = %lease.outbox_id,
            command_kind = lease.command_kind.as_str(),
            status = %receipt.status,
            dead_letter_count = u8::from(receipt.status == "dead_letter"),
            "orchestration control delivery recorded"
        );
        Ok(())
    }

    async fn deliver_reminder(&self, lease: &ControlLease) -> Result<DestinationReceipt, Error> {
        let channel = self.reminder_channel_id.to_string();
        let plan = lease.plan_id.to_string();
        let occurrence = lease.occurrence_id.to_string();
        let delivery = lease.outbox_id.to_string();
        let created_at = u64::try_from(lease.command_created_at.timestamp())
            .map_err(|_| Error::Contract("reminder creation time is invalid"))?;
        let event = EventBuilder::new(Kind::Custom(9), FIXED_REMINDER_TEXT)
            .tags([
                Tag::parse(["h", channel.as_str()]).map_err(|_| Error::Signing)?,
                Tag::parse(["snowman-plan", plan.as_str()]).map_err(|_| Error::Signing)?,
                Tag::parse(["snowman-occurrence", occurrence.as_str()])
                    .map_err(|_| Error::Signing)?,
                Tag::parse(["snowman-delivery", delivery.as_str()]).map_err(|_| Error::Signing)?,
                Tag::parse(["snowman-command-sha256", lease.command_sha256.as_str()])
                    .map_err(|_| Error::Signing)?,
            ])
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(&self.reminder.keys)
            .map_err(|_| Error::Signing)?;
        let event_id = event.id.to_hex();
        let relay: RelayEventReceipt = self.reminder.post_json("/events", &event).await?;
        if !relay.accepted || relay.event_id != event_id {
            return Err(Error::Contract("reminder relay receipt is invalid"));
        }
        let delivery_reference = format!("snowman:reminder-delivery:{}", lease.outbox_id);
        let mut hasher = Sha256::new();
        hasher.update(b"snowman.orchestration.reminder-receipt.v1\0");
        hasher.update(event_id.as_bytes());
        hasher.update(delivery_reference.as_bytes());
        Ok(DestinationReceipt {
            schema_version: DESTINATION_RECEIPT_SCHEMA.into(),
            request_id: lease.outbox_id,
            delivery_reference,
            response_sha256: hex::encode(hasher.finalize()),
        })
    }

    fn scoped_path(&self, suffix: &str) -> String {
        format!(
            "/v1/tenants/{}/workspaces/{}/{}",
            self.tenant_id, self.workspace_id, suffix
        )
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CoordinatorDispatchEnvelope {
    schema_version: String,
    community_id: Uuid,
    workspace_id: Uuid,
    dispatch_id: Uuid,
    plan_id: Uuid,
    plan_generation: u64,
    task_id: Uuid,
    request_id: Uuid,
    execution_snapshot_sha256: String,
    model_id: String,
    specialist_role: String,
    classification: snowman_orchestration::Classification,
    lease_generation: u64,
    cancellation_generation: u64,
    coordinator_job_reference: String,
    model_route_reference: String,
    analyst_context_references: Vec<String>,
    required_capabilities: Vec<String>,
    reserved_cost_microusd: u64,
    deadline_at: chrono::DateTime<Utc>,
    lease_expires_at: chrono::DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ControlDestinationCommand {
    schema_version: String,
    community_id: Uuid,
    workspace_id: Uuid,
    outbox_id: Uuid,
    command_kind: ControlCommandKind,
    plan_id: Uuid,
    plan_generation: u64,
    dispatch_id: Option<Uuid>,
    occurrence_id: Uuid,
    command_sha256: String,
    coordinator_job_reference: Option<String>,
    lease_generation: u64,
    lease_expires_at: chrono::DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DestinationReceipt {
    schema_version: String,
    request_id: Uuid,
    delivery_reference: String,
    response_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayEventReceipt {
    event_id: String,
    accepted: bool,
    #[serde(rename = "message")]
    _message: String,
}

fn validate_destination_receipt(
    receipt: &DestinationReceipt,
    expected_reference: &str,
    expected_request_id: Uuid,
) -> Result<(), Error> {
    if receipt.schema_version != DESTINATION_RECEIPT_SCHEMA
        || receipt.request_id != expected_request_id
        || receipt.delivery_reference != expected_reference
        || !valid_sha256(&receipt.response_sha256)
    {
        return Err(Error::Contract("destination receipt binding is invalid"));
    }
    Ok(())
}

struct SignedClient {
    origin: Url,
    keys: Keys,
    http: Client,
}

impl SignedClient {
    fn new(origin: Url, keys: Keys, timeout: Duration) -> Result<Self, Error> {
        let http = Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(5).min(timeout))
            .redirect(Policy::none())
            .no_proxy()
            .https_only(true)
            .build()
            .map_err(|_| Error::Configuration("HTTP client could not be built"))?;
        Ok(Self { origin, keys, http })
    }

    async fn post_json<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, Error> {
        let bytes = serde_json::to_vec(body).map_err(|_| Error::Contract("request JSON failed"))?;
        let url = self.url(path)?;
        let auth = sign_nip98(&self.keys, url.as_str(), &bytes)?;
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

    fn url(&self, path: &str) -> Result<Url, Error> {
        if !path.starts_with('/') || path.contains('?') || path.contains('#') {
            return Err(Error::Configuration("private service path is invalid"));
        }
        self.origin
            .join(path)
            .map_err(|_| Error::Configuration("private service URL could not be built"))
    }
}

fn sign_nip98(keys: &Keys, url: &str, body: &[u8]) -> Result<String, Error> {
    let payload = hex::encode(Sha256::digest(body));
    let event = EventBuilder::new(Kind::Custom(27235), "")
        .tags([
            Tag::parse(["u", url]).map_err(|_| Error::Signing)?,
            Tag::parse(["method", "POST"]).map_err(|_| Error::Signing)?,
            Tag::parse(["payload", &payload]).map_err(|_| Error::Signing)?,
            Tag::parse(["nonce", &Uuid::new_v4().to_string()]).map_err(|_| Error::Signing)?,
        ])
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
        return Err(Error::Rejected(status.as_u16()));
    }
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("");
    if content_type != "application/json" {
        return Err(Error::Contract("response content type is invalid"));
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Transport)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(Error::Contract("response exceeds 512 KiB"));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| Error::Contract("response JSON is invalid"))
}

fn failure_digest(error: &Error) -> String {
    let class = error_class(error);
    hex::encode(Sha256::digest(
        format!("snowman.orchestration.delivery-failure.v1\0{class}").as_bytes(),
    ))
}

fn error_class(error: &Error) -> &'static str {
    match error {
        Error::Configuration(_) => "configuration",
        Error::Signing => "signing",
        Error::Transport => "transport",
        Error::Rejected(_) => "rejected",
        Error::Contract(_) => "contract",
    }
}

fn parse_private_origin(value: &str) -> Result<Url, Error> {
    let url = Url::parse(value).map_err(|_| Error::Configuration("service origin is invalid"))?;
    let host = url.host_str().unwrap_or("");
    if value != value.to_ascii_lowercase()
        || url.scheme() != "https"
        || !(host == "internal.snowmanai.org" || host.ends_with(".internal.snowmanai.org"))
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::Configuration(
            "service origin must be exact private Snowman HTTPS",
        ));
    }
    Ok(url)
}

fn valid_principal(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.starts_with("snowman:")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn required(name: &'static str) -> Result<String, Error> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(Error::Configuration(name))
}

fn parse_uuid(name: &'static str) -> Result<Uuid, Error> {
    let value = Uuid::parse_str(&required(name)?)
        .map_err(|_| Error::Configuration("UUID setting is invalid"))?;
    if value.is_nil() {
        return Err(Error::Configuration("UUID setting is nil"));
    }
    Ok(value)
}

fn parse_u16(name: &'static str, minimum: u16, maximum: u16) -> Result<u16, Error> {
    let value = required(name)?
        .parse::<u16>()
        .map_err(|_| Error::Configuration("numeric setting is invalid"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(Error::Configuration("numeric setting is out of bounds"));
    }
    Ok(value)
}

fn parse_u64(name: &'static str, minimum: u64, maximum: u64) -> Result<u64, Error> {
    let value = required(name)?
        .parse::<u64>()
        .map_err(|_| Error::Configuration("numeric setting is invalid"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(Error::Configuration("numeric setting is out of bounds"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_origins_reject_block_public_and_lookalike_hosts() {
        assert!(
            parse_private_origin("https://orchestration.staging.internal.snowmanai.org/").is_ok()
        );
        let block_origin = format!("https://{}.xyz/", "block");
        for denied in [
            block_origin.as_str(),
            "https://api.openai.com/",
            "https://internal.snowmanai.org.attacker.test/",
            "http://orchestration.internal.snowmanai.org/",
            "https://orchestration.internal.snowmanai.org/path",
        ] {
            assert!(parse_private_origin(denied).is_err(), "{denied}");
        }
    }

    #[test]
    fn destination_receipt_is_exactly_request_and_reference_bound() {
        let request_id = Uuid::new_v4();
        let reference = format!("snowman:agent-job:{request_id}:generation:1");
        let mut receipt = DestinationReceipt {
            schema_version: DESTINATION_RECEIPT_SCHEMA.into(),
            request_id,
            delivery_reference: reference.clone(),
            response_sha256: hex::encode([7_u8; 32]),
        };
        assert!(validate_destination_receipt(&receipt, &reference, request_id).is_ok());
        receipt.request_id = Uuid::new_v4();
        assert!(validate_destination_receipt(&receipt, &reference, request_id).is_err());
    }

    #[test]
    fn retry_failure_digest_is_stable_and_content_free() {
        let first = failure_digest(&Error::Transport);
        let second = failure_digest(&Error::Transport);
        assert_eq!(first, second);
        assert!(valid_sha256(&first));
        assert_ne!(first, failure_digest(&Error::Rejected(503)));
    }

    #[test]
    fn control_destination_contract_carries_no_message_or_provider_body() {
        let source = include_str!("lib.rs");
        let start = source
            .find("struct ControlDestinationCommand")
            .expect("contract");
        let tail = &source[start..];
        let end = tail.find("\n}\n").expect("contract end");
        let contract = &tail[..end];
        for prohibited in ["message", "prompt", "transcript", "provider", "api_key"] {
            assert!(!contract.contains(prohibited), "{prohibited}");
        }
    }

    #[test]
    fn reminder_content_is_fixed_and_contains_no_work_coordinates() {
        assert_eq!(
            FIXED_REMINDER_TEXT,
            "Snowman deadline reminder: governed work is due. Open the Command Center for details."
        );
        for prohibited in ["client", "provider", "transcript", "email", "prompt"] {
            assert!(!FIXED_REMINDER_TEXT
                .to_ascii_lowercase()
                .contains(prohibited));
        }
    }
}
