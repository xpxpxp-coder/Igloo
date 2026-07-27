#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Provider-neutral authority and lifecycle contracts for governed live media.
//!
//! This crate performs no network I/O and deliberately contains no provider
//! credential or raw-coordinate fields. A deployed adapter may resolve an
//! opaque Snowman seal only after this boundary returns a provider plan. Audio
//! frames are borrowed and non-serializable; durable outputs are digests,
//! bounded usage, and Analyst-owned evidence references.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snowman_meeting_control::{
    ConferenceKind, DataClass, MeetingToolIntentEnvelope, RetentionMode, ScheduleStatus,
    ScheduledMeeting, SpeechOutputRoute, VoiceRoute,
};
use uuid::Uuid;

/// Executable, transport-injected provider adapters for governed live media.
pub mod adapters;
/// Private server, transactional repository, and separately authenticated
/// provider-ingress boundaries.
pub mod server;

/// Contract schema for a join command.
pub const JOIN_SCHEMA: &str = "snowman.meeting-media.join.v1";
/// Contract schema for a leave/cancel command.
pub const STOP_SCHEMA: &str = "snowman.meeting-media.stop.v1";
/// Contract schema for provider webhook receipts.
pub const WEBHOOK_RECEIPT_SCHEMA: &str = "snowman.meeting-media.webhook-receipt.v1";
/// Contract schema for provider usage receipts.
pub const USAGE_RECEIPT_SCHEMA: &str = "snowman.meeting-media.usage-receipt.v1";

const SHA256_HEX_LEN: usize = 64;
const MAX_AUDIO_FRAME_BYTES: usize = 1024 * 1024;
const MAX_RENDER_TEXT_BYTES: usize = 4096;
const MAX_WEBHOOK_BODY_BYTES: usize = 256 * 1024;
const MAX_WEBHOOK_AGE: Duration = Duration::minutes(5);
const MAX_SESSION_DURATION: Duration = Duration::hours(12);

/// Fail-closed media authority error.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// A bounded field, digest, or schema is malformed.
    #[error("meeting media field is invalid: {0}")]
    InvalidField(&'static str),
    /// A tenant, workspace, meeting, identity, revision, or fence mismatched.
    #[error("meeting media authority boundary mismatch")]
    BoundaryMismatch,
    /// Provider activation remains disabled or the route is not allowlisted.
    #[error("meeting media provider is not enabled")]
    ProviderDisabled,
    /// Consent or the active meeting-control state is absent.
    #[error("meeting media consent is incomplete")]
    ConsentIncomplete,
    /// A command replayed with different content.
    #[error("meeting media idempotency key conflicts")]
    IdempotencyConflict,
    /// A stale generation or invalid lifecycle transition was requested.
    #[error("meeting media lifecycle transition is invalid")]
    InvalidTransition,
    /// The current duration, event, or cost budget was exhausted.
    #[error("meeting media budget or deadline is exhausted")]
    BudgetExceeded,
    /// A provider callback was unauthenticated, stale, or replayed inconsistently.
    #[error("meeting media provider callback is not authentic")]
    WebhookAuthentication,
    /// Raw speech attempted to grant authority or address a provider target.
    #[error("meeting audio and transcript content cannot grant authority")]
    UntrustedAuthority,
}

/// Provider families understood by the policy gateway.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Native Snowman huddle transport inside the Snowman boundary.
    SnowmanHuddle,
    /// Snowman AWS speech/media runtime.
    SnowmanAws,
    /// Snowman-owned Twilio account or subaccount.
    Twilio,
    /// OpenAI Realtime server-to-server route.
    OpenAiRealtime,
    /// Optional output-only ElevenLabs text-to-speech route.
    ElevenLabs,
}

/// Exact provider-independent ingress route selected by trusted admission.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IngressRoute {
    /// Audio from an existing native Snowman huddle.
    SnowmanHuddle,
    /// Audio from a Snowman-owned Twilio Media Stream or SIP trunk.
    TwilioTelephony,
}

/// Exact live conversational processor.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationRoute {
    /// Snowman AWS-controlled inference.
    SnowmanAws,
    /// OpenAI Realtime over a server-side Snowman adapter.
    OpenAiRealtime,
}

/// Exact speech renderer.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RendererRoute {
    /// Renderer native to the chosen conversational route.
    ConversationNative,
    /// Snowman AWS-controlled renderer.
    SnowmanAws,
    /// Optional output-only ElevenLabs text-to-speech.
    ElevenLabs,
}

/// Operations-owned route registration. Its safe default is disabled.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayPolicy {
    /// Exact tenant.
    pub tenant_id: Uuid,
    /// Exact workspace.
    pub workspace_id: Uuid,
    /// Dedicated mailbox/calendar identity.
    pub mailbox_identity_id: Uuid,
    /// Dedicated media-gateway service identity.
    pub gateway_service_identity_id: Uuid,
    /// Whether any provider may activate for this registration.
    pub activation_enabled: bool,
    /// Explicit provider allowlist.
    pub allowed_providers: BTreeSet<Provider>,
    /// Digest of the exact Snowman provider account/project registrations.
    pub provider_binding_sha256: String,
    /// Operations policy receipt.
    pub policy_evidence_sha256: String,
    /// Per-session ceiling, no larger than admission.
    pub max_session_cost_microusd: u64,
    /// Per-session duration, no larger than admission.
    pub max_session_duration_seconds: u32,
    /// Exact number of concurrent sessions allowed for this registration.
    pub max_concurrent_sessions: u16,
}

impl GatewayPolicy {
    fn validate(&self) -> Result<(), Error> {
        validate_digest(&self.provider_binding_sha256, "provider binding")?;
        validate_digest(&self.policy_evidence_sha256, "gateway policy evidence")?;
        if self.mailbox_identity_id == self.gateway_service_identity_id
            || self.max_session_cost_microusd == 0
            || self.max_session_cost_microusd > 1_000_000_000
            || self.max_session_duration_seconds == 0
            || self.max_session_duration_seconds > MAX_SESSION_DURATION.num_seconds() as u32
            || self.max_concurrent_sessions == 0
            || self.max_concurrent_sessions > 1000
        {
            return Err(Error::InvalidField("gateway policy limits or identities"));
        }
        if !self.activation_enabled && !self.allowed_providers.is_empty() {
            return Err(Error::InvalidField("disabled policy provider allowlist"));
        }
        Ok(())
    }
}

/// Exact, consent-complete execution authority derived from meeting control.
///
/// It can only be constructed from a currently active [`ScheduledMeeting`], so
/// calendar text, email, provider callbacks, and model output cannot mint it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaExecutionGrant {
    tenant_id: Uuid,
    workspace_id: Uuid,
    meeting_id: Uuid,
    mailbox_identity_id: Uuid,
    meeting_agent_identity_id: Uuid,
    provider_event_id_sha256: String,
    provider_revision: u64,
    schedule_revision: u64,
    session_id: Uuid,
    session_generation: u32,
    data_class: DataClass,
    conference_kind: ConferenceKind,
    sealed_coordinate_ref: String,
    conference_approval_sha256: String,
    ingress_route: IngressRoute,
    conversation_route: ConversationRoute,
    renderer_route: RendererRoute,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    join_not_before: DateTime<Utc>,
    join_not_after: DateTime<Utc>,
    max_cost_microusd: u64,
    max_duration_seconds: u32,
    raw_audio_retention: RetentionMode,
    transcript_retention: RetentionMode,
    admission_evidence_sha256: String,
    consent_evidence_sha256: String,
}

impl MediaExecutionGrant {
    /// Derive one fenced media grant from active meeting-control state.
    pub fn from_active_meeting(
        meeting: &ScheduledMeeting,
        session_id: Uuid,
        consent_evidence_sha256: String,
    ) -> Result<Self, Error> {
        if meeting.status() != ScheduleStatus::Active || meeting.session_generation() == 0 {
            return Err(Error::ConsentIncomplete);
        }
        let admission = meeting.admission();
        admission.validate().map_err(|_| Error::BoundaryMismatch)?;
        validate_digest(&consent_evidence_sha256, "consent evidence")?;
        let ingress_route = match admission.conference.kind {
            ConferenceKind::SnowmanHuddle => IngressRoute::SnowmanHuddle,
            ConferenceKind::Telephony => IngressRoute::TwilioTelephony,
            // A Google Meet URL is not a phone/SIP coordinate. A future
            // browser/WebRTC adapter needs its own separately admitted route.
            ConferenceKind::GoogleMeet => return Err(Error::ProviderDisabled),
        };
        let conversation_route = match admission.processing.voice_route {
            VoiceRoute::SnowmanAws => ConversationRoute::SnowmanAws,
            VoiceRoute::OpenAiRealtime => ConversationRoute::OpenAiRealtime,
            VoiceRoute::Disabled => return Err(Error::ProviderDisabled),
        };
        let renderer_route = match admission.processing.speech_output_route {
            SpeechOutputRoute::VoiceRoute => RendererRoute::ConversationNative,
            SpeechOutputRoute::SnowmanAws => RendererRoute::SnowmanAws,
            SpeechOutputRoute::ElevenLabs => RendererRoute::ElevenLabs,
        };
        Ok(Self {
            tenant_id: admission.tenant_id,
            workspace_id: admission.workspace_id,
            meeting_id: admission.meeting_id,
            mailbox_identity_id: admission.mailbox_identity_id,
            meeting_agent_identity_id: admission.meeting_agent_identity_id,
            provider_event_id_sha256: admission.provider_event_id_sha256.clone(),
            provider_revision: admission.provider_revision,
            schedule_revision: meeting.schedule_revision(),
            session_id,
            session_generation: meeting.session_generation(),
            data_class: admission.data_class,
            conference_kind: admission.conference.kind,
            sealed_coordinate_ref: admission.conference.sealed_coordinate_ref.clone(),
            conference_approval_sha256: admission.conference.approval_evidence_sha256.clone(),
            ingress_route,
            conversation_route,
            renderer_route,
            starts_at: admission.starts_at,
            ends_at: admission.ends_at,
            join_not_before: admission.join_not_before,
            join_not_after: admission.join_not_after,
            max_cost_microusd: admission.processing.max_cost_microusd,
            max_duration_seconds: admission.processing.max_duration_seconds,
            raw_audio_retention: admission.consent.raw_audio_retention,
            transcript_retention: admission.consent.transcript_retention,
            admission_evidence_sha256: admission.admission_evidence_sha256.clone(),
            consent_evidence_sha256,
        })
    }

    fn required_providers(&self) -> BTreeSet<Provider> {
        let mut providers = self.required_session_providers();
        match self.renderer_route {
            RendererRoute::ConversationNative => {}
            RendererRoute::SnowmanAws => {
                providers.insert(Provider::SnowmanAws);
            }
            RendererRoute::ElevenLabs => {
                providers.insert(Provider::ElevenLabs);
            }
        }
        providers
    }

    fn required_session_providers(&self) -> BTreeSet<Provider> {
        let mut providers = BTreeSet::new();
        providers.insert(match self.ingress_route {
            IngressRoute::SnowmanHuddle => Provider::SnowmanHuddle,
            IngressRoute::TwilioTelephony => Provider::Twilio,
        });
        providers.insert(match self.conversation_route {
            ConversationRoute::SnowmanAws => Provider::SnowmanAws,
            ConversationRoute::OpenAiRealtime => Provider::OpenAiRealtime,
        });
        providers
    }
}

/// A target-free, idempotent request to join the exact admitted meeting.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JoinCommand {
    /// Exact schema.
    pub schema_version: String,
    /// Idempotency key.
    pub command_id: Uuid,
    /// Exact tenant.
    pub tenant_id: Uuid,
    /// Exact workspace.
    pub workspace_id: Uuid,
    /// Exact meeting.
    pub meeting_id: Uuid,
    /// Exact session.
    pub session_id: Uuid,
    /// Exact meeting-control fence.
    pub session_generation: u32,
    /// Exact admitted calendar revision.
    pub provider_revision: u64,
    /// Dedicated mailbox identity.
    pub mailbox_identity_id: Uuid,
    /// Dedicated meeting agent identity.
    pub meeting_agent_identity_id: Uuid,
    /// Dedicated media gateway service identity.
    pub gateway_service_identity_id: Uuid,
    /// Digest of the trusted command issuer receipt.
    pub issuer_evidence_sha256: String,
    /// Deadline for resolving and establishing the route.
    pub deadline: DateTime<Utc>,
}

impl JoinCommand {
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != JOIN_SCHEMA
            || self.session_generation == 0
            || self.provider_revision == 0
        {
            return Err(Error::InvalidField("join schema or revision"));
        }
        validate_digest(&self.issuer_evidence_sha256, "join issuer evidence")
    }
}

/// Target-free, provider-neutral plan released only after all authority checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPlan {
    /// Exact session.
    pub session_id: Uuid,
    /// Exact session fence.
    pub session_generation: u32,
    /// Ingress adapter.
    pub ingress_route: IngressRoute,
    /// Conversational processor adapter.
    pub conversation_route: ConversationRoute,
    /// Speech renderer adapter.
    pub renderer_route: RendererRoute,
    /// Opaque seal resolvable only by the selected trusted adapter.
    pub sealed_coordinate_ref: String,
    /// Digest of the trusted resolver approval.
    pub conference_approval_sha256: String,
    /// Hard session deadline.
    pub deadline: DateTime<Utc>,
    /// Hard duration ceiling.
    pub max_duration_seconds: u32,
    /// Hard spend ceiling.
    pub max_cost_microusd: u64,
}

/// Media session lifecycle.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Join plan released; provider establishment is pending.
    Joining,
    /// Provider execution may have crossed the network boundary but no final
    /// receipt is durable; exact replay cannot invoke it again.
    Indeterminate,
    /// Provider session is active.
    Active,
    /// Cancellation, budget, or deadline teardown is pending.
    Stopping,
    /// Provider session is conclusively stopped.
    Stopped,
    /// Provider establishment or execution failed.
    Failed,
}

/// Durable, PII-minimized media session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaSession {
    grant: MediaExecutionGrant,
    gateway_service_identity_id: Uuid,
    provider_binding_sha256: String,
    status: SessionStatus,
    provider_session_ids_sha256: BTreeMap<Provider, String>,
    spent_microusd: u64,
    cost_ceiling_microusd: u64,
    started_at: DateTime<Utc>,
    deadline: DateTime<Utc>,
    stopped_at: Option<DateTime<Utc>>,
    last_receipt_sha256: String,
}

impl MediaSession {
    /// Current lifecycle status.
    pub fn status(&self) -> SessionStatus {
        self.status
    }

    /// Exact media session identifier.
    pub fn session_id(&self) -> Uuid {
        self.grant.session_id
    }

    /// Exact session generation.
    pub fn session_generation(&self) -> u32 {
        self.grant.session_generation
    }

    /// Cumulative provider spend in micro-USD.
    pub fn spent_microusd(&self) -> u64 {
        self.spent_microusd
    }

    /// Pseudonymous provider-session digest for an established adapter leg.
    pub fn provider_session_id_sha256(&self, provider: Provider) -> Option<&str> {
        self.provider_session_ids_sha256
            .get(&provider)
            .map(String::as_str)
    }

    /// Release a short-lived provider adapter lease from the current fenced
    /// session. The lease contains no raw conference coordinate or credential.
    pub fn adapter_lease(
        &self,
        provider: Provider,
        now: DateTime<Utc>,
    ) -> Result<adapters::AdapterLease, Error> {
        if !matches!(self.status, SessionStatus::Joining | SessionStatus::Active)
            || now >= self.deadline
            || !self.grant.required_providers().contains(&provider)
        {
            return Err(Error::InvalidTransition);
        }
        Ok(adapters::AdapterLease {
            tenant_id: self.grant.tenant_id,
            workspace_id: self.grant.workspace_id,
            meeting_id: self.grant.meeting_id,
            session_id: self.grant.session_id,
            session_generation: self.grant.session_generation,
            provider,
            provider_binding_sha256: self.provider_binding_sha256.clone(),
            conference_approval_sha256: self.grant.conference_approval_sha256.clone(),
            sealed_coordinate_ref: self.grant.sealed_coordinate_ref.clone(),
            deadline: self.deadline,
            lease_expires_at: self.deadline.min(now + Duration::seconds(15)),
            remaining_cost_microusd: self
                .cost_ceiling_microusd
                .saturating_sub(self.spent_microusd),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandReceipt {
    command_sha256: String,
    result_receipt_sha256: String,
}

/// Idempotency outcome for gateway commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult<T> {
    /// A new transition was applied.
    Applied(T),
    /// The same exact command was already applied.
    Duplicate {
        /// Digest of the original result receipt.
        result_receipt_sha256: String,
    },
}

/// Provider-established event after an authenticated adapter handshake.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderEstablished {
    /// Provider family.
    pub provider: Provider,
    /// Session ID digest; raw Twilio/OpenAI identifiers never persist.
    pub provider_session_id_sha256: String,
    /// Exact provider handshake receipt digest.
    pub handshake_sha256: String,
    /// Provider observation time.
    pub observed_at: DateTime<Utc>,
}

/// Provider usage receipt used for hard spend enforcement.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsageReceipt {
    /// Exact schema.
    pub schema_version: String,
    /// Unique provider receipt digest or digest of its stable provider ID.
    pub provider_receipt_sha256: String,
    /// Provider family.
    pub provider: Provider,
    /// Incremental cost in micro-USD.
    pub cost_microusd: u64,
    /// Input token or duration unit count, where applicable.
    pub input_units: u64,
    /// Output token or duration unit count, where applicable.
    pub output_units: u64,
    /// Exact raw provider response digest.
    pub response_sha256: String,
    /// When the provider usage was observed.
    pub observed_at: DateTime<Utc>,
}

impl UsageReceipt {
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != USAGE_RECEIPT_SCHEMA || self.cost_microusd > 1_000_000_000 {
            return Err(Error::InvalidField("usage schema or cost"));
        }
        validate_digest(&self.provider_receipt_sha256, "provider receipt")?;
        validate_digest(&self.response_sha256, "provider response")
    }
}

/// Result of accounting one exact provider usage receipt.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum UsageAccounting {
    /// The increment was inside the session ceiling.
    Accounted {
        /// New cumulative spend.
        spent_microusd: u64,
    },
    /// The receipt was preserved but accepting the increment would exceed a
    /// hard ceiling or deadline, so the session moved to stopping.
    TeardownRequired {
        /// Cumulative spend before the rejected increment.
        spent_before_microusd: u64,
        /// Provider-reported increment that triggered teardown.
        attempted_increment_microusd: u64,
        /// Exact effective session ceiling.
        ceiling_microusd: u64,
    },
}

/// Trusted stop authority. It contains no dial target and can always reduce
/// capability, including after a newer Calendar cancellation fence arrives.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StopCommand {
    /// Exact schema.
    pub schema_version: String,
    /// Idempotency key.
    pub command_id: Uuid,
    /// Exact tenant.
    pub tenant_id: Uuid,
    /// Exact meeting.
    pub meeting_id: Uuid,
    /// Exact session.
    pub session_id: Uuid,
    /// Current or newer session fence.
    pub cancellation_generation: u32,
    /// Trusted cancellation/leave evidence.
    pub evidence_sha256: String,
    /// Bounded machine-readable reason.
    pub reason: String,
}

impl StopCommand {
    fn validate(&self) -> Result<(), Error> {
        if self.schema_version != STOP_SCHEMA || self.cancellation_generation == 0 {
            return Err(Error::InvalidField("stop schema or generation"));
        }
        validate_digest(&self.evidence_sha256, "stop evidence")?;
        validate_catalog_id(&self.reason, "stop reason")
    }
}

/// In-memory reference state machine. A production repository must apply the
/// same transitions under row locks using migration 0050.
#[derive(Debug, Default)]
pub struct MediaGatewayBook {
    sessions: BTreeMap<(Uuid, Uuid), MediaSession>,
    commands: BTreeMap<(Uuid, Uuid), CommandReceipt>,
    usage_receipts: BTreeMap<(Uuid, String), String>,
    webhook_receipts: BTreeMap<(Provider, String), String>,
}

impl MediaGatewayBook {
    /// Join exactly one consent-complete admitted meeting.
    pub fn join(
        &mut self,
        policy: &GatewayPolicy,
        grant: MediaExecutionGrant,
        command: JoinCommand,
        now: DateTime<Utc>,
    ) -> Result<ApplyResult<ProviderPlan>, Error> {
        policy.validate()?;
        command.validate()?;
        let digest = canonical_digest(&command)?;
        if let Some(receipt) = self.commands.get(&(command.tenant_id, command.command_id)) {
            return if receipt.command_sha256 == digest {
                Ok(ApplyResult::Duplicate {
                    result_receipt_sha256: receipt.result_receipt_sha256.clone(),
                })
            } else {
                Err(Error::IdempotencyConflict)
            };
        }
        validate_join_boundaries(policy, &grant, &command, now)?;
        let concurrent = self
            .sessions
            .values()
            .filter(|session| {
                session.grant.tenant_id == grant.tenant_id
                    && matches!(
                        session.status,
                        SessionStatus::Joining | SessionStatus::Active
                    )
            })
            .count();
        if concurrent >= usize::from(policy.max_concurrent_sessions) {
            return Err(Error::BudgetExceeded);
        }
        let duration_deadline = now
            + Duration::seconds(i64::from(
                policy
                    .max_session_duration_seconds
                    .min(grant.max_duration_seconds),
            ));
        let deadline = command.deadline.min(grant.ends_at).min(duration_deadline);
        if deadline <= now {
            return Err(Error::BudgetExceeded);
        }
        let max_cost_microusd = policy
            .max_session_cost_microusd
            .min(grant.max_cost_microusd);
        let plan = ProviderPlan {
            session_id: grant.session_id,
            session_generation: grant.session_generation,
            ingress_route: grant.ingress_route,
            conversation_route: grant.conversation_route,
            renderer_route: grant.renderer_route,
            sealed_coordinate_ref: grant.sealed_coordinate_ref.clone(),
            conference_approval_sha256: grant.conference_approval_sha256.clone(),
            deadline,
            max_duration_seconds: policy
                .max_session_duration_seconds
                .min(grant.max_duration_seconds),
            max_cost_microusd,
        };
        let result_receipt_sha256 = canonical_digest(&(
            grant.tenant_id,
            grant.meeting_id,
            grant.session_id,
            grant.session_generation,
            &digest,
            deadline,
            max_cost_microusd,
        ))?;
        let session = MediaSession {
            grant: grant.clone(),
            gateway_service_identity_id: policy.gateway_service_identity_id,
            provider_binding_sha256: policy.provider_binding_sha256.clone(),
            status: SessionStatus::Joining,
            provider_session_ids_sha256: BTreeMap::new(),
            spent_microusd: 0,
            cost_ceiling_microusd: max_cost_microusd,
            started_at: now,
            deadline,
            stopped_at: None,
            last_receipt_sha256: result_receipt_sha256.clone(),
        };
        self.sessions
            .insert((grant.tenant_id, grant.session_id), session);
        self.commands.insert(
            (command.tenant_id, command.command_id),
            CommandReceipt {
                command_sha256: digest,
                result_receipt_sha256,
            },
        );
        Ok(ApplyResult::Applied(plan))
    }

    /// Mark a session active only for its current provider binding and fence.
    pub fn provider_established(
        &mut self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u32,
        provider_binding_sha256: &str,
        event: ProviderEstablished,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        validate_digest(provider_binding_sha256, "provider binding")?;
        validate_digest(&event.provider_session_id_sha256, "provider session")?;
        validate_digest(&event.handshake_sha256, "provider handshake")?;
        let session = self
            .sessions
            .get_mut(&(tenant_id, session_id))
            .ok_or(Error::BoundaryMismatch)?;
        if session.grant.session_generation != generation
            || session.provider_binding_sha256 != provider_binding_sha256
            || session.status != SessionStatus::Joining
            || !session
                .grant
                .required_session_providers()
                .contains(&event.provider)
            || now > session.deadline
            || event.observed_at > now + Duration::seconds(30)
        {
            return Err(Error::InvalidTransition);
        }
        session
            .provider_session_ids_sha256
            .insert(event.provider, event.provider_session_id_sha256);
        let established: BTreeSet<_> = session
            .provider_session_ids_sha256
            .keys()
            .copied()
            .collect();
        if session
            .grant
            .required_session_providers()
            .is_subset(&established)
        {
            session.status = SessionStatus::Active;
        }
        session.last_receipt_sha256 = event.handshake_sha256;
        Ok(())
    }

    /// Account an authenticated provider usage increment exactly once.
    pub fn record_usage(
        &mut self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u32,
        receipt: UsageReceipt,
        now: DateTime<Utc>,
    ) -> Result<ApplyResult<UsageAccounting>, Error> {
        receipt.validate()?;
        let digest = canonical_digest(&receipt)?;
        let replay_key = (tenant_id, receipt.provider_receipt_sha256.clone());
        if let Some(existing) = self.usage_receipts.get(&replay_key) {
            return if existing == &digest {
                Ok(ApplyResult::Duplicate {
                    result_receipt_sha256: digest,
                })
            } else {
                Err(Error::IdempotencyConflict)
            };
        }
        let session = self
            .sessions
            .get_mut(&(tenant_id, session_id))
            .ok_or(Error::BoundaryMismatch)?;
        if session.grant.session_generation != generation
            || !matches!(
                session.status,
                SessionStatus::Joining | SessionStatus::Active
            )
            || !session
                .grant
                .required_providers()
                .contains(&receipt.provider)
        {
            return Err(Error::InvalidTransition);
        }
        let next = session
            .spent_microusd
            .checked_add(receipt.cost_microusd)
            .ok_or(Error::BudgetExceeded)?;
        let ceiling = session.cost_ceiling_microusd;
        if now >= session.deadline || next > ceiling {
            session.status = SessionStatus::Stopping;
            session.last_receipt_sha256 = receipt.response_sha256;
            self.usage_receipts.insert(replay_key, digest);
            return Ok(ApplyResult::Applied(UsageAccounting::TeardownRequired {
                spent_before_microusd: session.spent_microusd,
                attempted_increment_microusd: receipt.cost_microusd,
                ceiling_microusd: ceiling,
            }));
        }
        session.spent_microusd = next;
        session.last_receipt_sha256 = receipt.response_sha256;
        self.usage_receipts.insert(replay_key, digest);
        Ok(ApplyResult::Applied(UsageAccounting::Accounted {
            spent_microusd: next,
        }))
    }

    /// Start idempotent teardown. A newer cancellation generation always wins.
    pub fn stop(
        &mut self,
        command: StopCommand,
        now: DateTime<Utc>,
    ) -> Result<ApplyResult<SessionStatus>, Error> {
        command.validate()?;
        let digest = canonical_digest(&command)?;
        if let Some(receipt) = self.commands.get(&(command.tenant_id, command.command_id)) {
            return if receipt.command_sha256 == digest {
                Ok(ApplyResult::Duplicate {
                    result_receipt_sha256: receipt.result_receipt_sha256.clone(),
                })
            } else {
                Err(Error::IdempotencyConflict)
            };
        }
        let session = self
            .sessions
            .get_mut(&(command.tenant_id, command.session_id))
            .ok_or(Error::BoundaryMismatch)?;
        if session.grant.meeting_id != command.meeting_id
            || command.cancellation_generation < session.grant.session_generation
        {
            return Err(Error::BoundaryMismatch);
        }
        if session.status != SessionStatus::Stopped {
            session.status = SessionStatus::Stopping;
            session.last_receipt_sha256 = command.evidence_sha256.clone();
        }
        let result_receipt_sha256 = canonical_digest(&(
            command.tenant_id,
            command.session_id,
            command.cancellation_generation,
            &digest,
            now,
        ))?;
        self.commands.insert(
            (command.tenant_id, command.command_id),
            CommandReceipt {
                command_sha256: digest,
                result_receipt_sha256,
            },
        );
        Ok(ApplyResult::Applied(session.status))
    }

    /// Confirm provider teardown under the exact session fence.
    pub fn confirm_stopped(
        &mut self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u32,
        provider_receipt_sha256: String,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        validate_digest(&provider_receipt_sha256, "provider stop receipt")?;
        let session = self
            .sessions
            .get_mut(&(tenant_id, session_id))
            .ok_or(Error::BoundaryMismatch)?;
        if session.grant.session_generation != generation
            || session.status != SessionStatus::Stopping
        {
            return Err(Error::InvalidTransition);
        }
        session.status = SessionStatus::Stopped;
        session.stopped_at = Some(now);
        session.last_receipt_sha256 = provider_receipt_sha256;
        Ok(())
    }

    /// Enforce deadline and duration kill switches without provider input.
    pub fn enforce_deadlines(&mut self, now: DateTime<Utc>) -> Vec<Uuid> {
        let mut stopped = Vec::new();
        for session in self.sessions.values_mut() {
            if matches!(
                session.status,
                SessionStatus::Joining | SessionStatus::Active
            ) && now >= session.deadline
            {
                session.status = SessionStatus::Stopping;
                stopped.push(session.grant.session_id);
            }
        }
        stopped
    }

    /// Read a media session under its exact tenant key.
    pub fn get(&self, tenant_id: Uuid, session_id: Uuid) -> Option<&MediaSession> {
        self.sessions.get(&(tenant_id, session_id))
    }

    /// Authenticate and replay-fence one provider callback before parsing it.
    pub fn authenticate_webhook(
        &mut self,
        authenticator: &dyn WebhookAuthenticator,
        request: WebhookRequest<'_>,
        now: DateTime<Utc>,
    ) -> Result<WebhookReceipt, Error> {
        request.validate(now)?;
        let authenticated = authenticator.verify(&request, now)?;
        if authenticated.provider != request.provider
            || authenticated.request_sha256 != request.request_sha256()
            || authenticated.verified_at > now + Duration::seconds(30)
        {
            return Err(Error::WebhookAuthentication);
        }
        let key = (request.provider, authenticated.delivery_id.clone());
        if let Some(existing) = self.webhook_receipts.get(&key) {
            return if existing == &authenticated.request_sha256 {
                Ok(WebhookReceipt {
                    schema_version: WEBHOOK_RECEIPT_SCHEMA.into(),
                    provider: request.provider,
                    delivery_id_sha256: digest_text(&authenticated.delivery_id),
                    request_sha256: authenticated.request_sha256,
                    authentication_key_version_sha256: authenticated.key_version_sha256,
                    received_at: now,
                    duplicate: true,
                })
            } else {
                Err(Error::IdempotencyConflict)
            };
        }
        self.webhook_receipts
            .insert(key, authenticated.request_sha256.clone());
        Ok(WebhookReceipt {
            schema_version: WEBHOOK_RECEIPT_SCHEMA.into(),
            provider: request.provider,
            delivery_id_sha256: digest_text(&authenticated.delivery_id),
            request_sha256: authenticated.request_sha256,
            authentication_key_version_sha256: authenticated.key_version_sha256,
            received_at: now,
            duplicate: false,
        })
    }

    /// Admit only the four bounded meeting-control intents for this exact live
    /// session. Speech text itself never becomes executable authority.
    pub fn validate_live_intent(&self, envelope: &MeetingToolIntentEnvelope) -> Result<(), Error> {
        envelope.validate().map_err(|_| Error::UntrustedAuthority)?;
        let session = self
            .sessions
            .get(&(envelope.tenant_id, envelope.session_id))
            .ok_or(Error::BoundaryMismatch)?;
        if session.status != SessionStatus::Active
            || envelope.workspace_id != session.grant.workspace_id
            || envelope.meeting_id != session.grant.meeting_id
            || envelope.session_generation != session.grant.session_generation
            || envelope.service_identity_id != session.grant.meeting_agent_identity_id
        {
            return Err(Error::BoundaryMismatch);
        }
        Ok(())
    }
}

fn validate_join_boundaries(
    policy: &GatewayPolicy,
    grant: &MediaExecutionGrant,
    command: &JoinCommand,
    now: DateTime<Utc>,
) -> Result<(), Error> {
    if !policy.activation_enabled {
        return Err(Error::ProviderDisabled);
    }
    if policy.tenant_id != grant.tenant_id
        || policy.workspace_id != grant.workspace_id
        || policy.mailbox_identity_id != grant.mailbox_identity_id
        || command.tenant_id != grant.tenant_id
        || command.workspace_id != grant.workspace_id
        || command.meeting_id != grant.meeting_id
        || command.session_id != grant.session_id
        || command.session_generation != grant.session_generation
        || command.provider_revision != grant.provider_revision
        || command.mailbox_identity_id != grant.mailbox_identity_id
        || command.meeting_agent_identity_id != grant.meeting_agent_identity_id
        || command.gateway_service_identity_id != policy.gateway_service_identity_id
        || grant.schedule_revision == 0
        || now < grant.join_not_before
        || now > grant.join_not_after
        || now >= command.deadline
    {
        return Err(Error::BoundaryMismatch);
    }
    let required = grant.required_providers();
    if !required.is_subset(&policy.allowed_providers) {
        return Err(Error::ProviderDisabled);
    }
    validate_digest(&grant.provider_event_id_sha256, "provider event")?;
    validate_digest(&grant.admission_evidence_sha256, "admission evidence")?;
    validate_digest(&grant.consent_evidence_sha256, "consent evidence")?;
    validate_digest(&grant.conference_approval_sha256, "conference approval")?;
    validate_opaque_reference(&grant.sealed_coordinate_ref)?;
    if grant.starts_at >= grant.ends_at
        || grant.max_cost_microusd == 0
        || grant.max_duration_seconds == 0
        || grant.raw_audio_retention != RetentionMode::None
    {
        return Err(Error::InvalidField("meeting media retention or limits"));
    }
    if grant.transcript_retention != RetentionMode::None
        && grant.transcript_retention != RetentionMode::AnalystEvidence
    {
        return Err(Error::InvalidField("transcript retention"));
    }
    if grant.data_class == DataClass::Restricted
        && matches!(grant.conversation_route, ConversationRoute::OpenAiRealtime)
    {
        // Meeting control verified the separate restricted approval. The
        // gateway still requires its exact external providers to be allowlisted.
    }
    Ok(())
}

/// Borrowed audio frame. It cannot be cloned, serialized, logged, or persisted
/// by this contract; call [`TransientAudioFrame::receipt`] for safe evidence.
pub struct TransientAudioFrame<'a> {
    /// Exact session.
    pub session_id: Uuid,
    /// Exact fence.
    pub session_generation: u32,
    /// Monotonic provider sequence.
    pub sequence: u64,
    /// Provider timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Borrowed audio bytes.
    pub bytes: &'a [u8],
}

impl TransientAudioFrame<'_> {
    /// Validate bounds and return a persistable digest-only receipt.
    pub fn receipt(&self, observed_at: DateTime<Utc>) -> Result<AudioFrameReceipt, Error> {
        if self.session_generation == 0
            || self.sequence == 0
            || self.bytes.is_empty()
            || self.bytes.len() > MAX_AUDIO_FRAME_BYTES
        {
            return Err(Error::InvalidField("transient audio frame"));
        }
        Ok(AudioFrameReceipt {
            session_id: self.session_id,
            session_generation: self.session_generation,
            sequence: self.sequence,
            timestamp_ms: self.timestamp_ms,
            byte_count: self.bytes.len() as u32,
            frame_sha256: hex::encode(Sha256::digest(self.bytes)),
            observed_at,
        })
    }
}

/// Persistable digest-only evidence for one transient audio frame.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AudioFrameReceipt {
    /// Exact session.
    pub session_id: Uuid,
    /// Exact fence.
    pub session_generation: u32,
    /// Provider sequence.
    pub sequence: u64,
    /// Provider timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Number of transient bytes.
    pub byte_count: u32,
    /// SHA-256 digest of transient bytes.
    pub frame_sha256: String,
    /// Observation time.
    pub observed_at: DateTime<Utc>,
}

/// Output-only speech request for the optional ElevenLabs adapter.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpeechRenderRequest {
    /// Exact tenant.
    pub tenant_id: Uuid,
    /// Exact session.
    pub session_id: Uuid,
    /// Exact fence.
    pub session_generation: u32,
    /// Approved bounded response text. Never inbound audio or a transcript.
    pub approved_text: String,
    /// Digest of the exact approved model turn.
    pub approved_turn_sha256: String,
    /// Operations-catalog voice identifier, not user-provided.
    pub voice_catalog_id: String,
    /// Operations-catalog model identifier.
    pub model_catalog_id: String,
    /// Hard renderer cost ceiling.
    pub max_cost_microusd: u64,
}

impl SpeechRenderRequest {
    /// Validate against the exact active output-only ElevenLabs route.
    pub fn validate_for(&self, session: &MediaSession) -> Result<(), Error> {
        if session.status != SessionStatus::Active
            || session.grant.tenant_id != self.tenant_id
            || session.grant.session_id != self.session_id
            || session.grant.session_generation != self.session_generation
            || session.grant.renderer_route != RendererRoute::ElevenLabs
            || self.approved_text.is_empty()
            || self.approved_text.len() > MAX_RENDER_TEXT_BYTES
            || self.approved_text.contains('\0')
            || self.max_cost_microusd == 0
            || self.max_cost_microusd
                > session
                    .grant
                    .max_cost_microusd
                    .saturating_sub(session.spent_microusd)
        {
            return Err(Error::BoundaryMismatch);
        }
        validate_digest(&self.approved_turn_sha256, "approved speech turn")?;
        validate_catalog_id(&self.voice_catalog_id, "voice catalog id")?;
        validate_catalog_id(&self.model_catalog_id, "speech model catalog id")
    }
}

/// Raw callback request presented to a provider-specific verifier.
pub struct WebhookRequest<'a> {
    /// Provider family.
    pub provider: Provider,
    /// Exact externally visible HTTPS/WSS URL used for signature calculation.
    pub exact_url: &'a str,
    /// Original headers without normalization of signed values.
    pub headers: &'a BTreeMap<String, String>,
    /// Original body bytes.
    pub raw_body: &'a [u8],
    /// Gateway receive time.
    pub received_at: DateTime<Utc>,
}

impl WebhookRequest<'_> {
    fn validate(&self, now: DateTime<Utc>) -> Result<(), Error> {
        if !self.exact_url.starts_with("https://") && !self.exact_url.starts_with("wss://")
            || self.exact_url.len() > 2048
            || self.raw_body.len() > MAX_WEBHOOK_BODY_BYTES
            || self.received_at < now - MAX_WEBHOOK_AGE
            || self.received_at > now + Duration::seconds(30)
        {
            return Err(Error::WebhookAuthentication);
        }
        Ok(())
    }

    fn request_sha256(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(self.exact_url.as_bytes());
        digest.update([0]);
        digest.update(self.raw_body);
        hex::encode(digest.finalize())
    }
}

/// Successful private result from a provider-specific signature verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedWebhook {
    provider: Provider,
    delivery_id: String,
    request_sha256: String,
    key_version_sha256: String,
    verified_at: DateTime<Utc>,
}

impl AuthenticatedWebhook {
    /// Construct a verifier result after the adapter checked the exact raw
    /// request with the provider-supported algorithm or official SDK.
    pub fn verified(
        request: &WebhookRequest<'_>,
        delivery_id: String,
        key_version_sha256: String,
        verified_at: DateTime<Utc>,
    ) -> Result<Self, Error> {
        validate_catalog_id(&delivery_id, "provider delivery id")?;
        validate_digest(&key_version_sha256, "webhook key version")?;
        Ok(Self {
            provider: request.provider,
            delivery_id,
            request_sha256: request.request_sha256(),
            key_version_sha256,
            verified_at,
        })
    }
}

/// Provider-specific webhook authenticity boundary.
///
/// Twilio implementations must validate the lowercase `x-twilio-signature`
/// against the exact external URL and original parameters/body. OpenAI
/// implementations must use the current webhook secret verification flow and
/// preserve its delivery ID/timestamp replay data. Provider SDK verification
/// belongs in adapters, not this provider-neutral state machine.
pub trait WebhookAuthenticator: Send + Sync {
    /// Verify the exact raw request or fail closed.
    fn verify(
        &self,
        request: &WebhookRequest<'_>,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedWebhook, Error>;
}

/// Durable callback evidence without raw body, headers, phone, SIP, or URL.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebhookReceipt {
    /// Exact schema.
    pub schema_version: String,
    /// Provider family.
    pub provider: Provider,
    /// Pseudonymous delivery ID digest.
    pub delivery_id_sha256: String,
    /// Digest of exact URL plus raw body.
    pub request_sha256: String,
    /// Digest identifying the webhook secret/key version used.
    pub authentication_key_version_sha256: String,
    /// Gateway receive time.
    pub received_at: DateTime<Utc>,
    /// Whether this was the same exact retry.
    pub duplicate: bool,
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), Error> {
    if value.len() != SHA256_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::InvalidField(field));
    }
    Ok(())
}

fn validate_catalog_id(value: &str, field: &'static str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(Error::InvalidField(field));
    }
    Ok(())
}

fn validate_opaque_reference(value: &str) -> Result<(), Error> {
    if value.len() < 16
        || value.len() > 256
        || value.contains("//")
        || value.to_ascii_lowercase().starts_with("sip:")
        || value.contains('@')
        || value.contains('+')
        || value.chars().all(|character| character.is_ascii_digit())
    {
        return Err(Error::UntrustedAuthority);
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, Error> {
    serde_json::to_vec(value)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|_| Error::InvalidField("canonical receipt"))
}

fn digest_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use snowman_meeting_control::{
        ApprovedConference, AttendanceStatus, CalendarObservation, ConferenceCandidate,
        ConsentPolicy, MeetingAdmission, ParticipantConsent, ProcessingPolicy, ScheduleBook,
        UntrustedContentRef, CALENDAR_OBSERVATION_SCHEMA, MEETING_ADMISSION_SCHEMA,
    };

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, SHA256_HEX_LEN).collect()
    }

    fn active_meeting(route: VoiceRoute, renderer: SpeechOutputRoute) -> (ScheduledMeeting, Uuid) {
        let tenant_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let mailbox = Uuid::new_v4();
        let starts_at = Utc::now() - Duration::minutes(1);
        let content = UntrustedContentRef {
            authority: "analyst360".into(),
            artifact_id: Uuid::new_v4(),
            content_sha256: digest('a'),
            label: "calendar context".into(),
        };
        let calendar = CalendarObservation {
            schema_version: CALENDAR_OBSERVATION_SCHEMA.into(),
            tenant_id,
            workspace_id,
            mailbox_identity_id: mailbox,
            provider_event_id_sha256: digest('b'),
            provider_revision_sha256: digest('c'),
            revision: 3,
            organizer_subject_sha256: digest('d'),
            attendance: AttendanceStatus::Accepted,
            starts_at,
            ends_at: starts_at + Duration::hours(1),
            conference: ConferenceCandidate {
                kind: ConferenceKind::Telephony,
                entrypoint_sha256: digest('e'),
                metadata_sha256: digest('f'),
            },
            content: content.clone(),
            observed_at: Utc::now(),
        };
        let external =
            route == VoiceRoute::OpenAiRealtime || renderer == SpeechOutputRoute::ElevenLabs;
        let admission = MeetingAdmission {
            schema_version: MEETING_ADMISSION_SCHEMA.into(),
            meeting_id: Uuid::new_v4(),
            tenant_id,
            workspace_id,
            mailbox_identity_id: mailbox,
            meeting_agent_identity_id: Uuid::new_v4(),
            parent_thread_sha256: digest('1'),
            data_class: DataClass::Confidential,
            provider_event_id_sha256: calendar.provider_event_id_sha256.clone(),
            provider_revision: calendar.revision,
            organizer_approved: true,
            starts_at,
            ends_at: calendar.ends_at,
            join_not_before: starts_at - Duration::minutes(5),
            join_not_after: starts_at + Duration::minutes(5),
            conference: ApprovedConference {
                kind: ConferenceKind::Telephony,
                entrypoint_sha256: calendar.conference.entrypoint_sha256.clone(),
                sealed_coordinate_ref: "snowman-coordinate:meeting-123".into(),
                approval_evidence_sha256: digest('2'),
            },
            processing: ProcessingPolicy {
                voice_route: route,
                speech_output_route: renderer,
                external_processing_allowed: external,
                restricted_external_approval_sha256: None,
                policy_evidence_sha256: digest('3'),
                max_cost_microusd: 500_000,
                max_duration_seconds: 3600,
            },
            consent: ConsentPolicy {
                disclosure_required: true,
                transcription_consent_required: true,
                recording_enabled: false,
                external_processing_consent_required: external,
                raw_audio_retention: RetentionMode::None,
                transcript_retention: RetentionMode::AnalystEvidence,
                policy_evidence_sha256: digest('4'),
            },
            admission_evidence_sha256: digest('5'),
            source_context: content,
        };
        let verified = MeetingAdmission::from_calendar(&calendar, admission).unwrap();
        let meeting_id = verified.admission().meeting_id;
        let mut book = ScheduleBook::default();
        book.schedule(Uuid::new_v4(), verified, Utc::now()).unwrap();
        let mut meeting = book.get(tenant_id, meeting_id).unwrap().clone();
        let generation = meeting.begin_join(Utc::now()).unwrap();
        meeting
            .record_participant(
                ParticipantConsent {
                    participant_subject_sha256: digest('6'),
                    disclosure_evidence_sha256: Some(digest('7')),
                    transcription_consent_sha256: Some(digest('8')),
                    recording_consent_sha256: None,
                    external_processing_consent_sha256: external.then(|| digest('9')),
                    observed_at: Utc::now(),
                },
                Utc::now(),
            )
            .unwrap();
        meeting.activate_media(generation, Utc::now()).unwrap();
        (meeting, workspace_id)
    }

    fn policy(grant: &MediaExecutionGrant, providers: BTreeSet<Provider>) -> GatewayPolicy {
        GatewayPolicy {
            tenant_id: grant.tenant_id,
            workspace_id: grant.workspace_id,
            mailbox_identity_id: grant.mailbox_identity_id,
            gateway_service_identity_id: Uuid::new_v4(),
            activation_enabled: true,
            allowed_providers: providers,
            provider_binding_sha256: digest('a'),
            policy_evidence_sha256: digest('b'),
            max_session_cost_microusd: 400_000,
            max_session_duration_seconds: 1800,
            max_concurrent_sessions: 2,
        }
    }

    fn join_command(grant: &MediaExecutionGrant, gateway_service_identity_id: Uuid) -> JoinCommand {
        JoinCommand {
            schema_version: JOIN_SCHEMA.into(),
            command_id: Uuid::new_v4(),
            tenant_id: grant.tenant_id,
            workspace_id: grant.workspace_id,
            meeting_id: grant.meeting_id,
            session_id: grant.session_id,
            session_generation: grant.session_generation,
            provider_revision: grant.provider_revision,
            mailbox_identity_id: grant.mailbox_identity_id,
            meeting_agent_identity_id: grant.meeting_agent_identity_id,
            gateway_service_identity_id,
            issuer_evidence_sha256: digest('c'),
            deadline: Utc::now() + Duration::minutes(10),
        }
    }

    #[test]
    fn route_is_default_off_and_requires_every_exact_provider() {
        let (meeting, _) =
            active_meeting(VoiceRoute::OpenAiRealtime, SpeechOutputRoute::ElevenLabs);
        let grant = MediaExecutionGrant::from_active_meeting(&meeting, Uuid::new_v4(), digest('d'))
            .unwrap();
        let mut disabled = policy(&grant, BTreeSet::new());
        disabled.activation_enabled = false;
        let command = join_command(&grant, disabled.gateway_service_identity_id);
        assert!(matches!(
            MediaGatewayBook::default().join(&disabled, grant.clone(), command, Utc::now()),
            Err(Error::ProviderDisabled)
        ));

        let mut providers = grant.required_providers();
        providers.remove(&Provider::ElevenLabs);
        let incomplete = policy(&grant, providers);
        let command = join_command(&grant, incomplete.gateway_service_identity_id);
        assert!(matches!(
            MediaGatewayBook::default().join(&incomplete, grant, command, Utc::now()),
            Err(Error::ProviderDisabled)
        ));
    }

    #[test]
    fn join_is_exactly_bound_and_digest_idempotent_without_a_target_field() {
        let (meeting, _) = active_meeting(VoiceRoute::SnowmanAws, SpeechOutputRoute::VoiceRoute);
        let grant = MediaExecutionGrant::from_active_meeting(&meeting, Uuid::new_v4(), digest('d'))
            .unwrap();
        let policy = policy(&grant, grant.required_providers());
        let command = join_command(&grant, policy.gateway_service_identity_id);
        let mut gateway = MediaGatewayBook::default();
        let first = gateway
            .join(&policy, grant.clone(), command.clone(), Utc::now())
            .unwrap();
        assert!(matches!(first, ApplyResult::Applied(_)));
        assert!(matches!(
            gateway
                .join(&policy, grant.clone(), command.clone(), Utc::now())
                .unwrap(),
            ApplyResult::Duplicate { .. }
        ));
        let mut conflict = command;
        conflict.deadline += Duration::seconds(1);
        assert_eq!(
            gateway.join(&policy, grant, conflict, Utc::now()),
            Err(Error::IdempotencyConflict)
        );
    }

    #[test]
    fn every_live_provider_leg_must_establish_before_media_is_active() {
        let (meeting, _) =
            active_meeting(VoiceRoute::OpenAiRealtime, SpeechOutputRoute::ElevenLabs);
        let grant = MediaExecutionGrant::from_active_meeting(&meeting, Uuid::new_v4(), digest('d'))
            .unwrap();
        let policy = policy(&grant, grant.required_providers());
        let command = join_command(&grant, policy.gateway_service_identity_id);
        let mut gateway = MediaGatewayBook::default();
        gateway
            .join(&policy, grant.clone(), command, Utc::now())
            .unwrap();

        gateway
            .provider_established(
                grant.tenant_id,
                grant.session_id,
                grant.session_generation,
                &policy.provider_binding_sha256,
                ProviderEstablished {
                    provider: Provider::Twilio,
                    provider_session_id_sha256: digest('1'),
                    handshake_sha256: digest('2'),
                    observed_at: Utc::now(),
                },
                Utc::now(),
            )
            .unwrap();
        assert_eq!(
            gateway
                .get(grant.tenant_id, grant.session_id)
                .unwrap()
                .status(),
            SessionStatus::Joining
        );

        gateway
            .provider_established(
                grant.tenant_id,
                grant.session_id,
                grant.session_generation,
                &policy.provider_binding_sha256,
                ProviderEstablished {
                    provider: Provider::OpenAiRealtime,
                    provider_session_id_sha256: digest('3'),
                    handshake_sha256: digest('4'),
                    observed_at: Utc::now(),
                },
                Utc::now(),
            )
            .unwrap();
        let session = gateway.get(grant.tenant_id, grant.session_id).unwrap();
        assert_eq!(session.status(), SessionStatus::Active);
        assert_eq!(
            session.provider_session_id_sha256(Provider::Twilio),
            Some(digest('1').as_str())
        );
    }

    #[test]
    fn cancellation_and_deadline_stop_media_under_the_fence() {
        let (meeting, _) = active_meeting(VoiceRoute::SnowmanAws, SpeechOutputRoute::VoiceRoute);
        let grant = MediaExecutionGrant::from_active_meeting(&meeting, Uuid::new_v4(), digest('d'))
            .unwrap();
        let policy = policy(&grant, grant.required_providers());
        let mut command = join_command(&grant, policy.gateway_service_identity_id);
        command.deadline = Utc::now() + Duration::seconds(1);
        let mut gateway = MediaGatewayBook::default();
        gateway
            .join(&policy, grant.clone(), command, Utc::now())
            .unwrap();
        let stopped = gateway.enforce_deadlines(Utc::now() + Duration::seconds(2));
        assert_eq!(stopped, vec![grant.session_id]);
        assert_eq!(
            gateway
                .get(grant.tenant_id, grant.session_id)
                .unwrap()
                .status(),
            SessionStatus::Stopping
        );
    }

    #[test]
    fn provider_usage_is_exactly_once_and_overage_triggers_teardown() {
        let (meeting, _) = active_meeting(VoiceRoute::SnowmanAws, SpeechOutputRoute::VoiceRoute);
        let grant = MediaExecutionGrant::from_active_meeting(&meeting, Uuid::new_v4(), digest('d'))
            .unwrap();
        let mut policy = policy(&grant, grant.required_providers());
        policy.max_session_cost_microusd = 100;
        let command = join_command(&grant, policy.gateway_service_identity_id);
        let mut gateway = MediaGatewayBook::default();
        gateway
            .join(&policy, grant.clone(), command, Utc::now())
            .unwrap();
        let usage = UsageReceipt {
            schema_version: USAGE_RECEIPT_SCHEMA.into(),
            provider_receipt_sha256: digest('1'),
            provider: Provider::SnowmanAws,
            cost_microusd: 60,
            input_units: 1,
            output_units: 1,
            response_sha256: digest('2'),
            observed_at: Utc::now(),
        };
        assert_eq!(
            gateway
                .record_usage(
                    grant.tenant_id,
                    grant.session_id,
                    grant.session_generation,
                    usage.clone(),
                    Utc::now(),
                )
                .unwrap(),
            ApplyResult::Applied(UsageAccounting::Accounted { spent_microusd: 60 })
        );
        assert!(matches!(
            gateway
                .record_usage(
                    grant.tenant_id,
                    grant.session_id,
                    grant.session_generation,
                    usage,
                    Utc::now(),
                )
                .unwrap(),
            ApplyResult::Duplicate { .. }
        ));
        let over = UsageReceipt {
            schema_version: USAGE_RECEIPT_SCHEMA.into(),
            provider_receipt_sha256: digest('3'),
            provider: Provider::SnowmanAws,
            cost_microusd: 41,
            input_units: 1,
            output_units: 1,
            response_sha256: digest('4'),
            observed_at: Utc::now(),
        };
        assert_eq!(
            gateway
                .record_usage(
                    grant.tenant_id,
                    grant.session_id,
                    grant.session_generation,
                    over,
                    Utc::now(),
                )
                .unwrap(),
            ApplyResult::Applied(UsageAccounting::TeardownRequired {
                spent_before_microusd: 60,
                attempted_increment_microusd: 41,
                ceiling_microusd: 100,
            })
        );
        assert_eq!(
            gateway
                .get(grant.tenant_id, grant.session_id)
                .unwrap()
                .status(),
            SessionStatus::Stopping
        );
    }

    struct MockAuthenticator {
        accept: bool,
    }

    impl WebhookAuthenticator for MockAuthenticator {
        fn verify(
            &self,
            request: &WebhookRequest<'_>,
            now: DateTime<Utc>,
        ) -> Result<AuthenticatedWebhook, Error> {
            if !self.accept {
                return Err(Error::WebhookAuthentication);
            }
            AuthenticatedWebhook::verified(request, "delivery-1".into(), digest('a'), now)
        }
    }

    #[test]
    fn webhook_requires_authentication_and_replays_only_exact_raw_request() {
        let headers = BTreeMap::from([("x-twilio-signature".into(), "signed".into())]);
        let now = Utc::now();
        let request = WebhookRequest {
            provider: Provider::Twilio,
            exact_url: "https://meetings.snowmanai.org/v1/twilio/media",
            headers: &headers,
            raw_body: b"event=start",
            received_at: now,
        };
        let mut gateway = MediaGatewayBook::default();
        assert_eq!(
            gateway.authenticate_webhook(&MockAuthenticator { accept: false }, request, now),
            Err(Error::WebhookAuthentication)
        );
        let request = WebhookRequest {
            provider: Provider::Twilio,
            exact_url: "https://meetings.snowmanai.org/v1/twilio/media",
            headers: &headers,
            raw_body: b"event=start",
            received_at: now,
        };
        assert!(
            !gateway
                .authenticate_webhook(&MockAuthenticator { accept: true }, request, now)
                .unwrap()
                .duplicate
        );
        let request = WebhookRequest {
            provider: Provider::Twilio,
            exact_url: "https://meetings.snowmanai.org/v1/twilio/media",
            headers: &headers,
            raw_body: b"event=start",
            received_at: now,
        };
        assert!(
            gateway
                .authenticate_webhook(&MockAuthenticator { accept: true }, request, now)
                .unwrap()
                .duplicate
        );
        let changed = WebhookRequest {
            provider: Provider::Twilio,
            exact_url: "https://meetings.snowmanai.org/v1/twilio/media",
            headers: &headers,
            raw_body: b"event=changed",
            received_at: now,
        };
        assert_eq!(
            gateway.authenticate_webhook(&MockAuthenticator { accept: true }, changed, now),
            Err(Error::IdempotencyConflict)
        );
    }

    #[test]
    fn audio_is_borrowed_and_only_digest_receipt_is_persistable() {
        let bytes = [1_u8, 2, 3, 4];
        let frame = TransientAudioFrame {
            session_id: Uuid::new_v4(),
            session_generation: 2,
            sequence: 1,
            timestamp_ms: 10,
            bytes: &bytes,
        };
        let receipt = frame.receipt(Utc::now()).unwrap();
        assert_eq!(receipt.byte_count, 4);
        assert_eq!(receipt.frame_sha256.len(), SHA256_HEX_LEN);
        assert!(!serde_json::to_string(&receipt).unwrap().contains("AQIDBA"));
    }
}
