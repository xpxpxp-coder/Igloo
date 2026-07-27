#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Governed meeting admission, scheduling, consent, and tool-intent contracts.
//!
//! This crate deliberately contains no HTTP client and no provider SDK. Gmail,
//! Calendar, telephony, speech, and huddle adapters must reduce remote input to
//! these contracts at a trusted Snowman boundary. Remote content is represented
//! only by digest-bound Analyst artifact references and can never supply policy,
//! credentials, provider routes, or conference coordinates.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Version for normalized mailbox observations.
pub const MAIL_OBSERVATION_SCHEMA: &str = "snowman.meeting.mail-observation.v1";
/// Version for normalized calendar observations.
pub const CALENDAR_OBSERVATION_SCHEMA: &str = "snowman.meeting.calendar-observation.v1";
/// Version for trusted meeting admissions.
pub const MEETING_ADMISSION_SCHEMA: &str = "snowman.meeting.admission.v1";
/// Version for meeting-tool intents.
pub const MEETING_TOOL_INTENT_SCHEMA: &str = "snowman.meeting.tool-intent.v1";

const SHA256_HEX_LEN: usize = 64;
const MAX_CONTEXT_LABEL_BYTES: usize = 256;
const MAX_INTENT_TEXT_BYTES: usize = 8 * 1024;
const MAX_EVIDENCE_REFERENCES: usize = 32;
const MAX_MEETING_DURATION: Duration = Duration::hours(12);
const MAX_JOIN_WINDOW: Duration = Duration::minutes(30);

/// Fail-closed contract and state-transition failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// A required bounded identifier or digest is malformed.
    #[error("meeting contract field is invalid: {0}")]
    InvalidField(&'static str),
    /// A source attempted to cross a tenant, workspace, or mailbox boundary.
    #[error("meeting contract boundary mismatch")]
    BoundaryMismatch,
    /// Remote content or a model attempted to supply trusted authority.
    #[error("untrusted meeting content cannot supply trusted authority")]
    UntrustedAuthority,
    /// The requested processor is not authorized for the data class.
    #[error("meeting processor policy does not authorize this route")]
    ProcessorNotAuthorized,
    /// Required disclosure or participant consent is absent.
    #[error("meeting consent is incomplete")]
    ConsentIncomplete,
    /// A stale provider revision attempted to replace current schedule state.
    #[error("meeting update is stale")]
    StaleRevision,
    /// An idempotency key was reused with different content.
    #[error("meeting idempotency key conflicts with an existing command")]
    IdempotencyConflict,
    /// The requested lifecycle transition is not allowed.
    #[error("meeting lifecycle transition is invalid")]
    InvalidTransition,
}

/// Classification fixed by Snowman policy before any meeting media is routed.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Snowman internal content without client-confidential material.
    Internal,
    /// Confidential Snowman or client work product.
    Confidential,
    /// Material requiring the narrowest Snowman-controlled processing route.
    Restricted,
}

/// Explicitly selected live-audio processor route.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VoiceRoute {
    /// No live media may start. This is the default deployment state.
    Disabled,
    /// Snowman-controlled processing inside its AWS boundary.
    SnowmanAws,
    /// Optional OpenAI Realtime route for an expressly eligible meeting.
    OpenAiRealtime,
}

/// Explicitly selected speech-output renderer.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SpeechOutputRoute {
    /// Use the selected live voice route's native output.
    VoiceRoute,
    /// Use a Snowman-controlled AWS renderer.
    SnowmanAws,
    /// Use ElevenLabs only for approved response text.
    ElevenLabs,
}

/// The normalized provider that supplied a conference candidate.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConferenceKind {
    /// Native Snowman huddle.
    SnowmanHuddle,
    /// Google Meet coordinates read through the governed Calendar connector.
    GoogleMeet,
    /// A phone/SIP plan held by the Snowman telephony gateway.
    Telephony,
}

/// Exact retention choice; none is the safe default for raw media.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RetentionMode {
    /// Do not retain the material.
    None,
    /// Retain only under Analyst 360 evidence and deletion authority.
    AnalystEvidence,
}

/// Digest-bound reference to untrusted content held by Analyst 360.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UntrustedContentRef {
    /// Must be the literal Analyst 360 authority.
    pub authority: String,
    /// Immutable Analyst artifact identifier.
    pub artifact_id: Uuid,
    /// SHA-256 digest of the exact source bytes.
    pub content_sha256: String,
    /// Short display-only label; never interpreted as instructions.
    pub label: String,
}

impl UntrustedContentRef {
    /// Validate that the reference carries no delegated policy authority.
    pub fn validate(&self) -> Result<(), Error> {
        if self.authority != "analyst360" {
            return Err(Error::UntrustedAuthority);
        }
        validate_digest(&self.content_sha256, "content_sha256")?;
        validate_text(&self.label, 1, MAX_CONTEXT_LABEL_BYTES, "context label")
    }
}

/// Normalized Gmail history item from a mailbox-bound connector.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MailObservation {
    /// Exact contract schema.
    pub schema_version: String,
    /// Tenant fixed by the connector credential binding, not message content.
    pub tenant_id: Uuid,
    /// Workspace fixed by the mailbox registration.
    pub workspace_id: Uuid,
    /// Dedicated Snowman mailbox identity.
    pub mailbox_identity_id: Uuid,
    /// Digest of the immutable Gmail message identifier.
    pub provider_message_id_sha256: String,
    /// Monotonic Gmail history identifier returned by the provider API.
    pub history_id: u64,
    /// Pseudonymous digest of the envelope sender.
    pub sender_subject_sha256: String,
    /// When the connector observed the item.
    pub observed_at: DateTime<Utc>,
    /// Entire body, attachment, and quoted history remain untrusted in Analyst.
    pub content: UntrustedContentRef,
}

impl MailObservation {
    /// Validate a mail observation without assigning it scheduling authority.
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != MAIL_OBSERVATION_SCHEMA || self.history_id == 0 {
            return Err(Error::InvalidField("mail schema or history id"));
        }
        validate_digest(
            &self.provider_message_id_sha256,
            "provider_message_id_sha256",
        )?;
        validate_digest(&self.sender_subject_sha256, "sender_subject_sha256")?;
        self.content.validate()
    }
}

/// Calendar attendance status as returned for the dedicated Snowman identity.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttendanceStatus {
    /// The account has not accepted and cannot auto-join.
    NeedsAction,
    /// The dedicated account accepted the current event revision.
    Accepted,
    /// The account declined the event.
    Declined,
    /// The event was cancelled by its source.
    Cancelled,
}

/// Untrusted conference material discovered in Calendar.
///
/// It intentionally contains only digests. A separate trusted resolver must
/// map the exact digest to a sealed dial plan or native room coordinate.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConferenceCandidate {
    /// Provider family reported by the connector.
    pub kind: ConferenceKind,
    /// Digest of the exact conference entry-point bytes.
    pub entrypoint_sha256: String,
    /// Digest of provider conference metadata used during resolution.
    pub metadata_sha256: String,
}

impl ConferenceCandidate {
    fn validate(&self) -> Result<(), Error> {
        validate_digest(&self.entrypoint_sha256, "entrypoint_sha256")?;
        validate_digest(&self.metadata_sha256, "metadata_sha256")
    }
}

/// Normalized Calendar event revision. Description and conference instructions
/// are untrusted evidence and cannot themselves authorize a join.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CalendarObservation {
    /// Exact contract schema.
    pub schema_version: String,
    /// Tenant fixed by the Calendar credential binding.
    pub tenant_id: Uuid,
    /// Workspace fixed by the calendar registration.
    pub workspace_id: Uuid,
    /// Dedicated Snowman calendar identity.
    pub mailbox_identity_id: Uuid,
    /// Digest of the provider event identifier and recurring instance key.
    pub provider_event_id_sha256: String,
    /// Digest of the provider ETag/revision token.
    pub provider_revision_sha256: String,
    /// Monotonic connector revision used for stale-update rejection.
    pub revision: u64,
    /// Pseudonymous organizer digest.
    pub organizer_subject_sha256: String,
    /// Current attendance status for the Snowman account.
    pub attendance: AttendanceStatus,
    /// Scheduled start from the provider object.
    pub starts_at: DateTime<Utc>,
    /// Scheduled end from the provider object.
    pub ends_at: DateTime<Utc>,
    /// Candidate requiring trusted policy resolution.
    pub conference: ConferenceCandidate,
    /// Description, summary, attachments, and remote instructions in Analyst.
    pub content: UntrustedContentRef,
    /// Connector observation time.
    pub observed_at: DateTime<Utc>,
}

impl CalendarObservation {
    /// Validate provider facts without trusting their content.
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != CALENDAR_OBSERVATION_SCHEMA || self.revision == 0 {
            return Err(Error::InvalidField("calendar schema or revision"));
        }
        validate_digest(&self.provider_event_id_sha256, "provider_event_id_sha256")?;
        validate_digest(&self.provider_revision_sha256, "provider_revision_sha256")?;
        validate_digest(&self.organizer_subject_sha256, "organizer digest")?;
        validate_interval(self.starts_at, self.ends_at)?;
        self.conference.validate()?;
        self.content.validate()
    }
}

/// Trusted, immutable conference coordinate resolved outside model context.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovedConference {
    /// Exact conference family.
    pub kind: ConferenceKind,
    /// Must exactly match the admitted Calendar candidate.
    pub entrypoint_sha256: String,
    /// Opaque reference resolved only by the media gateway. It must not be a
    /// phone number, URL, SIP URI, provider secret, or model-visible value.
    pub sealed_coordinate_ref: String,
    /// Digest of the Snowman resolver/policy receipt.
    pub approval_evidence_sha256: String,
}

impl ApprovedConference {
    fn validate(&self) -> Result<(), Error> {
        validate_digest(&self.entrypoint_sha256, "approved entrypoint digest")?;
        validate_digest(
            &self.approval_evidence_sha256,
            "conference approval evidence",
        )?;
        validate_opaque_reference(&self.sealed_coordinate_ref)
    }
}

/// Explicit provider and retention policy evaluated before scheduling.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessingPolicy {
    /// Live audio route. Disabled is the default-off state.
    pub voice_route: VoiceRoute,
    /// Optional speech output route.
    pub speech_output_route: SpeechOutputRoute,
    /// Whether an external processor is expressly approved for this data class.
    pub external_processing_allowed: bool,
    /// Additional approval required before restricted data leaves Snowman AWS.
    pub restricted_external_approval_sha256: Option<String>,
    /// Exact policy evaluation evidence.
    pub policy_evidence_sha256: String,
    /// Hard maximum media spend, in millionths of a US dollar.
    pub max_cost_microusd: u64,
    /// Hard maximum session duration.
    pub max_duration_seconds: u32,
}

impl ProcessingPolicy {
    fn validate(&self, class: DataClass) -> Result<(), Error> {
        validate_digest(&self.policy_evidence_sha256, "processor policy evidence")?;
        if self.max_duration_seconds == 0
            || self.max_duration_seconds > MAX_MEETING_DURATION.num_seconds() as u32
            || self.max_cost_microusd > 1_000_000_000
        {
            return Err(Error::InvalidField("meeting duration or spend ceiling"));
        }
        let external = self.voice_route == VoiceRoute::OpenAiRealtime
            || self.speech_output_route == SpeechOutputRoute::ElevenLabs;
        if external && !self.external_processing_allowed {
            return Err(Error::ProcessorNotAuthorized);
        }
        if class == DataClass::Restricted && external {
            let Some(evidence) = &self.restricted_external_approval_sha256 else {
                return Err(Error::ProcessorNotAuthorized);
            };
            validate_digest(evidence, "restricted external approval")?;
        } else if self.restricted_external_approval_sha256.is_some() {
            return Err(Error::InvalidField("unexpected restricted approval"));
        }
        Ok(())
    }
}

/// Separate consent requirements for transcription, recording, and external
/// processing. Calendar attendance never satisfies these fields.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsentPolicy {
    /// Require audible/visible agent disclosure for every participant.
    pub disclosure_required: bool,
    /// Require explicit transcription consent.
    pub transcription_consent_required: bool,
    /// Whether raw audio recording is enabled after separate consent.
    pub recording_enabled: bool,
    /// Require separate consent before any external processing.
    pub external_processing_consent_required: bool,
    /// Raw audio retention mode.
    pub raw_audio_retention: RetentionMode,
    /// Transcript retention mode.
    pub transcript_retention: RetentionMode,
    /// Digest of jurisdiction-aware policy evidence.
    pub policy_evidence_sha256: String,
}

impl ConsentPolicy {
    fn validate(&self, processing: &ProcessingPolicy) -> Result<(), Error> {
        validate_digest(&self.policy_evidence_sha256, "consent policy evidence")?;
        if !self.disclosure_required {
            return Err(Error::InvalidField("agent disclosure must be required"));
        }
        if !self.recording_enabled && self.raw_audio_retention != RetentionMode::None {
            return Err(Error::InvalidField("raw audio retention without recording"));
        }
        let external = processing.voice_route == VoiceRoute::OpenAiRealtime
            || processing.speech_output_route == SpeechOutputRoute::ElevenLabs;
        if external && !self.external_processing_consent_required {
            return Err(Error::ProcessorNotAuthorized);
        }
        Ok(())
    }
}

/// Trusted schedule admission created only after organizer, account response,
/// tenant, conference, processor, consent, budget, and time policy evaluation.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeetingAdmission {
    /// Exact contract schema.
    pub schema_version: String,
    /// Stable Snowman meeting identifier.
    pub meeting_id: Uuid,
    /// Exact tenant boundary.
    pub tenant_id: Uuid,
    /// Exact workspace boundary.
    pub workspace_id: Uuid,
    /// Dedicated mailbox/calendar service identity.
    pub mailbox_identity_id: Uuid,
    /// Distinct meeting-agent service identity.
    pub meeting_agent_identity_id: Uuid,
    /// Parent Command Center thread, represented by an immutable digest.
    pub parent_thread_sha256: String,
    /// Fixed meeting data class.
    pub data_class: DataClass,
    /// Provider event coordinate copied from the exact admitted observation.
    pub provider_event_id_sha256: String,
    /// Exact admitted provider revision.
    pub provider_revision: u64,
    /// Trusted organizer policy result.
    pub organizer_approved: bool,
    /// Scheduled start.
    pub starts_at: DateTime<Utc>,
    /// Scheduled end.
    pub ends_at: DateTime<Utc>,
    /// Earliest time the media gateway may resolve the sealed coordinate.
    pub join_not_before: DateTime<Utc>,
    /// Latest time a join may begin.
    pub join_not_after: DateTime<Utc>,
    /// Trusted conference coordinate.
    pub conference: ApprovedConference,
    /// Explicit processor policy.
    pub processing: ProcessingPolicy,
    /// Explicit consent/retention policy.
    pub consent: ConsentPolicy,
    /// Digest of the complete admission evidence packet.
    pub admission_evidence_sha256: String,
    /// Untrusted source context, never authority.
    pub source_context: UntrustedContentRef,
}

impl MeetingAdmission {
    /// Construct and validate an admission against one exact Calendar revision.
    pub fn from_calendar(
        calendar: &CalendarObservation,
        admission: Self,
    ) -> Result<VerifiedMeetingAdmission, Error> {
        calendar.validate()?;
        admission.validate()?;
        if calendar.attendance != AttendanceStatus::Accepted
            || !admission.organizer_approved
            || calendar.tenant_id != admission.tenant_id
            || calendar.workspace_id != admission.workspace_id
            || calendar.mailbox_identity_id != admission.mailbox_identity_id
            || calendar.provider_event_id_sha256 != admission.provider_event_id_sha256
            || calendar.revision != admission.provider_revision
            || calendar.starts_at != admission.starts_at
            || calendar.ends_at != admission.ends_at
            || calendar.conference.kind != admission.conference.kind
            || calendar.conference.entrypoint_sha256 != admission.conference.entrypoint_sha256
            || calendar.content != admission.source_context
        {
            return Err(Error::BoundaryMismatch);
        }
        Ok(VerifiedMeetingAdmission(admission))
    }

    /// Validate admission invariants independent of its source observation.
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != MEETING_ADMISSION_SCHEMA || self.provider_revision == 0 {
            return Err(Error::InvalidField("meeting schema or provider revision"));
        }
        if self.mailbox_identity_id == self.meeting_agent_identity_id {
            return Err(Error::InvalidField("mailbox and meeting-agent identities"));
        }
        validate_digest(&self.parent_thread_sha256, "parent thread digest")?;
        validate_digest(&self.provider_event_id_sha256, "provider event digest")?;
        validate_digest(&self.admission_evidence_sha256, "admission evidence digest")?;
        validate_interval(self.starts_at, self.ends_at)?;
        if self.join_not_before > self.starts_at
            || self.join_not_after < self.starts_at
            || self.join_not_after <= self.join_not_before
            || self.join_not_after - self.join_not_before > MAX_JOIN_WINDOW
        {
            return Err(Error::InvalidField("join window"));
        }
        self.conference.validate()?;
        self.processing.validate(self.data_class)?;
        self.consent.validate(&self.processing)?;
        self.source_context.validate()
    }
}

/// Admission token obtainable only by matching a trusted admission to one
/// exact accepted Calendar observation. Scheduling accepts this type rather
/// than a freely constructed [`MeetingAdmission`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMeetingAdmission(MeetingAdmission);

impl VerifiedMeetingAdmission {
    /// Inspect the immutable, policy-evaluated meeting contract.
    pub fn admission(&self) -> &MeetingAdmission {
        &self.0
    }
}

/// A participant's current disclosure and consent evidence.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParticipantConsent {
    /// Pseudonymous participant digest.
    pub participant_subject_sha256: String,
    /// Evidence that the AI participant was disclosed to this participant.
    pub disclosure_evidence_sha256: Option<String>,
    /// Separate transcription consent evidence.
    pub transcription_consent_sha256: Option<String>,
    /// Separate recording consent evidence.
    pub recording_consent_sha256: Option<String>,
    /// Separate external-processing consent evidence.
    pub external_processing_consent_sha256: Option<String>,
    /// When this participant's current evidence was observed.
    pub observed_at: DateTime<Utc>,
}

impl ParticipantConsent {
    fn validate(&self, policy: &ConsentPolicy, processing: &ProcessingPolicy) -> Result<(), Error> {
        validate_digest(&self.participant_subject_sha256, "participant digest")?;
        require_optional_digest(
            &self.disclosure_evidence_sha256,
            policy.disclosure_required,
            "disclosure evidence",
        )?;
        require_optional_digest(
            &self.transcription_consent_sha256,
            policy.transcription_consent_required,
            "transcription consent",
        )?;
        require_optional_digest(
            &self.recording_consent_sha256,
            policy.recording_enabled,
            "recording consent",
        )?;
        let external = processing.voice_route == VoiceRoute::OpenAiRealtime
            || processing.speech_output_route == SpeechOutputRoute::ElevenLabs;
        require_optional_digest(
            &self.external_processing_consent_sha256,
            external && policy.external_processing_consent_required,
            "external-processing consent",
        )
    }
}

/// Durable scheduling lifecycle. Cancellation is terminal for a provider
/// revision and invalidates any active session generation.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    /// Accepted but no join is currently in progress.
    Scheduled,
    /// The join window was reached and a session generation was allocated.
    Joining,
    /// Media is active after consent validation.
    Active,
    /// The exact provider event was cancelled or invalidated.
    Cancelled,
    /// The join window elapsed without activation.
    Expired,
    /// The session ended normally.
    Completed,
}

/// Current durable state for one admitted meeting.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScheduledMeeting {
    /// Trusted immutable admission.
    admission: MeetingAdmission,
    /// Monotonic Snowman schedule revision.
    schedule_revision: u64,
    /// Monotonic session fencing generation.
    session_generation: u32,
    /// Current lifecycle state.
    status: ScheduleStatus,
    /// Current participant consent evidence.
    participants: BTreeMap<String, ParticipantConsent>,
    /// Last trusted state transition time.
    updated_at: DateTime<Utc>,
}

impl ScheduledMeeting {
    /// Return the immutable policy admission.
    pub fn admission(&self) -> &MeetingAdmission {
        &self.admission
    }

    /// Return the current durable scheduling revision.
    pub fn schedule_revision(&self) -> u64 {
        self.schedule_revision
    }

    /// Return the current fenced session generation.
    pub fn session_generation(&self) -> u32 {
        self.session_generation
    }

    /// Return the current scheduling lifecycle.
    pub fn status(&self) -> ScheduleStatus {
        self.status
    }

    /// Return the last trusted state-transition time.
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// Start a new fenced join attempt within the admitted join window.
    pub fn begin_join(&mut self, now: DateTime<Utc>) -> Result<u32, Error> {
        if self.status != ScheduleStatus::Scheduled
            || now < self.admission.join_not_before
            || now > self.admission.join_not_after
            || self.admission.processing.voice_route == VoiceRoute::Disabled
        {
            return Err(Error::InvalidTransition);
        }
        self.session_generation = self
            .session_generation
            .checked_add(1)
            .ok_or(Error::InvalidTransition)?;
        self.status = ScheduleStatus::Joining;
        self.updated_at = now;
        Ok(self.session_generation)
    }

    /// Register or replace participant evidence. A late joiner immediately
    /// pauses an active route until the complete policy is satisfied again.
    pub fn record_participant(
        &mut self,
        participant: ParticipantConsent,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        validate_digest(
            &participant.participant_subject_sha256,
            "participant digest",
        )?;
        self.participants
            .insert(participant.participant_subject_sha256.clone(), participant);
        if self.status == ScheduleStatus::Active && !self.all_participants_consented() {
            self.status = ScheduleStatus::Joining;
        }
        self.updated_at = now;
        Ok(())
    }

    /// Activate media only after every present participant satisfies every
    /// independently required consent dimension.
    pub fn activate_media(&mut self, generation: u32, now: DateTime<Utc>) -> Result<(), Error> {
        if self.status != ScheduleStatus::Joining
            || generation != self.session_generation
            || self.participants.is_empty()
        {
            return Err(Error::InvalidTransition);
        }
        if !self.all_participants_consented() {
            return Err(Error::ConsentIncomplete);
        }
        self.status = ScheduleStatus::Active;
        self.updated_at = now;
        Ok(())
    }

    /// End the current fenced session. A stale generation cannot end a newer
    /// attempt.
    pub fn complete(&mut self, generation: u32, now: DateTime<Utc>) -> Result<(), Error> {
        if generation != self.session_generation
            || !matches!(
                self.status,
                ScheduleStatus::Joining | ScheduleStatus::Active
            )
        {
            return Err(Error::InvalidTransition);
        }
        self.status = ScheduleStatus::Completed;
        self.updated_at = now;
        Ok(())
    }

    fn all_participants_consented(&self) -> bool {
        self.participants.values().all(|participant| {
            participant
                .validate(&self.admission.consent, &self.admission.processing)
                .is_ok()
        })
    }
}

/// Idempotent command result returned by the schedule book.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyResult {
    /// A new durable state transition was applied.
    Applied {
        /// New Snowman schedule revision.
        schedule_revision: u64,
    },
    /// The same command and digest had already been applied.
    Duplicate {
        /// Existing Snowman schedule revision.
        schedule_revision: u64,
    },
}

/// Trusted cancellation for one exact provider event revision. Remote email or
/// speech content cannot construct this authority without an independently
/// verified cancellation evidence digest.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CancellationCommand {
    /// Idempotency key within the tenant.
    pub command_id: Uuid,
    /// Exact tenant boundary.
    pub tenant_id: Uuid,
    /// Exact admitted meeting.
    pub meeting_id: Uuid,
    /// Exact provider event coordinate.
    pub provider_event_id_sha256: String,
    /// Current or newer trusted provider revision.
    pub provider_revision: u64,
    /// Digest of the cancellation/revocation evidence.
    pub cancellation_evidence_sha256: String,
}

#[derive(Debug, Clone)]
struct CommandReceipt {
    digest: String,
    schedule_revision: u64,
}

/// In-memory reference state machine used by adapters and deterministic tests.
/// Production persistence mirrors these invariants in migration 0048.
#[derive(Debug, Default)]
pub struct ScheduleBook {
    meetings: BTreeMap<(Uuid, Uuid), ScheduledMeeting>,
    receipts: BTreeMap<(Uuid, Uuid), CommandReceipt>,
}

impl ScheduleBook {
    /// Admit or replace one meeting only with a strictly newer provider
    /// revision. The command ID is idempotent within a tenant.
    pub fn schedule(
        &mut self,
        command_id: Uuid,
        admission: VerifiedMeetingAdmission,
        now: DateTime<Utc>,
    ) -> Result<ApplyResult, Error> {
        admission.0.validate()?;
        let digest = canonical_digest(&admission.0)?;
        if let Some(result) = self.replay(admission.0.tenant_id, command_id, &digest)? {
            return Ok(result);
        }
        let admission = admission.0;
        let key = (admission.tenant_id, admission.meeting_id);
        let schedule_revision = match self.meetings.get(&key) {
            Some(existing)
                if admission.provider_revision <= existing.admission.provider_revision =>
            {
                return Err(Error::StaleRevision);
            }
            Some(existing) => existing.schedule_revision + 1,
            None => 1,
        };
        self.meetings.insert(
            key,
            ScheduledMeeting {
                admission,
                schedule_revision,
                session_generation: 0,
                status: ScheduleStatus::Scheduled,
                participants: BTreeMap::new(),
                updated_at: now,
            },
        );
        self.receipts.insert(
            (key.0, command_id),
            CommandReceipt {
                digest,
                schedule_revision,
            },
        );
        Ok(ApplyResult::Applied { schedule_revision })
    }

    /// Cancel one exact meeting revision idempotently. The caller must provide
    /// the trusted provider event digest; untrusted message text is insufficient.
    pub fn cancel(
        &mut self,
        command: CancellationCommand,
        now: DateTime<Utc>,
    ) -> Result<ApplyResult, Error> {
        validate_digest(&command.provider_event_id_sha256, "provider event digest")?;
        validate_digest(
            &command.cancellation_evidence_sha256,
            "cancellation evidence",
        )?;
        let digest = canonical_digest(&(
            command.meeting_id,
            &command.provider_event_id_sha256,
            command.provider_revision,
            &command.cancellation_evidence_sha256,
        ))?;
        if let Some(result) = self.replay(command.tenant_id, command.command_id, &digest)? {
            return Ok(result);
        }
        let meeting = self
            .meetings
            .get_mut(&(command.tenant_id, command.meeting_id))
            .ok_or(Error::BoundaryMismatch)?;
        if meeting.admission.provider_event_id_sha256 != command.provider_event_id_sha256
            || command.provider_revision < meeting.admission.provider_revision
        {
            return Err(Error::StaleRevision);
        }
        if meeting.status == ScheduleStatus::Cancelled {
            return Err(Error::StaleRevision);
        }
        meeting.schedule_revision += 1;
        meeting.session_generation = meeting
            .session_generation
            .checked_add(1)
            .ok_or(Error::InvalidTransition)?;
        meeting.status = ScheduleStatus::Cancelled;
        meeting.participants.clear();
        meeting.updated_at = now;
        let schedule_revision = meeting.schedule_revision;
        self.receipts.insert(
            (command.tenant_id, command.command_id),
            CommandReceipt {
                digest,
                schedule_revision,
            },
        );
        Ok(ApplyResult::Applied { schedule_revision })
    }

    /// Read one meeting only under its exact tenant key.
    pub fn get(&self, tenant_id: Uuid, meeting_id: Uuid) -> Option<&ScheduledMeeting> {
        self.meetings.get(&(tenant_id, meeting_id))
    }

    fn replay(
        &self,
        tenant_id: Uuid,
        command_id: Uuid,
        digest: &str,
    ) -> Result<Option<ApplyResult>, Error> {
        match self.receipts.get(&(tenant_id, command_id)) {
            None => Ok(None),
            Some(receipt) if receipt.digest == digest => Ok(Some(ApplyResult::Duplicate {
                schedule_revision: receipt.schedule_revision,
            })),
            Some(_) => Err(Error::IdempotencyConflict),
        }
    }
}

/// The only model-originated meeting actions accepted by the control plane.
/// No variant includes a provider route, conference coordinate, phone number,
/// URL, recipient, credential, consent decision, retention choice, or policy.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MeetingToolIntent {
    /// Propose an action item for governed workforce review.
    ProposeActionItem {
        /// Bounded untrusted action title.
        title: String,
        /// Bounded untrusted supporting detail.
        detail: String,
        /// Optional pre-existing Snowman workforce identity.
        owner_identity_id: Option<Uuid>,
        /// Optional proposed due time; policy decides whether to accept it.
        due_at: Option<DateTime<Utc>>,
    },
    /// Ask participants to clarify an owner without assigning one itself.
    ClarifyOwner {
        /// Existing action-item identifier.
        action_item_id: Uuid,
        /// Bounded question spoken in the current meeting.
        question: String,
    },
    /// Propose a durable decision with bounded evidence references.
    RecordDecision {
        /// Bounded untrusted decision statement.
        statement: String,
        /// Bounded untrusted rationale.
        rationale: String,
        /// Immutable Analyst artifact IDs already admitted to this meeting.
        evidence_artifact_ids: Vec<Uuid>,
    },
    /// Request a specialist workforce task through the normal policy gateway.
    RequestSpecialistWork {
        /// Bounded objective; still untrusted until workforce admission.
        objective: String,
        /// Existing policy-catalog role, not a runtime or model identifier.
        specialist_role: String,
        /// Existing policy-catalog artifact type.
        artifact_type: String,
    },
}

impl MeetingToolIntent {
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::ProposeActionItem { title, detail, .. } => {
                validate_text(title, 1, 512, "action title")?;
                validate_text(detail, 0, MAX_INTENT_TEXT_BYTES, "action detail")
            }
            Self::ClarifyOwner { question, .. } => {
                validate_text(question, 1, 1024, "owner question")
            }
            Self::RecordDecision {
                statement,
                rationale,
                evidence_artifact_ids,
            } => {
                validate_text(statement, 1, 2048, "decision statement")?;
                validate_text(rationale, 0, MAX_INTENT_TEXT_BYTES, "decision rationale")?;
                if evidence_artifact_ids.len() > MAX_EVIDENCE_REFERENCES {
                    return Err(Error::InvalidField("decision evidence references"));
                }
                Ok(())
            }
            Self::RequestSpecialistWork {
                objective,
                specialist_role,
                artifact_type,
            } => {
                validate_text(objective, 1, MAX_INTENT_TEXT_BYTES, "specialist objective")?;
                validate_catalog_id(specialist_role, "specialist role")?;
                validate_catalog_id(artifact_type, "artifact type")
            }
        }
    }
}

/// Tenant-, meeting-, session-, and generation-bound model intent envelope.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeetingToolIntentEnvelope {
    /// Exact contract schema.
    pub schema_version: String,
    /// Unique intent idempotency key.
    pub intent_id: Uuid,
    /// Exact tenant boundary.
    pub tenant_id: Uuid,
    /// Exact workspace boundary.
    pub workspace_id: Uuid,
    /// Exact admitted meeting.
    pub meeting_id: Uuid,
    /// Exact fenced media session.
    pub session_id: Uuid,
    /// Exact session generation.
    pub session_generation: u32,
    /// Meeting-agent service identity that proposed the intent.
    pub service_identity_id: Uuid,
    /// Digest of the exact provider/model turn receipt.
    pub source_turn_sha256: String,
    /// When Snowman received the intent.
    pub observed_at: DateTime<Utc>,
    /// Narrow intent. Its text remains untrusted workforce input.
    pub intent: MeetingToolIntent,
}

impl MeetingToolIntentEnvelope {
    /// Validate structural bounds before live session and tenant authority are
    /// rechecked by the policy gateway.
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != MEETING_TOOL_INTENT_SCHEMA || self.session_generation == 0 {
            return Err(Error::InvalidField("tool intent schema or generation"));
        }
        validate_digest(&self.source_turn_sha256, "source turn digest")?;
        self.intent.validate()
    }
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

fn require_optional_digest(
    value: &Option<String>,
    required: bool,
    field: &'static str,
) -> Result<(), Error> {
    match value {
        Some(value) => validate_digest(value, field),
        None if required => Err(Error::ConsentIncomplete),
        None => Ok(()),
    }
}

fn validate_text(
    value: &str,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), Error> {
    if value.len() < minimum || value.len() > maximum || value.contains('\0') {
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
        || value.contains("://")
        || value.to_ascii_lowercase().starts_with("sip:")
        || value.contains('@')
        || value.contains('+')
        || value.chars().all(|character| character.is_ascii_digit())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(Error::InvalidField(
            "sealed conference coordinate reference",
        ));
    }
    Ok(())
}

fn validate_interval(starts_at: DateTime<Utc>, ends_at: DateTime<Utc>) -> Result<(), Error> {
    if ends_at <= starts_at || ends_at - starts_at > MAX_MEETING_DURATION {
        return Err(Error::InvalidField("meeting interval"));
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::InvalidField("command body"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, SHA256_HEX_LEN).collect()
    }

    fn content(seed: char) -> UntrustedContentRef {
        UntrustedContentRef {
            authority: "analyst360".into(),
            artifact_id: Uuid::new_v4(),
            content_sha256: digest(seed),
            label: "calendar context".into(),
        }
    }

    fn calendar(tenant_id: Uuid, workspace_id: Uuid, mailbox: Uuid) -> CalendarObservation {
        let starts_at = Utc::now() + Duration::hours(1);
        CalendarObservation {
            schema_version: CALENDAR_OBSERVATION_SCHEMA.into(),
            tenant_id,
            workspace_id,
            mailbox_identity_id: mailbox,
            provider_event_id_sha256: digest('a'),
            provider_revision_sha256: digest('b'),
            revision: 7,
            organizer_subject_sha256: digest('c'),
            attendance: AttendanceStatus::Accepted,
            starts_at,
            ends_at: starts_at + Duration::hours(1),
            conference: ConferenceCandidate {
                kind: ConferenceKind::Telephony,
                entrypoint_sha256: digest('d'),
                metadata_sha256: digest('e'),
            },
            content: content('f'),
            observed_at: Utc::now(),
        }
    }

    fn admission(calendar: &CalendarObservation) -> MeetingAdmission {
        MeetingAdmission {
            schema_version: MEETING_ADMISSION_SCHEMA.into(),
            meeting_id: Uuid::new_v4(),
            tenant_id: calendar.tenant_id,
            workspace_id: calendar.workspace_id,
            mailbox_identity_id: calendar.mailbox_identity_id,
            meeting_agent_identity_id: Uuid::new_v4(),
            parent_thread_sha256: digest('1'),
            data_class: DataClass::Confidential,
            provider_event_id_sha256: calendar.provider_event_id_sha256.clone(),
            provider_revision: calendar.revision,
            organizer_approved: true,
            starts_at: calendar.starts_at,
            ends_at: calendar.ends_at,
            join_not_before: calendar.starts_at - Duration::minutes(5),
            join_not_after: calendar.starts_at + Duration::minutes(5),
            conference: ApprovedConference {
                kind: calendar.conference.kind,
                entrypoint_sha256: calendar.conference.entrypoint_sha256.clone(),
                sealed_coordinate_ref: "snowman-coordinate:meeting-123".into(),
                approval_evidence_sha256: digest('2'),
            },
            processing: ProcessingPolicy {
                voice_route: VoiceRoute::SnowmanAws,
                speech_output_route: SpeechOutputRoute::VoiceRoute,
                external_processing_allowed: false,
                restricted_external_approval_sha256: None,
                policy_evidence_sha256: digest('3'),
                max_cost_microusd: 500_000,
                max_duration_seconds: 3_600,
            },
            consent: ConsentPolicy {
                disclosure_required: true,
                transcription_consent_required: true,
                recording_enabled: false,
                external_processing_consent_required: false,
                raw_audio_retention: RetentionMode::None,
                transcript_retention: RetentionMode::AnalystEvidence,
                policy_evidence_sha256: digest('4'),
            },
            admission_evidence_sha256: digest('5'),
            source_context: calendar.content.clone(),
        }
    }

    #[test]
    fn email_is_context_only_and_cannot_deserialize_policy_fields() {
        let tenant = Uuid::new_v4();
        let workspace = Uuid::new_v4();
        let mailbox = Uuid::new_v4();
        let raw = json!({
            "schema_version": MAIL_OBSERVATION_SCHEMA,
            "tenant_id": tenant,
            "workspace_id": workspace,
            "mailbox_identity_id": mailbox,
            "provider_message_id_sha256": digest('1'),
            "history_id": 9,
            "sender_subject_sha256": digest('2'),
            "observed_at": Utc::now(),
            "content": content('3'),
            "voice_route": "open_ai_realtime",
            "dial_number": "+15551234567"
        });
        assert!(serde_json::from_value::<MailObservation>(raw).is_err());
    }

    #[test]
    fn calendar_admission_is_exactly_tenant_revision_and_coordinate_bound() {
        let calendar = calendar(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let approved = MeetingAdmission::from_calendar(&calendar, admission(&calendar));
        assert!(approved.is_ok());

        let mut cross_tenant = admission(&calendar);
        cross_tenant.tenant_id = Uuid::new_v4();
        assert_eq!(
            MeetingAdmission::from_calendar(&calendar, cross_tenant),
            Err(Error::BoundaryMismatch)
        );

        let mut replaced_dial_target = admission(&calendar);
        replaced_dial_target.conference.entrypoint_sha256 = digest('9');
        assert_eq!(
            MeetingAdmission::from_calendar(&calendar, replaced_dial_target),
            Err(Error::BoundaryMismatch)
        );
    }

    #[test]
    fn forwarded_mail_never_authorizes_schedule_or_join() {
        let calendar = calendar(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut unaccepted = calendar.clone();
        unaccepted.attendance = AttendanceStatus::NeedsAction;
        assert_eq!(
            MeetingAdmission::from_calendar(&unaccepted, admission(&unaccepted)),
            Err(Error::BoundaryMismatch)
        );

        let mut disabled = admission(&calendar);
        disabled.processing.voice_route = VoiceRoute::Disabled;
        let disabled = MeetingAdmission::from_calendar(&calendar, disabled).unwrap();
        let mut book = ScheduleBook::default();
        book.schedule(Uuid::new_v4(), disabled, Utc::now()).unwrap();
        let meeting = book
            .get(calendar.tenant_id, book.meetings.keys().next().unwrap().1)
            .unwrap();
        let mut meeting = meeting.clone();
        assert_eq!(
            meeting.begin_join(calendar.starts_at),
            Err(Error::InvalidTransition)
        );
    }

    #[test]
    fn scheduling_and_cancellation_are_digest_idempotent_and_fenced() {
        let calendar = calendar(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let admitted = MeetingAdmission::from_calendar(&calendar, admission(&calendar)).unwrap();
        let meeting_id = admitted.admission().meeting_id;
        let command_id = Uuid::new_v4();
        let now = Utc::now();
        let mut book = ScheduleBook::default();
        assert_eq!(
            book.schedule(command_id, admitted.clone(), now),
            Ok(ApplyResult::Applied {
                schedule_revision: 1
            })
        );
        assert_eq!(
            book.schedule(command_id, admitted.clone(), now),
            Ok(ApplyResult::Duplicate {
                schedule_revision: 1
            })
        );

        let mut conflict = admitted.admission().clone();
        conflict.admission_evidence_sha256 = digest('9');
        let conflict = MeetingAdmission::from_calendar(&calendar, conflict).unwrap();
        assert_eq!(
            book.schedule(command_id, conflict, now),
            Err(Error::IdempotencyConflict)
        );

        let cancel_id = Uuid::new_v4();
        assert_eq!(
            book.cancel(
                CancellationCommand {
                    command_id: cancel_id,
                    tenant_id: calendar.tenant_id,
                    meeting_id,
                    provider_event_id_sha256: calendar.provider_event_id_sha256.clone(),
                    provider_revision: calendar.revision,
                    cancellation_evidence_sha256: digest('8'),
                },
                now,
            ),
            Ok(ApplyResult::Applied {
                schedule_revision: 2
            })
        );
        assert_eq!(
            book.cancel(
                CancellationCommand {
                    command_id: cancel_id,
                    tenant_id: calendar.tenant_id,
                    meeting_id,
                    provider_event_id_sha256: calendar.provider_event_id_sha256.clone(),
                    provider_revision: calendar.revision,
                    cancellation_evidence_sha256: digest('8'),
                },
                now,
            ),
            Ok(ApplyResult::Duplicate {
                schedule_revision: 2
            })
        );
        assert_eq!(
            book.get(calendar.tenant_id, meeting_id).unwrap().status(),
            ScheduleStatus::Cancelled
        );
        assert!(book.get(Uuid::new_v4(), meeting_id).is_none());
    }

    #[test]
    fn late_joiner_pauses_media_until_separate_consents_exist() {
        let calendar = calendar(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let admitted = MeetingAdmission::from_calendar(&calendar, admission(&calendar)).unwrap();
        let meeting_id = admitted.admission().meeting_id;
        let mut book = ScheduleBook::default();
        book.schedule(Uuid::new_v4(), admitted, Utc::now()).unwrap();
        let meeting = book
            .meetings
            .get_mut(&(calendar.tenant_id, meeting_id))
            .unwrap();
        let generation = meeting.begin_join(calendar.starts_at).unwrap();
        let participant = |seed| ParticipantConsent {
            participant_subject_sha256: digest(seed),
            disclosure_evidence_sha256: Some(digest('a')),
            transcription_consent_sha256: Some(digest('b')),
            recording_consent_sha256: None,
            external_processing_consent_sha256: None,
            observed_at: Utc::now(),
        };
        meeting
            .record_participant(participant('1'), calendar.starts_at)
            .unwrap();
        meeting
            .activate_media(generation, calendar.starts_at)
            .unwrap();
        assert_eq!(meeting.status, ScheduleStatus::Active);

        let mut late = participant('2');
        late.transcription_consent_sha256 = None;
        meeting
            .record_participant(late, calendar.starts_at + Duration::minutes(1))
            .unwrap();
        assert_eq!(meeting.status, ScheduleStatus::Joining);
        assert_eq!(
            meeting.activate_media(generation, calendar.starts_at),
            Err(Error::ConsentIncomplete)
        );
    }

    #[test]
    fn external_and_restricted_routes_fail_without_explicit_policy_and_consent() {
        let calendar = calendar(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut external = admission(&calendar);
        external.processing.voice_route = VoiceRoute::OpenAiRealtime;
        assert_eq!(external.validate(), Err(Error::ProcessorNotAuthorized));

        external.processing.external_processing_allowed = true;
        assert_eq!(external.validate(), Err(Error::ProcessorNotAuthorized));

        external.consent.external_processing_consent_required = true;
        external.data_class = DataClass::Restricted;
        assert_eq!(external.validate(), Err(Error::ProcessorNotAuthorized));

        external.processing.restricted_external_approval_sha256 = Some(digest('7'));
        assert!(external.validate().is_ok());
    }

    #[test]
    fn model_tool_contract_rejects_phone_provider_and_consent_injection() {
        let raw = json!({
            "schema_version": MEETING_TOOL_INTENT_SCHEMA,
            "intent_id": Uuid::new_v4(),
            "tenant_id": Uuid::new_v4(),
            "workspace_id": Uuid::new_v4(),
            "meeting_id": Uuid::new_v4(),
            "session_id": Uuid::new_v4(),
            "session_generation": 1,
            "service_identity_id": Uuid::new_v4(),
            "source_turn_sha256": digest('1'),
            "observed_at": Utc::now(),
            "intent": {
                "kind": "request_specialist_work",
                "objective": "build the approved artifact",
                "specialist_role": "client_delivery",
                "artifact_type": "presentation",
                "phone_number": "+15551234567",
                "provider": "twilio",
                "consent": true
            }
        });
        assert!(serde_json::from_value::<MeetingToolIntentEnvelope>(raw).is_err());
    }

    #[test]
    fn sealed_coordinate_rejects_urls_sip_addresses_and_phone_numbers() {
        for value in [
            "https://meet.example/secret",
            "sip:room@example.com",
            "+15551234567",
            "1555123456789012",
        ] {
            let calendar = calendar(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
            let mut admitted = admission(&calendar);
            admitted.conference.sealed_coordinate_ref = value.into();
            assert_eq!(
                admitted.validate(),
                Err(Error::InvalidField(
                    "sealed conference coordinate reference"
                ))
            );
        }
    }
}
