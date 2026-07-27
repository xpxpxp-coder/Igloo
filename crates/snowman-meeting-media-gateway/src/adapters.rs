//! Transport-injected provider adapters for the governed media gateway.
//!
//! The adapters turn an already-fenced [`AdapterLease`] into exact provider
//! protocol operations. They never read process environment variables or
//! files, never accept a dial target from speech/model input, and never retain
//! audio. Network and secret access are deliberately delegated to a private
//! Snowman service transport so unit tests can prove the wire contract without
//! credentials or live traffic.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use super::{
    AuthenticatedWebhook, Error, Provider, SpeechRenderRequest, TransientAudioFrame,
    WebhookAuthenticator, WebhookRequest,
};

const MAX_PROTOCOL_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_AUDIO_BYTES: usize = 1024 * 1024;
const MAX_CLOCK_SKEW: Duration = Duration::minutes(5);

/// A short-lived, target-free authority released by an active media session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterLease {
    /// Exact tenant.
    pub tenant_id: Uuid,
    /// Exact workspace.
    pub workspace_id: Uuid,
    /// Exact meeting.
    pub meeting_id: Uuid,
    /// Exact media session.
    pub session_id: Uuid,
    /// Exact cancellation fence.
    pub session_generation: u32,
    /// Provider this lease may operate.
    pub provider: Provider,
    /// Digest of the operations-owned account/project binding.
    pub provider_binding_sha256: String,
    /// Digest of the admitted conference coordinate approval.
    pub conference_approval_sha256: String,
    /// Opaque resolver reference; never a URL, phone number, or SIP URI.
    pub sealed_coordinate_ref: String,
    /// Hard provider deadline.
    pub deadline: DateTime<Utc>,
    /// Short lease expiry. Cancellation prevents renewal, bounding stale use.
    pub lease_expires_at: DateTime<Utc>,
    /// Remaining hard cost ceiling.
    pub remaining_cost_microusd: u64,
}

impl AdapterLease {
    fn validate(&self, provider: Provider, now: DateTime<Utc>) -> Result<(), Error> {
        if self.provider != provider
            || self.session_generation == 0
            || now >= self.deadline
            || now >= self.lease_expires_at
            || self.lease_expires_at > self.deadline
            || self.remaining_cost_microusd == 0
        {
            return Err(Error::BudgetExceeded);
        }
        super::validate_digest(&self.provider_binding_sha256, "provider binding")?;
        super::validate_digest(&self.conference_approval_sha256, "conference approval")?;
        super::validate_opaque_reference(&self.sealed_coordinate_ref)
    }
}

/// Opaque AWS Secrets Manager reference resolved only inside the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    arn: String,
    version_sha256: String,
}

impl SecretRef {
    /// Construct a purpose-specific Secrets Manager reference.
    pub fn new(arn: String, version_sha256: String) -> Result<Self, Error> {
        if !arn.starts_with("arn:aws:secretsmanager:")
            || arn.len() > 512
            || arn.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(Error::InvalidField("provider secret reference"));
        }
        super::validate_digest(&version_sha256, "provider secret version")?;
        Ok(Self {
            arn,
            version_sha256,
        })
    }

    /// Digest identifying the exact secret version, without exposing it.
    pub fn version_sha256(&self) -> &str {
        &self.version_sha256
    }
}

/// One exact operations-owned endpoint and credential binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEndpoint {
    /// Provider family.
    pub provider: Provider,
    /// Exact HTTPS or WSS URL supplied by operations.
    pub exact_url: Url,
    /// Purpose-specific secret reference, absent for native huddles.
    pub secret: Option<SecretRef>,
    /// Digest of the provider account/project registration.
    pub binding_sha256: String,
}

impl ProviderEndpoint {
    /// Validate a provider endpoint. Redirect targets are never accepted later.
    pub fn validate(&self) -> Result<(), Error> {
        if !matches!(self.exact_url.scheme(), "https" | "wss")
            || self.exact_url.host_str().is_none()
            || self.exact_url.username() != ""
            || self.exact_url.password().is_some()
            || self.exact_url.fragment().is_some()
            || is_block_host(self.exact_url.host_str().unwrap_or_default())
        {
            return Err(Error::ProviderDisabled);
        }
        super::validate_digest(&self.binding_sha256, "endpoint binding")?;
        match self.provider {
            Provider::SnowmanHuddle => {
                if self.exact_url.scheme() != "wss" || self.secret.is_some() {
                    return Err(Error::ProviderDisabled);
                }
            }
            Provider::Twilio | Provider::OpenAiRealtime | Provider::ElevenLabs => {
                if self.secret.is_none() {
                    return Err(Error::ProviderDisabled);
                }
            }
            Provider::SnowmanAws => return Err(Error::ProviderDisabled),
        }
        Ok(())
    }
}

/// One provider-scoped exact egress rule. URL paths may only become narrower.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    /// Provider family.
    pub provider: Provider,
    /// Required URL scheme.
    pub scheme: String,
    /// Exact DNS name.
    pub host: String,
    /// Exact port (explicit or scheme default).
    pub port: u16,
    /// Required path prefix.
    pub path_prefix: String,
}

/// Default-deny provider egress policy.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
    rules: Vec<EgressRule>,
}

impl EgressPolicy {
    /// Construct a default-deny policy from operations-owned exact rules.
    pub fn new(rules: Vec<EgressRule>) -> Result<Self, Error> {
        if rules.is_empty() {
            return Err(Error::ProviderDisabled);
        }
        for rule in &rules {
            if !matches!(rule.scheme.as_str(), "https" | "wss")
                || rule.host.is_empty()
                || is_block_host(&rule.host)
                || !rule.path_prefix.starts_with('/')
            {
                return Err(Error::ProviderDisabled);
            }
        }
        Ok(Self { rules })
    }

    /// Authorize one exact endpoint without redirects, proxies, or DNS aliases.
    pub fn authorize(&self, endpoint: &ProviderEndpoint) -> Result<(), Error> {
        endpoint.validate()?;
        let host = endpoint
            .exact_url
            .host_str()
            .ok_or(Error::ProviderDisabled)?;
        let port = endpoint
            .exact_url
            .port_or_known_default()
            .ok_or(Error::ProviderDisabled)?;
        if self.rules.iter().any(|rule| {
            rule.provider == endpoint.provider
                && rule.scheme == endpoint.exact_url.scheme()
                && rule.host.eq_ignore_ascii_case(host)
                && rule.port == port
                && endpoint.exact_url.path().starts_with(&rule.path_prefix)
        }) {
            Ok(())
        } else {
            Err(Error::ProviderDisabled)
        }
    }
}

fn is_block_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "block.xyz"
        || host.ends_with(".block.xyz")
        || host == "squareup.com"
        || host.ends_with(".squareup.com")
        || host == "buzz.block.xyz"
}

/// Trusted result of resolving a sealed coordinate inside Snowman services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// Provider that owns the target.
    pub provider: Provider,
    /// Short-lived opaque target token consumed by the private transport.
    pub target_token: String,
    /// Digest of the exact target, for evidence and provider-session matching.
    pub target_sha256: String,
    /// Approval digest copied from the admitted conference coordinate.
    pub approval_sha256: String,
    /// Token expiry.
    pub expires_at: DateTime<Utc>,
}

/// Resolver for a pre-approved target. No caller may supply a raw destination.
pub trait SealedTargetResolver: Send + Sync {
    /// Resolve the exact opaque reference under its session fence.
    fn resolve(&self, lease: &AdapterLease, now: DateTime<Utc>) -> Result<ResolvedTarget, Error>;
}

fn resolve_target(
    resolver: &dyn SealedTargetResolver,
    lease: &AdapterLease,
    now: DateTime<Utc>,
) -> Result<ResolvedTarget, Error> {
    let target = resolver.resolve(lease, now)?;
    if target.provider != lease.provider
        || target.approval_sha256 != lease.conference_approval_sha256
        || target.expires_at <= now
        || target.expires_at > lease.deadline
        || target.target_token.is_empty()
        || target.target_token.len() > 512
        || target.target_token.contains("sip:")
        || target.target_token.contains("tel:")
        || target.target_token.contains("https://")
        || target.target_token.contains("wss://")
    {
        return Err(Error::UntrustedAuthority);
    }
    super::validate_digest(&target.target_sha256, "resolved target")?;
    Ok(target)
}

/// Exact operation executed by the private provider transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportOperation {
    /// Join the exact admitted native huddle.
    JoinSnowmanHuddle {
        /// Fenced target token.
        target_token: String,
        /// Session.
        session_id: Uuid,
        /// Fence.
        generation: u32,
    },
    /// Start one Twilio call/Media Stream using a sealed target token.
    StartTwilioMediaStream {
        /// Fenced target token; never a number or SIP URI.
        target_token: String,
        /// Exact public Snowman WSS callback, pre-bound by operations.
        stream_callback_url: Url,
        /// Session.
        session_id: Uuid,
        /// Fence.
        generation: u32,
    },
    /// Send one Twilio WebSocket protocol message.
    TwilioWebSocketMessage {
        /// Pseudonymous stream binding.
        stream_id_sha256: String,
        /// Exact JSON bytes.
        message: Vec<u8>,
    },
    /// Open a server-to-server OpenAI Realtime WebSocket.
    OpenAiRealtimeConnect {
        /// Privacy-preserving stable subject digest.
        safety_identifier: String,
        /// Operations-catalog model.
        model_catalog_id: String,
        /// Session.
        session_id: Uuid,
        /// Fence.
        generation: u32,
    },
    /// Send one OpenAI Realtime client event.
    OpenAiRealtimeEvent {
        /// Provider-session digest.
        provider_session_sha256: String,
        /// Exact JSON bytes.
        event: Vec<u8>,
    },
    /// Accept/reject/hang up a pre-authorized OpenAI SIP call.
    OpenAiSipControl {
        /// Action is deliberately limited; transfer/refer is unsupported.
        action: SipAction,
        /// Provider call ID from an authenticated webhook.
        call_id: String,
        /// Optional exact accept configuration JSON.
        body: Option<Vec<u8>>,
    },
    /// Open the server-side sideband WebSocket for an admitted SIP call.
    OpenAiSipSidebandConnect {
        /// Provider call ID from the authenticated webhook.
        call_id: String,
        /// Session.
        session_id: Uuid,
        /// Fence.
        generation: u32,
    },
    /// Open output-only ElevenLabs streaming TTS.
    ElevenLabsRender {
        /// Operations-catalog voice.
        voice_catalog_id: String,
        /// Operations-catalog model.
        model_catalog_id: String,
        /// Approved response text only.
        approved_text: String,
        /// Approved model-turn digest.
        approved_turn_sha256: String,
    },
    /// Stop provider activity under the exact fence.
    Stop {
        /// Provider.
        provider: Provider,
        /// Session.
        session_id: Uuid,
        /// Fence.
        generation: u32,
    },
}

/// One provider request after egress and authority checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportRequest {
    /// Exact injected endpoint.
    pub endpoint: ProviderEndpoint,
    /// Provider operation.
    pub operation: TransportOperation,
    /// Deadline inherited from the media lease.
    pub deadline: DateTime<Utc>,
    /// Maximum provider spend for this operation.
    pub max_cost_microusd: u64,
}

/// PII-minimized transport result. Raw audio is returned transiently only.
pub struct TransportResponse {
    /// Provider-assigned session ID, held only long enough to hash.
    pub provider_session_id: Option<String>,
    /// Optional transient audio bytes.
    pub transient_audio: Vec<u8>,
    /// Exact raw provider response digest.
    pub response_sha256: String,
    /// Provider request/receipt ID digest.
    pub provider_receipt_sha256: String,
    /// Provider-reported cost where available.
    pub cost_microusd: u64,
}

/// Private transport boundary. Production implementations own secret
/// resolution, TLS, DNS pinning, proxy disablement, and redirect rejection.
pub trait ProviderTransport: Send + Sync {
    /// Execute one already-authorized exact operation.
    fn execute(&self, request: TransportRequest) -> Result<TransportResponse, Error>;
}

fn execute(
    transport: &dyn ProviderTransport,
    egress: &EgressPolicy,
    lease: &AdapterLease,
    endpoint: &ProviderEndpoint,
    operation: TransportOperation,
    now: DateTime<Utc>,
) -> Result<TransportResponse, Error> {
    lease.validate(endpoint.provider, now)?;
    if endpoint.binding_sha256 != lease.provider_binding_sha256 {
        return Err(Error::BoundaryMismatch);
    }
    egress.authorize(endpoint)?;
    let response = transport.execute(TransportRequest {
        endpoint: endpoint.clone(),
        operation,
        deadline: lease.deadline,
        max_cost_microusd: lease.remaining_cost_microusd,
    })?;
    super::validate_digest(&response.response_sha256, "provider response")?;
    super::validate_digest(&response.provider_receipt_sha256, "provider receipt")?;
    if response.cost_microusd > lease.remaining_cost_microusd
        || response.transient_audio.len() > MAX_OUTPUT_AUDIO_BYTES
    {
        return Err(Error::BudgetExceeded);
    }
    Ok(response)
}

/// Tear down one provider leg under the exact session fence. Stop is allowed
/// even after the activity lease or budget expires because it only reduces
/// capability.
pub fn stop_provider(
    transport: &dyn ProviderTransport,
    egress: &EgressPolicy,
    lease: &AdapterLease,
    endpoint: &ProviderEndpoint,
    now: DateTime<Utc>,
) -> Result<TransportResponse, Error> {
    if lease.provider != endpoint.provider || lease.session_generation == 0 {
        return Err(Error::BoundaryMismatch);
    }
    if endpoint.binding_sha256 != lease.provider_binding_sha256 {
        return Err(Error::BoundaryMismatch);
    }
    egress.authorize(endpoint)?;
    let response = transport.execute(TransportRequest {
        endpoint: endpoint.clone(),
        operation: TransportOperation::Stop {
            provider: endpoint.provider,
            session_id: lease.session_id,
            generation: lease.session_generation,
        },
        deadline: now + Duration::seconds(30),
        max_cost_microusd: 0,
    })?;
    super::validate_digest(&response.response_sha256, "provider stop response")?;
    super::validate_digest(&response.provider_receipt_sha256, "provider stop receipt")?;
    Ok(response)
}

/// Native Snowman huddle adapter.
pub struct SnowmanHuddleAdapter<'a> {
    /// Exact huddle endpoint.
    pub endpoint: &'a ProviderEndpoint,
    /// Default-deny egress policy.
    pub egress: &'a EgressPolicy,
    /// Private transport.
    pub transport: &'a dyn ProviderTransport,
    /// Sealed-coordinate resolver.
    pub resolver: &'a dyn SealedTargetResolver,
}

impl SnowmanHuddleAdapter<'_> {
    /// Join only the exact admitted huddle room and fence.
    pub fn join(
        &self,
        lease: &AdapterLease,
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        lease.validate(Provider::SnowmanHuddle, now)?;
        let target = resolve_target(self.resolver, lease, now)?;
        execute(
            self.transport,
            self.egress,
            lease,
            self.endpoint,
            TransportOperation::JoinSnowmanHuddle {
                target_token: target.target_token,
                session_id: lease.session_id,
                generation: lease.session_generation,
            },
            now,
        )
    }
}

/// Snowman-owned Twilio bidirectional Media Streams adapter.
pub struct TwilioAdapter<'a> {
    /// Exact Twilio API endpoint.
    pub endpoint: &'a ProviderEndpoint,
    /// Exact Snowman public WSS callback bound in Twilio configuration.
    pub stream_callback_url: Url,
    /// Default-deny egress policy.
    pub egress: &'a EgressPolicy,
    /// Private transport.
    pub transport: &'a dyn ProviderTransport,
    /// Sealed phone/SIP resolver.
    pub resolver: &'a dyn SealedTargetResolver,
}

impl TwilioAdapter<'_> {
    /// Start one outbound/pre-scheduled phone leg. There is no raw dial API.
    pub fn start(
        &self,
        lease: &AdapterLease,
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        lease.validate(Provider::Twilio, now)?;
        if self.stream_callback_url.scheme() != "wss"
            || is_block_host(self.stream_callback_url.host_str().unwrap_or_default())
            || self.stream_callback_url.query().is_some()
            || self.stream_callback_url.fragment().is_some()
        {
            return Err(Error::ProviderDisabled);
        }
        let target = resolve_target(self.resolver, lease, now)?;
        execute(
            self.transport,
            self.egress,
            lease,
            self.endpoint,
            TransportOperation::StartTwilioMediaStream {
                target_token: target.target_token,
                stream_callback_url: self.stream_callback_url.clone(),
                session_id: lease.session_id,
                generation: lease.session_generation,
            },
            now,
        )
    }

    /// Parse a bounded Twilio server message and reduce raw identifiers/audio
    /// to a transient frame or digest-only lifecycle evidence.
    pub fn handle_server_message(
        &self,
        lease: &AdapterLease,
        message: &[u8],
        now: DateTime<Utc>,
    ) -> Result<TwilioInbound, Error> {
        lease.validate(Provider::Twilio, now)?;
        if message.is_empty() || message.len() > MAX_PROTOCOL_MESSAGE_BYTES {
            return Err(Error::InvalidField("twilio websocket message"));
        }
        let value: Value = serde_json::from_slice(message)
            .map_err(|_| Error::InvalidField("twilio websocket json"))?;
        let event = value
            .get("event")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidField("twilio websocket event"))?;
        let message_sha256 = digest_bytes(message);
        match event {
            "start" => {
                let start = value.get("start").ok_or(Error::BoundaryMismatch)?;
                let stream_sid = string_field(&value, "streamSid")?;
                let custom = start
                    .get("customParameters")
                    .and_then(Value::as_object)
                    .ok_or(Error::BoundaryMismatch)?;
                let session = custom
                    .get("snowman_session_id")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or(Error::BoundaryMismatch)?;
                let generation = custom
                    .get("snowman_generation")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<u32>().ok())
                    .ok_or(Error::BoundaryMismatch)?;
                let media_format = start.get("mediaFormat").ok_or(Error::BoundaryMismatch)?;
                if session != lease.session_id
                    || generation != lease.session_generation
                    || media_format.get("encoding").and_then(Value::as_str) != Some("audio/x-mulaw")
                    || media_format.get("sampleRate").and_then(Value::as_u64) != Some(8000)
                    || media_format.get("channels").and_then(Value::as_u64) != Some(1)
                {
                    return Err(Error::BoundaryMismatch);
                }
                Ok(TwilioInbound::Started {
                    stream_id_sha256: digest_bytes(stream_sid.as_bytes()),
                    message_sha256,
                })
            }
            "media" => {
                let media = value
                    .get("media")
                    .ok_or(Error::InvalidField("twilio media"))?;
                let payload = media
                    .get("payload")
                    .and_then(Value::as_str)
                    .ok_or(Error::InvalidField("twilio media payload"))?;
                let bytes = BASE64
                    .decode(payload)
                    .map_err(|_| Error::InvalidField("twilio media encoding"))?;
                let sequence = string_or_number_u64(&value, "sequenceNumber")?;
                let timestamp_ms = string_or_number_u64(media, "timestamp")?;
                let receipt = TransientAudioFrame {
                    session_id: lease.session_id,
                    session_generation: lease.session_generation,
                    sequence,
                    timestamp_ms,
                    bytes: &bytes,
                }
                .receipt(now)?;
                Ok(TwilioInbound::Audio { bytes, receipt })
            }
            "dtmf" => Ok(TwilioInbound::UntrustedSignal { message_sha256 }),
            "mark" => Ok(TwilioInbound::PlaybackMark { message_sha256 }),
            "stop" => Ok(TwilioInbound::Stopped { message_sha256 }),
            "connected" => Ok(TwilioInbound::Connected { message_sha256 }),
            _ => Err(Error::InvalidField("twilio websocket event")),
        }
    }

    /// Send headerless μ-law/8kHz audio to the exact fenced stream.
    pub fn send_audio(
        &self,
        lease: &AdapterLease,
        stream_id_sha256: String,
        mulaw_8khz: &[u8],
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        super::validate_digest(&stream_id_sha256, "twilio stream")?;
        if mulaw_8khz.is_empty() || mulaw_8khz.len() > MAX_OUTPUT_AUDIO_BYTES {
            return Err(Error::InvalidField("twilio output audio"));
        }
        let message = serde_json::to_vec(&json!({
            "event": "media",
            "media": { "payload": BASE64.encode(mulaw_8khz) }
        }))
        .map_err(|_| Error::InvalidField("twilio output message"))?;
        execute(
            self.transport,
            self.egress,
            lease,
            self.endpoint,
            TransportOperation::TwilioWebSocketMessage {
                stream_id_sha256,
                message,
            },
            now,
        )
    }

    /// Interrupt buffered Twilio output after cancellation or barge-in.
    pub fn clear(
        &self,
        lease: &AdapterLease,
        stream_id_sha256: String,
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        super::validate_digest(&stream_id_sha256, "twilio stream")?;
        let message = serde_json::to_vec(&json!({ "event": "clear" }))
            .map_err(|_| Error::InvalidField("twilio clear message"))?;
        execute(
            self.transport,
            self.egress,
            lease,
            self.endpoint,
            TransportOperation::TwilioWebSocketMessage {
                stream_id_sha256,
                message,
            },
            now,
        )
    }
}

/// Inbound Twilio protocol result. Audio bytes are transient and non-serializable.
pub enum TwilioInbound {
    /// WebSocket connected.
    Connected {
        /// Exact inbound message digest.
        message_sha256: String,
    },
    /// Fenced stream established.
    Started {
        /// Digest of the provider stream ID.
        stream_id_sha256: String,
        /// Exact inbound message digest.
        message_sha256: String,
    },
    /// One transient μ-law frame plus digest receipt.
    Audio {
        /// Transient μ-law bytes.
        bytes: Vec<u8>,
        /// Digest-only frame evidence.
        receipt: super::AudioFrameReceipt,
    },
    /// DTMF or another signal that can never grant authority.
    UntrustedSignal {
        /// Exact inbound message digest.
        message_sha256: String,
    },
    /// Playback marker.
    PlaybackMark {
        /// Exact inbound message digest.
        message_sha256: String,
    },
    /// Provider stopped.
    Stopped {
        /// Exact inbound message digest.
        message_sha256: String,
    },
}

/// OpenAI Realtime server-to-server adapter.
pub struct OpenAiRealtimeAdapter<'a> {
    /// Exact injected Realtime endpoint.
    pub endpoint: &'a ProviderEndpoint,
    /// Default-deny egress policy.
    pub egress: &'a EgressPolicy,
    /// Private transport.
    pub transport: &'a dyn ProviderTransport,
    /// Operations-catalog model ID.
    pub model_catalog_id: String,
    /// Exact allowed proposal-only tool names.
    pub allowed_intents: BTreeSet<String>,
}

impl OpenAiRealtimeAdapter<'_> {
    /// Open a server-side Realtime session using a pseudonymous safety ID.
    pub fn connect(
        &self,
        lease: &AdapterLease,
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        super::validate_catalog_id(&self.model_catalog_id, "realtime model")?;
        validate_intent_allowlist(&self.allowed_intents)?;
        let safety_identifier =
            digest_bytes(format!("{}:{}", lease.tenant_id, lease.session_id).as_bytes());
        execute(
            self.transport,
            self.egress,
            lease,
            self.endpoint,
            TransportOperation::OpenAiRealtimeConnect {
                safety_identifier,
                model_catalog_id: self.model_catalog_id.clone(),
                session_id: lease.session_id,
                generation: lease.session_generation,
            },
            now,
        )
    }

    /// Append transient audio to the exact provider session.
    pub fn append_audio(
        &self,
        lease: &AdapterLease,
        provider_session_sha256: String,
        audio: &[u8],
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        super::validate_digest(&provider_session_sha256, "realtime session")?;
        if audio.is_empty() || audio.len() > MAX_OUTPUT_AUDIO_BYTES {
            return Err(Error::InvalidField("realtime input audio"));
        }
        let event = serde_json::to_vec(&json!({
            "type": "input_audio_buffer.append",
            "audio": BASE64.encode(audio),
        }))
        .map_err(|_| Error::InvalidField("realtime audio event"))?;
        self.send_event(lease, provider_session_sha256, event, now)
    }

    /// Cancel in-flight model output. Cancellation never needs speech authority.
    pub fn cancel(
        &self,
        lease: &AdapterLease,
        provider_session_sha256: String,
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        let event = serde_json::to_vec(&json!({ "type": "response.cancel" }))
            .map_err(|_| Error::InvalidField("realtime cancel event"))?;
        self.send_event(lease, provider_session_sha256, event, now)
    }

    fn send_event(
        &self,
        lease: &AdapterLease,
        provider_session_sha256: String,
        event: Vec<u8>,
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        super::validate_digest(&provider_session_sha256, "realtime session")?;
        execute(
            self.transport,
            self.egress,
            lease,
            self.endpoint,
            TransportOperation::OpenAiRealtimeEvent {
                provider_session_sha256,
                event,
            },
            now,
        )
    }

    /// Parse a server event into transient audio, digest-only usage, or a
    /// proposal-only intent. No event directly executes a tool.
    pub fn handle_server_event(
        &self,
        lease: &AdapterLease,
        event: &[u8],
        now: DateTime<Utc>,
    ) -> Result<RealtimeInbound, Error> {
        lease.validate(Provider::OpenAiRealtime, now)?;
        if event.is_empty() || event.len() > MAX_PROTOCOL_MESSAGE_BYTES {
            return Err(Error::InvalidField("realtime server event"));
        }
        let value: Value = serde_json::from_slice(event)
            .map_err(|_| Error::InvalidField("realtime server json"))?;
        let kind = string_field(&value, "type")?;
        let event_sha256 = digest_bytes(event);
        match kind {
            "response.output_audio.delta" | "response.audio.delta" => {
                let delta = string_field(&value, "delta")?;
                let bytes = BASE64
                    .decode(delta)
                    .map_err(|_| Error::InvalidField("realtime audio encoding"))?;
                if bytes.is_empty() || bytes.len() > MAX_OUTPUT_AUDIO_BYTES {
                    return Err(Error::InvalidField("realtime output audio"));
                }
                Ok(RealtimeInbound::Audio {
                    audio_sha256: digest_bytes(&bytes),
                    bytes,
                    event_sha256,
                })
            }
            "response.function_call_arguments.done" => {
                let name = string_field(&value, "name")?;
                if !self.allowed_intents.contains(name) {
                    return Err(Error::UntrustedAuthority);
                }
                let arguments = string_field(&value, "arguments")?;
                let _: Value =
                    serde_json::from_str(arguments).map_err(|_| Error::UntrustedAuthority)?;
                Ok(RealtimeInbound::ProposedIntent {
                    name: name.to_owned(),
                    arguments_sha256: digest_bytes(arguments.as_bytes()),
                    event_sha256,
                })
            }
            "response.done" => {
                let usage = value
                    .pointer("/response/usage")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                Ok(RealtimeInbound::Usage {
                    usage_sha256: digest_bytes(
                        &serde_json::to_vec(&usage)
                            .map_err(|_| Error::InvalidField("realtime usage"))?,
                    ),
                    event_sha256,
                })
            }
            "error" => Ok(RealtimeInbound::ProviderError { event_sha256 }),
            _ => Ok(RealtimeInbound::Observation { event_sha256 }),
        }
    }
}

fn validate_intent_allowlist(allowed: &BTreeSet<String>) -> Result<(), Error> {
    let expected = BTreeSet::from([
        "propose_action_item".to_owned(),
        "clarify_owner".to_owned(),
        "record_decision".to_owned(),
        "request_specialist_work".to_owned(),
    ]);
    if allowed != &expected {
        return Err(Error::UntrustedAuthority);
    }
    Ok(())
}

/// Parsed Realtime event. It is evidence/proposal data, never authority.
pub enum RealtimeInbound {
    /// Transient output audio.
    Audio {
        /// Transient audio bytes.
        bytes: Vec<u8>,
        /// Digest of the transient audio.
        audio_sha256: String,
        /// Digest of the exact provider event.
        event_sha256: String,
    },
    /// Proposal-only bounded tool intent.
    ProposedIntent {
        /// One of the four bounded meeting intent names.
        name: String,
        /// Digest of the untrusted arguments.
        arguments_sha256: String,
        /// Digest of the exact provider event.
        event_sha256: String,
    },
    /// Digest-only provider usage observation.
    Usage {
        /// Digest of the provider usage object.
        usage_sha256: String,
        /// Digest of the exact provider event.
        event_sha256: String,
    },
    /// Provider error evidence.
    ProviderError {
        /// Digest of the exact provider event.
        event_sha256: String,
    },
    /// Non-authoritative provider event evidence.
    Observation {
        /// Digest of the exact provider event.
        event_sha256: String,
    },
}

/// Direct OpenAI SIP action. Transfer/refer is intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipAction {
    /// Accept only an authenticated, pre-authorized call.
    Accept,
    /// Reject an unadmitted call.
    Reject,
    /// Hang up an admitted call.
    Hangup,
}

/// Authenticated, still-untrusted incoming OpenAI SIP event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiIncomingCall {
    /// Raw call ID held transiently for the provider control request.
    pub call_id: String,
    /// Digest for durable binding.
    pub call_id_sha256: String,
    /// Exact raw webhook body digest.
    pub event_sha256: String,
}

impl OpenAiRealtimeAdapter<'_> {
    /// Parse only `realtime.call.incoming` after signature verification. SIP
    /// headers remain untrusted and are deliberately discarded.
    pub fn parse_incoming_call(&self, raw_body: &[u8]) -> Result<OpenAiIncomingCall, Error> {
        if raw_body.is_empty() || raw_body.len() > MAX_PROTOCOL_MESSAGE_BYTES {
            return Err(Error::InvalidField("openai sip webhook"));
        }
        let value: Value = serde_json::from_slice(raw_body)
            .map_err(|_| Error::InvalidField("openai sip webhook json"))?;
        if value.get("type").and_then(Value::as_str) != Some("realtime.call.incoming") {
            return Err(Error::UntrustedAuthority);
        }
        let call_id = value
            .pointer("/data/call_id")
            .and_then(Value::as_str)
            .ok_or(Error::InvalidField("openai call id"))?;
        super::validate_catalog_id(call_id, "openai call id")?;
        Ok(OpenAiIncomingCall {
            call_id: call_id.to_owned(),
            call_id_sha256: digest_bytes(call_id.as_bytes()),
            event_sha256: digest_bytes(raw_body),
        })
    }

    /// Accept/reject/hang up only when the authenticated call digest matches
    /// the resolved admitted coordinate. This API cannot transfer a call.
    pub fn control_sip(
        &self,
        lease: &AdapterLease,
        control_endpoint: &ProviderEndpoint,
        call: &OpenAiIncomingCall,
        expected_call_id_sha256: &str,
        action: SipAction,
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        super::validate_digest(expected_call_id_sha256, "expected openai call")?;
        if call.call_id_sha256 != expected_call_id_sha256 {
            return Err(Error::UntrustedAuthority);
        }
        let body = match action {
            SipAction::Accept => Some(
                serde_json::to_vec(&json!({
                    "type": "realtime",
                    "model": self.model_catalog_id,
                    "tools": [],
                }))
                .map_err(|_| Error::InvalidField("openai sip accept"))?,
            ),
            SipAction::Reject => Some(
                serde_json::to_vec(&json!({ "status_code": 486 }))
                    .map_err(|_| Error::InvalidField("openai sip reject"))?,
            ),
            SipAction::Hangup => None,
        };
        execute(
            self.transport,
            self.egress,
            lease,
            control_endpoint,
            TransportOperation::OpenAiSipControl {
                action,
                call_id: call.call_id.clone(),
                body,
            },
            now,
        )
    }

    /// Open the trusted server-side sideband channel for the same authenticated
    /// and pre-authorized SIP call. Tools and business logic remain here.
    pub fn connect_sip_sideband(
        &self,
        lease: &AdapterLease,
        sideband_endpoint: &ProviderEndpoint,
        call: &OpenAiIncomingCall,
        expected_call_id_sha256: &str,
        now: DateTime<Utc>,
    ) -> Result<TransportResponse, Error> {
        super::validate_digest(expected_call_id_sha256, "expected openai call")?;
        if call.call_id_sha256 != expected_call_id_sha256
            || sideband_endpoint.exact_url.scheme() != "wss"
        {
            return Err(Error::UntrustedAuthority);
        }
        execute(
            self.transport,
            self.egress,
            lease,
            sideband_endpoint,
            TransportOperation::OpenAiSipSidebandConnect {
                call_id: call.call_id.clone(),
                session_id: lease.session_id,
                generation: lease.session_generation,
            },
            now,
        )
    }
}

/// Optional output-only ElevenLabs adapter.
pub struct ElevenLabsAdapter<'a> {
    /// Exact injected streaming TTS endpoint.
    pub endpoint: &'a ProviderEndpoint,
    /// Default-deny egress policy.
    pub egress: &'a EgressPolicy,
    /// Private transport.
    pub transport: &'a dyn ProviderTransport,
}

impl ElevenLabsAdapter<'_> {
    /// Render only text already approved by the active media session.
    pub fn render(
        &self,
        lease: &AdapterLease,
        session: &super::MediaSession,
        request: &SpeechRenderRequest,
        now: DateTime<Utc>,
    ) -> Result<RenderedSpeech, Error> {
        lease.validate(Provider::ElevenLabs, now)?;
        request.validate_for(session)?;
        if request.max_cost_microusd > lease.remaining_cost_microusd {
            return Err(Error::BudgetExceeded);
        }
        let response = execute(
            self.transport,
            self.egress,
            lease,
            self.endpoint,
            TransportOperation::ElevenLabsRender {
                voice_catalog_id: request.voice_catalog_id.clone(),
                model_catalog_id: request.model_catalog_id.clone(),
                approved_text: request.approved_text.clone(),
                approved_turn_sha256: request.approved_turn_sha256.clone(),
            },
            now,
        )?;
        let audio_sha256 = digest_bytes(&response.transient_audio);
        Ok(RenderedSpeech {
            bytes: response.transient_audio,
            audio_sha256,
            response_sha256: response.response_sha256,
            provider_receipt_sha256: response.provider_receipt_sha256,
            cost_microusd: response.cost_microusd,
        })
    }
}

/// Transient rendered audio and durable digest/cost evidence.
pub struct RenderedSpeech {
    /// Transient output bytes.
    pub bytes: Vec<u8>,
    /// Output audio digest.
    pub audio_sha256: String,
    /// Provider response digest.
    pub response_sha256: String,
    /// Provider receipt digest.
    pub provider_receipt_sha256: String,
    /// Provider cost.
    pub cost_microusd: u64,
}

/// Signature scheme delegated to a current official provider verifier/SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// Twilio exact URL plus all form parameters/raw JSON semantics.
    TwilioRequest,
    /// Standard Webhooks verification used by OpenAI.
    OpenAiStandardWebhook,
}

/// Exact immutable input to a provider signature verifier.
pub struct SignatureInput<'a> {
    /// Scheme.
    pub scheme: SignatureScheme,
    /// Exact externally visible URL.
    pub exact_url: &'a str,
    /// Original headers.
    pub headers: &'a BTreeMap<String, String>,
    /// Original body bytes.
    pub raw_body: &'a [u8],
    /// Purpose-specific secret reference.
    pub secret: &'a SecretRef,
    /// Verification time.
    pub now: DateTime<Utc>,
}

/// Result from the private official-SDK/cryptographic verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelivery {
    /// Provider delivery identifier.
    pub delivery_id: String,
}

/// Private provider signature verifier boundary.
pub trait SignatureVerifier: Send + Sync {
    /// Verify the exact URL, all original headers, and exact raw body.
    fn verify(&self, input: SignatureInput<'_>) -> Result<VerifiedDelivery, Error>;
}

/// Twilio exact-request webhook authenticator.
pub struct TwilioWebhookAuthenticator<'a> {
    /// Purpose-specific Twilio Auth Token secret reference.
    pub secret: &'a SecretRef,
    /// Current official SDK verifier implementation.
    pub verifier: &'a dyn SignatureVerifier,
}

impl WebhookAuthenticator for TwilioWebhookAuthenticator<'_> {
    fn verify(
        &self,
        request: &WebhookRequest<'_>,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedWebhook, Error> {
        if request.provider != Provider::Twilio {
            return Err(Error::WebhookAuthentication);
        }
        let signature = if request.exact_url.starts_with("wss://") {
            request
                .headers
                .get("x-twilio-signature")
                .map(String::as_str)
        } else {
            header(request.headers, "x-twilio-signature")
        }
        .filter(|value| !value.is_empty())
        .ok_or(Error::WebhookAuthentication)?;
        let _ = signature;
        let verified = self.verifier.verify(SignatureInput {
            scheme: SignatureScheme::TwilioRequest,
            exact_url: request.exact_url,
            headers: request.headers,
            raw_body: request.raw_body,
            secret: self.secret,
            now,
        })?;
        AuthenticatedWebhook::verified(
            request,
            verified.delivery_id,
            self.secret.version_sha256.clone(),
            now,
        )
    }
}

/// OpenAI Standard Webhooks authenticator for Realtime SIP callbacks.
pub struct OpenAiWebhookAuthenticator<'a> {
    /// Purpose-specific OpenAI webhook signing secret reference.
    pub secret: &'a SecretRef,
    /// Current official SDK/Standard Webhooks verifier.
    pub verifier: &'a dyn SignatureVerifier,
}

impl WebhookAuthenticator for OpenAiWebhookAuthenticator<'_> {
    fn verify(
        &self,
        request: &WebhookRequest<'_>,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedWebhook, Error> {
        if request.provider != Provider::OpenAiRealtime {
            return Err(Error::WebhookAuthentication);
        }
        let delivery_id = header(request.headers, "webhook-id")
            .filter(|value| !value.is_empty())
            .ok_or(Error::WebhookAuthentication)?;
        let timestamp = header(request.headers, "webhook-timestamp")
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(DateTime::from_timestamp_secs)
            .ok_or(Error::WebhookAuthentication)?;
        let signature = header(request.headers, "webhook-signature")
            .filter(|value| value.starts_with("v1,") || value.contains(" v1,"))
            .ok_or(Error::WebhookAuthentication)?;
        let _ = signature;
        if timestamp < now - MAX_CLOCK_SKEW || timestamp > now + Duration::seconds(30) {
            return Err(Error::WebhookAuthentication);
        }
        let verified = self.verifier.verify(SignatureInput {
            scheme: SignatureScheme::OpenAiStandardWebhook,
            exact_url: request.exact_url,
            headers: request.headers,
            raw_body: request.raw_body,
            secret: self.secret,
            now,
        })?;
        if verified.delivery_id != delivery_id {
            return Err(Error::WebhookAuthentication);
        }
        AuthenticatedWebhook::verified(
            request,
            verified.delivery_id,
            self.secret.version_sha256.clone(),
            now,
        )
    }
}

fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn string_field<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, Error> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(Error::InvalidField(field))
}

fn string_or_number_u64(value: &Value, field: &'static str) -> Result<u64, Error> {
    value
        .get(field)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .filter(|value| *value > 0)
        .ok_or(Error::InvalidField(field))
}

fn digest_bytes(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn digest(seed: char) -> String {
        std::iter::repeat_n(seed, 64).collect()
    }

    fn secret() -> SecretRef {
        SecretRef::new(
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:snowman/media".into(),
            digest('a'),
        )
        .unwrap()
    }

    fn endpoint(provider: Provider, url: &str) -> ProviderEndpoint {
        ProviderEndpoint {
            provider,
            exact_url: Url::parse(url).unwrap(),
            secret: (provider != Provider::SnowmanHuddle).then(secret),
            binding_sha256: digest('b'),
        }
    }

    fn lease(provider: Provider) -> AdapterLease {
        AdapterLease {
            tenant_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            meeting_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            session_generation: 7,
            provider,
            provider_binding_sha256: digest('b'),
            conference_approval_sha256: digest('c'),
            sealed_coordinate_ref: "snowman-seal:approved-meeting".into(),
            deadline: Utc::now() + Duration::minutes(30),
            lease_expires_at: Utc::now() + Duration::seconds(15),
            remaining_cost_microusd: 100_000,
        }
    }

    fn egress(provider: Provider, url: &str) -> EgressPolicy {
        let parsed = Url::parse(url).unwrap();
        EgressPolicy::new(vec![EgressRule {
            provider,
            scheme: parsed.scheme().into(),
            host: parsed.host_str().unwrap().into(),
            port: parsed.port_or_known_default().unwrap(),
            path_prefix: parsed.path().into(),
        }])
        .unwrap()
    }

    struct Resolver;

    impl SealedTargetResolver for Resolver {
        fn resolve(
            &self,
            lease: &AdapterLease,
            now: DateTime<Utc>,
        ) -> Result<ResolvedTarget, Error> {
            Ok(ResolvedTarget {
                provider: lease.provider,
                target_token: "opaque-target-token".into(),
                target_sha256: digest('d'),
                approval_sha256: lease.conference_approval_sha256.clone(),
                expires_at: now + Duration::minutes(1),
            })
        }
    }

    #[derive(Default)]
    struct MockTransport {
        requests: Mutex<Vec<TransportRequest>>,
    }

    impl ProviderTransport for MockTransport {
        fn execute(&self, request: TransportRequest) -> Result<TransportResponse, Error> {
            self.requests.lock().unwrap().push(request);
            Ok(TransportResponse {
                provider_session_id: Some("provider-session".into()),
                transient_audio: vec![1, 2, 3],
                response_sha256: digest('e'),
                provider_receipt_sha256: digest('f'),
                cost_microusd: 10,
            })
        }
    }

    #[test]
    fn blocks_block_and_unregistered_egress() {
        let block_url = format!("wss://relay.{}.xyz/v1/realtime", "block");
        let block = endpoint(Provider::OpenAiRealtime, &block_url);
        assert_eq!(block.validate(), Err(Error::ProviderDisabled));

        let openai = endpoint(Provider::OpenAiRealtime, "wss://api.openai.com/v1/realtime");
        let policy = egress(Provider::OpenAiRealtime, "wss://api.openai.com/v1/realtime");
        let changed = endpoint(
            Provider::OpenAiRealtime,
            "wss://api.openai.com/v1/assistants",
        );
        assert!(policy.authorize(&openai).is_ok());
        assert_eq!(policy.authorize(&changed), Err(Error::ProviderDisabled));
    }

    #[test]
    fn native_huddle_uses_only_sealed_target() {
        let transport = MockTransport::default();
        let endpoint = endpoint(
            Provider::SnowmanHuddle,
            "wss://huddle.snowmanai.org/private/media",
        );
        let policy = egress(Provider::SnowmanHuddle, endpoint.exact_url.as_str());
        let adapter = SnowmanHuddleAdapter {
            endpoint: &endpoint,
            egress: &policy,
            transport: &transport,
            resolver: &Resolver,
        };
        let authority = lease(Provider::SnowmanHuddle);
        adapter.join(&authority, Utc::now()).unwrap();
        let requests = transport.requests.lock().unwrap();
        assert!(matches!(
            &requests[0].operation,
            TransportOperation::JoinSnowmanHuddle { target_token, .. }
                if target_token == "opaque-target-token"
        ));
    }

    #[test]
    fn twilio_start_has_no_raw_dial_target_and_parses_transient_audio() {
        let transport = MockTransport::default();
        let endpoint = endpoint(Provider::Twilio, "https://api.twilio.com/2010-04-01/Calls");
        let policy = egress(Provider::Twilio, endpoint.exact_url.as_str());
        let adapter = TwilioAdapter {
            endpoint: &endpoint,
            stream_callback_url: Url::parse("wss://meetings.snowmanai.org/media/twilio").unwrap(),
            egress: &policy,
            transport: &transport,
            resolver: &Resolver,
        };
        let authority = lease(Provider::Twilio);
        adapter.start(&authority, Utc::now()).unwrap();
        let start = json!({
            "event": "start",
            "streamSid": "MZ-private",
            "start": {
                "customParameters": {
                    "snowman_session_id": authority.session_id.to_string(),
                    "snowman_generation": authority.session_generation.to_string()
                },
                "mediaFormat": {"encoding":"audio/x-mulaw","sampleRate":8000,"channels":1}
            }
        });
        assert!(matches!(
            adapter
                .handle_server_message(&authority, &serde_json::to_vec(&start).unwrap(), Utc::now())
                .unwrap(),
            TwilioInbound::Started { .. }
        ));
        let media = json!({
            "event": "media",
            "sequenceNumber": "1",
            "media": {"timestamp":"20", "payload": BASE64.encode([1,2,3])}
        });
        match adapter
            .handle_server_message(&authority, &serde_json::to_vec(&media).unwrap(), Utc::now())
            .unwrap()
        {
            TwilioInbound::Audio { bytes, receipt } => {
                assert_eq!(bytes, vec![1, 2, 3]);
                assert_eq!(receipt.frame_sha256, digest_bytes(&bytes));
            }
            _ => panic!("expected transient audio"),
        }
    }

    #[test]
    fn twilio_dtmf_never_becomes_authority() {
        let transport = MockTransport::default();
        let endpoint = endpoint(Provider::Twilio, "https://api.twilio.com/2010-04-01/Calls");
        let policy = egress(Provider::Twilio, endpoint.exact_url.as_str());
        let adapter = TwilioAdapter {
            endpoint: &endpoint,
            stream_callback_url: Url::parse("wss://meetings.snowmanai.org/media/twilio").unwrap(),
            egress: &policy,
            transport: &transport,
            resolver: &Resolver,
        };
        let event = serde_json::to_vec(&json!({"event":"dtmf","dtmf":{"digit":"9"}})).unwrap();
        assert!(matches!(
            adapter
                .handle_server_message(&lease(Provider::Twilio), &event, Utc::now())
                .unwrap(),
            TwilioInbound::UntrustedSignal { .. }
        ));
    }

    fn intents() -> BTreeSet<String> {
        BTreeSet::from([
            "propose_action_item".into(),
            "clarify_owner".into(),
            "record_decision".into(),
            "request_specialist_work".into(),
        ])
    }

    #[test]
    fn realtime_allows_only_proposal_intents_and_cancel() {
        let transport = MockTransport::default();
        let endpoint = endpoint(Provider::OpenAiRealtime, "wss://api.openai.com/v1/realtime");
        let policy = egress(Provider::OpenAiRealtime, endpoint.exact_url.as_str());
        let adapter = OpenAiRealtimeAdapter {
            endpoint: &endpoint,
            egress: &policy,
            transport: &transport,
            model_catalog_id: "snowman.realtime.default".into(),
            allowed_intents: intents(),
        };
        let authority = lease(Provider::OpenAiRealtime);
        adapter.connect(&authority, Utc::now()).unwrap();
        adapter.cancel(&authority, digest('1'), Utc::now()).unwrap();
        let proposal = serde_json::to_vec(&json!({
            "type":"response.function_call_arguments.done",
            "name":"propose_action_item",
            "arguments":"{\"summary\":\"review\"}"
        }))
        .unwrap();
        assert!(matches!(
            adapter
                .handle_server_event(&authority, &proposal, Utc::now())
                .unwrap(),
            RealtimeInbound::ProposedIntent { .. }
        ));
        let forbidden = serde_json::to_vec(&json!({
            "type":"response.function_call_arguments.done",
            "name":"send_email",
            "arguments":"{}"
        }))
        .unwrap();
        assert_eq!(
            adapter
                .handle_server_event(&authority, &forbidden, Utc::now())
                .err(),
            Some(Error::UntrustedAuthority)
        );
    }

    #[test]
    fn expired_activity_lease_can_only_stop() {
        let transport = MockTransport::default();
        let endpoint = endpoint(Provider::Twilio, "https://api.twilio.com/2010-04-01/Calls");
        let policy = egress(Provider::Twilio, endpoint.exact_url.as_str());
        let mut authority = lease(Provider::Twilio);
        authority.lease_expires_at = Utc::now() - Duration::seconds(1);
        let adapter = TwilioAdapter {
            endpoint: &endpoint,
            stream_callback_url: Url::parse("wss://meetings.snowmanai.org/media/twilio").unwrap(),
            egress: &policy,
            transport: &transport,
            resolver: &Resolver,
        };
        assert_eq!(
            adapter.start(&authority, Utc::now()).err(),
            Some(Error::BudgetExceeded)
        );
        assert!(stop_provider(&transport, &policy, &authority, &endpoint, Utc::now()).is_ok());
    }

    fn elevenlabs_session(authority: &AdapterLease) -> crate::MediaSession {
        let now = Utc::now();
        crate::MediaSession {
            grant: crate::MediaExecutionGrant {
                tenant_id: authority.tenant_id,
                workspace_id: authority.workspace_id,
                meeting_id: authority.meeting_id,
                mailbox_identity_id: Uuid::new_v4(),
                meeting_agent_identity_id: Uuid::new_v4(),
                provider_event_id_sha256: digest('1'),
                provider_revision: 1,
                schedule_revision: 1,
                session_id: authority.session_id,
                session_generation: authority.session_generation,
                data_class: snowman_meeting_control::DataClass::Confidential,
                conference_kind: snowman_meeting_control::ConferenceKind::SnowmanHuddle,
                sealed_coordinate_ref: authority.sealed_coordinate_ref.clone(),
                conference_approval_sha256: authority.conference_approval_sha256.clone(),
                ingress_route: crate::IngressRoute::SnowmanHuddle,
                conversation_route: crate::ConversationRoute::SnowmanAws,
                renderer_route: crate::RendererRoute::ElevenLabs,
                starts_at: now - Duration::minutes(1),
                ends_at: now + Duration::minutes(30),
                join_not_before: now - Duration::minutes(5),
                join_not_after: now + Duration::minutes(5),
                max_cost_microusd: 100_000,
                max_duration_seconds: 1800,
                raw_audio_retention: snowman_meeting_control::RetentionMode::None,
                transcript_retention: snowman_meeting_control::RetentionMode::AnalystEvidence,
                admission_evidence_sha256: digest('2'),
                consent_evidence_sha256: digest('3'),
            },
            gateway_service_identity_id: Uuid::new_v4(),
            provider_binding_sha256: authority.provider_binding_sha256.clone(),
            status: crate::SessionStatus::Active,
            provider_session_ids_sha256: BTreeMap::new(),
            spent_microusd: 0,
            cost_ceiling_microusd: 100_000,
            started_at: now,
            deadline: authority.deadline,
            stopped_at: None,
            last_receipt_sha256: digest('4'),
        }
    }

    #[test]
    fn elevenlabs_is_output_only_and_approved_text_bound() {
        let transport = MockTransport::default();
        let endpoint = endpoint(
            Provider::ElevenLabs,
            "wss://api.elevenlabs.io/v1/text-to-speech/snowman/stream-input",
        );
        let policy = egress(Provider::ElevenLabs, endpoint.exact_url.as_str());
        let adapter = ElevenLabsAdapter {
            endpoint: &endpoint,
            egress: &policy,
            transport: &transport,
        };
        let authority = lease(Provider::ElevenLabs);
        let session = elevenlabs_session(&authority);
        let request = SpeechRenderRequest {
            tenant_id: authority.tenant_id,
            session_id: authority.session_id,
            session_generation: authority.session_generation,
            approved_text: "I captured the agreed next step.".into(),
            approved_turn_sha256: digest('5'),
            voice_catalog_id: "snowman.voice.default".into(),
            model_catalog_id: "snowman.tts.default".into(),
            max_cost_microusd: 1_000,
        };
        let rendered = adapter
            .render(&authority, &session, &request, Utc::now())
            .unwrap();
        assert_eq!(rendered.audio_sha256, digest_bytes(&rendered.bytes));
        assert!(matches!(
            transport.requests.lock().unwrap()[0].operation,
            TransportOperation::ElevenLabsRender { .. }
        ));
    }

    #[test]
    fn sip_control_requires_authenticated_expected_call_and_has_no_refer() {
        let transport = MockTransport::default();
        let control_endpoint = endpoint(
            Provider::OpenAiRealtime,
            "https://api.openai.com/v1/realtime/calls",
        );
        let sideband = endpoint(Provider::OpenAiRealtime, "wss://api.openai.com/v1/realtime");
        let policy = EgressPolicy::new(vec![
            EgressRule {
                provider: Provider::OpenAiRealtime,
                scheme: "https".into(),
                host: "api.openai.com".into(),
                port: 443,
                path_prefix: "/v1/realtime/calls".into(),
            },
            EgressRule {
                provider: Provider::OpenAiRealtime,
                scheme: "wss".into(),
                host: "api.openai.com".into(),
                port: 443,
                path_prefix: "/v1/realtime".into(),
            },
        ])
        .unwrap();
        let adapter = OpenAiRealtimeAdapter {
            endpoint: &control_endpoint,
            egress: &policy,
            transport: &transport,
            model_catalog_id: "snowman.realtime.default".into(),
            allowed_intents: intents(),
        };
        let body = serde_json::to_vec(&json!({
            "type":"realtime.call.incoming",
            "data":{"call_id":"rtc_123", "sip_headers":[{"name":"From","value":"sip:+1"}]}
        }))
        .unwrap();
        let call = adapter.parse_incoming_call(&body).unwrap();
        assert_eq!(
            adapter
                .control_sip(
                    &lease(Provider::OpenAiRealtime),
                    &control_endpoint,
                    &call,
                    &digest('9'),
                    SipAction::Accept,
                    Utc::now()
                )
                .err(),
            Some(Error::UntrustedAuthority)
        );
        adapter
            .control_sip(
                &lease(Provider::OpenAiRealtime),
                &control_endpoint,
                &call,
                &call.call_id_sha256,
                SipAction::Reject,
                Utc::now(),
            )
            .unwrap();
        adapter
            .connect_sip_sideband(
                &lease(Provider::OpenAiRealtime),
                &sideband,
                &call,
                &call.call_id_sha256,
                Utc::now(),
            )
            .unwrap();
    }

    struct MockVerifier {
        expected_url: String,
        expected_body: Vec<u8>,
        delivery_id: String,
    }

    impl SignatureVerifier for MockVerifier {
        fn verify(&self, input: SignatureInput<'_>) -> Result<VerifiedDelivery, Error> {
            assert_eq!(input.exact_url, self.expected_url);
            assert_eq!(input.raw_body, self.expected_body);
            assert!(
                input.headers.contains_key("webhook-signature")
                    || input.headers.contains_key("x-twilio-signature")
            );
            Ok(VerifiedDelivery {
                delivery_id: self.delivery_id.clone(),
            })
        }
    }

    #[test]
    fn webhook_authenticators_pass_exact_url_headers_and_raw_body() {
        let now = Utc::now();
        let body = br#"{"type":"realtime.call.incoming","data":{"call_id":"rtc_123"}}"#;
        let url = "https://meetings.snowmanai.org/webhooks/openai";
        let delivery_id = "wh_123";
        let headers = BTreeMap::from([
            ("webhook-id".into(), delivery_id.into()),
            ("webhook-timestamp".into(), now.timestamp().to_string()),
            ("webhook-signature".into(), "v1,signature".into()),
        ]);
        let verifier = MockVerifier {
            expected_url: url.into(),
            expected_body: body.to_vec(),
            delivery_id: delivery_id.into(),
        };
        let secret = secret();
        let auth = OpenAiWebhookAuthenticator {
            secret: &secret,
            verifier: &verifier,
        };
        let request = WebhookRequest {
            provider: Provider::OpenAiRealtime,
            exact_url: url,
            headers: &headers,
            raw_body: body,
            received_at: now,
        };
        assert!(auth.verify(&request, now).is_ok());

        let twilio_url = "wss://meetings.snowmanai.org/media/twilio";
        let twilio_headers = BTreeMap::from([("x-twilio-signature".into(), "signature".into())]);
        let twilio_verifier = MockVerifier {
            expected_url: twilio_url.into(),
            expected_body: Vec::new(),
            delivery_id: "twilio-upgrade-1".into(),
        };
        let twilio = TwilioWebhookAuthenticator {
            secret: &secret,
            verifier: &twilio_verifier,
        };
        let request = WebhookRequest {
            provider: Provider::Twilio,
            exact_url: twilio_url,
            headers: &twilio_headers,
            raw_body: &[],
            received_at: now,
        };
        assert!(twilio.verify(&request, now).is_ok());
    }

    #[test]
    fn stale_openai_webhook_fails_before_crypto() {
        let now = Utc::now();
        let headers = BTreeMap::from([
            ("webhook-id".into(), "wh_old".into()),
            (
                "webhook-timestamp".into(),
                (now - Duration::minutes(6)).timestamp().to_string(),
            ),
            ("webhook-signature".into(), "v1,signature".into()),
        ]);
        let verifier = MockVerifier {
            expected_url: "https://meetings.snowmanai.org/webhooks/openai".into(),
            expected_body: vec![],
            delivery_id: "wh_old".into(),
        };
        let secret = secret();
        let auth = OpenAiWebhookAuthenticator {
            secret: &secret,
            verifier: &verifier,
        };
        let request = WebhookRequest {
            provider: Provider::OpenAiRealtime,
            exact_url: "https://meetings.snowmanai.org/webhooks/openai",
            headers: &headers,
            raw_body: &[],
            received_at: now,
        };
        assert_eq!(
            auth.verify(&request, now),
            Err(Error::WebhookAuthentication)
        );
    }
}
