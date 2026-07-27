//! Concrete, KMS-authenticated client for the private Snowman provider proxy.
//!
//! This module has no provider credential and cannot select a URL. It sends
//! only metadata-bound, target-free operations to an operations-sealed
//! destination ID, and it delegates provider callback cryptography to the same
//! proxy that exclusively owns the provider signing secrets.

use std::{collections::BTreeMap, sync::Arc, time::Duration as StdDuration};

use async_trait::async_trait;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::{
    canonical_digest,
    server::{
        CallbackAuthenticator, CallbackRequest, ProviderRuntime, RuntimeJoinReceipt,
        VerifiedCallback,
    },
    ConversationRoute, Error, IngressRoute, MediaSession, Provider, ProviderEstablished,
    ProviderPlan, RendererRoute,
};

const REQUEST_SCHEMA: &str = "snowman.provider-egress.request.v1";
const CANCEL_SCHEMA: &str = "snowman.provider-egress.cancel.v1";
const CALLBACK_SCHEMA: &str = "snowman.provider-callback.verify.v1";
const MAX_PROXY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Static, non-secret provider proxy client policy.
#[derive(Debug, Clone)]
pub struct ProviderProxyConfig {
    /// Exact private Snowman proxy origin.
    pub origin: Url,
    /// KMS-authenticated workload principal.
    pub principal_id: String,
    /// Exact meeting-media service identity.
    pub service_identity_id: Uuid,
    /// Same-account asymmetric signing key.
    pub signing_key_arn: String,
    /// Operations policy generation.
    pub policy_generation: u64,
    /// Sealed Twilio route ID.
    pub twilio_destination_id: String,
    /// Sealed OpenAI Realtime route ID.
    pub openai_destination_id: String,
    /// Optional output-only ElevenLabs route ID.
    pub elevenlabs_destination_id: Option<String>,
    /// Exact public Snowman callback origin, without path.
    pub callback_public_origin: Url,
}

impl ProviderProxyConfig {
    /// Validate that no public, upstream, userinfo, query, or path-selected
    /// proxy authority can enter the runtime.
    pub fn validate(&self) -> Result<(), Error> {
        let origin_host = self.origin.host_str().unwrap_or_default();
        let callback_host = self.callback_public_origin.host_str().unwrap_or_default();
        if self.origin.scheme() != "https"
            || !origin_host.ends_with(".internal.snowmanai.org")
            || self.origin.port() != Some(8443)
            || self.origin.path() != "/"
            || self.callback_public_origin.scheme() != "https"
            || !(callback_host == "meetings.snowmanai.org"
                || callback_host.ends_with(".meetings.snowmanai.org"))
            || self.callback_public_origin.path() != "/"
            || self.origin.query().is_some()
            || self.origin.fragment().is_some()
            || self.callback_public_origin.query().is_some()
            || self.callback_public_origin.fragment().is_some()
            || !self.origin.username().is_empty()
            || self.origin.password().is_some()
            || !self.callback_public_origin.username().is_empty()
            || self.callback_public_origin.password().is_some()
            || !valid_identifier(&self.principal_id)
            || self.policy_generation == 0
            || !exact_destination(&self.twilio_destination_id, "twilio")
            || !exact_destination(&self.openai_destination_id, "openai")
            || self
                .elevenlabs_destination_id
                .as_deref()
                .is_some_and(|value| !exact_destination(value, "elevenlabs"))
            || !exact_kms_key_arn(&self.signing_key_arn)
        {
            return Err(Error::ProviderDisabled);
        }
        Ok(())
    }
}

#[async_trait]
trait EnvelopeSigner: Send + Sync {
    async fn sign(&self, canonical: &[u8]) -> Result<Vec<u8>, Error>;
}

struct KmsEnvelopeSigner {
    client: aws_sdk_kms::Client,
    key_arn: String,
}

#[async_trait]
impl EnvelopeSigner for KmsEnvelopeSigner {
    async fn sign(&self, canonical: &[u8]) -> Result<Vec<u8>, Error> {
        let output = self
            .client
            .sign()
            .key_id(&self.key_arn)
            .message(Blob::new(canonical))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPssSha256)
            .send()
            .await
            .map_err(|_| Error::UntrustedAuthority)?;
        output
            .signature()
            .map(|value| value.as_ref().to_vec())
            .filter(|value| (128..=1024).contains(&value.len()))
            .ok_or(Error::UntrustedAuthority)
    }
}

#[async_trait]
trait ProxyHttp: Send + Sync {
    async fn post(&self, url: Url, body: Vec<u8>) -> Result<Vec<u8>, Error>;
}

struct PrivateProxyHttp {
    client: reqwest::Client,
}

impl PrivateProxyHttp {
    fn new() -> Result<Self, Error> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .https_only(true)
            .connect_timeout(StdDuration::from_secs(5))
            .timeout(StdDuration::from_secs(30))
            .build()
            .map_err(|_| Error::ProviderDisabled)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl ProxyHttp for PrivateProxyHttp {
    async fn post(&self, url: Url, body: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| Error::ProviderDisabled)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|value| value > MAX_PROXY_RESPONSE_BYTES as u64)
        {
            return Err(Error::ProviderDisabled);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error::ProviderDisabled)?
        {
            if body.len().saturating_add(chunk.len()) > MAX_PROXY_RESPONSE_BYTES {
                return Err(Error::ProviderDisabled);
            }
            body.extend_from_slice(&chunk);
        }
        if !body.is_empty()
            && response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !value.starts_with("application/json"))
        {
            return Err(Error::ProviderDisabled);
        }
        Ok(body)
    }
}

/// Production provider and callback adapter. All network requests terminate at
/// the exact private Snowman origin and are signed with the meeting-media KMS
/// workload key.
pub struct ProviderProxyRuntime {
    config: ProviderProxyConfig,
    signer: Arc<dyn EnvelopeSigner>,
    http: Arc<dyn ProxyHttp>,
}

impl ProviderProxyRuntime {
    /// Build the production adapter from AWS clients after static validation.
    pub fn new(config: ProviderProxyConfig, kms: aws_sdk_kms::Client) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            signer: Arc::new(KmsEnvelopeSigner {
                client: kms,
                key_arn: config.signing_key_arn.clone(),
            }),
            http: Arc::new(PrivateProxyHttp::new()?),
            config,
        })
    }

    async fn dispatch(
        &self,
        session: &MediaSession,
        plan: &ProviderPlan,
        provider: WireProvider,
        destination_id: &str,
        purpose: &str,
        now: DateTime<Utc>,
    ) -> Result<DispatchResponse, Error> {
        let payload = ProviderOperationPayload {
            schema_version: "snowman.meeting-provider.operation.v1",
            tenant_id: session.grant.tenant_id,
            workspace_id: session.grant.workspace_id,
            meeting_id: session.grant.meeting_id,
            service_identity_id: self.config.service_identity_id,
            meeting_agent_identity_id: session.grant.meeting_agent_identity_id,
            session_id: plan.session_id,
            session_generation: plan.session_generation,
            operation: purpose,
            sealed_coordinate_ref: (provider == WireProvider::Twilio)
                .then_some(plan.sealed_coordinate_ref.as_str()),
            conference_approval_sha256: &plan.conference_approval_sha256,
            provider_binding_sha256: &session.provider_binding_sha256,
            max_duration_seconds: plan.max_duration_seconds,
        };
        let payload =
            serde_json::to_vec(&payload).map_err(|_| Error::InvalidField("provider payload"))?;
        let envelope = DispatchEnvelope {
            schema_version: REQUEST_SCHEMA,
            request_id: deterministic_request_id(plan.session_id, plan.session_generation, purpose),
            principal_id: &self.config.principal_id,
            tenant_id: session.grant.tenant_id,
            session_id: plan.session_id,
            generation: u64::from(plan.session_generation),
            provider,
            purpose,
            classification: data_class(session.grant.data_class),
            budget_microusd: plan.max_cost_microusd,
            policy_generation: self.config.policy_generation,
            destination_id,
            content_type: "application/json",
            payload_sha256: hex::encode(Sha256::digest(&payload)),
            issued_at: now,
            deadline: plan.deadline.min(now + Duration::seconds(120)),
        };
        let signature = self
            .signer
            .sign(&serde_json::to_vec(&envelope).map_err(|_| Error::UntrustedAuthority)?)
            .await?;
        let wire = serde_json::to_vec(&DispatchWire {
            envelope,
            payload_base64: STANDARD.encode(payload),
            signature_base64: STANDARD.encode(signature),
        })
        .map_err(|_| Error::UntrustedAuthority)?;
        let url = self
            .config
            .origin
            .join(&format!("v1/tenants/{}/dispatch", session.grant.tenant_id))
            .map_err(|_| Error::ProviderDisabled)?;
        let response: DispatchResponse = serde_json::from_slice(&self.http.post(url, wire).await?)
            .map_err(|_| Error::ProviderDisabled)?;
        response.validate(session, plan, provider, destination_id, purpose)?;
        Ok(response)
    }

    fn callback_url(&self, provider: &str, binding_id: Uuid) -> String {
        format!(
            "{}v1/provider-callbacks/{provider}/{binding_id}",
            self.config.callback_public_origin
        )
    }
}

#[async_trait]
impl ProviderRuntime for ProviderProxyRuntime {
    async fn join(
        &self,
        session: &MediaSession,
        plan: &ProviderPlan,
        now: DateTime<Utc>,
    ) -> Result<RuntimeJoinReceipt, Error> {
        let mut established = Vec::new();
        if plan.ingress_route == IngressRoute::TwilioTelephony {
            let response = self
                .dispatch(
                    session,
                    plan,
                    WireProvider::Twilio,
                    &self.config.twilio_destination_id,
                    "meeting.twilio.media_stream.start",
                    now,
                )
                .await?;
            established.push(response.established(Provider::Twilio, now)?);
        }
        if plan.conversation_route == ConversationRoute::OpenAiRealtime {
            let response = self
                .dispatch(
                    session,
                    plan,
                    WireProvider::OpenAi,
                    &self.config.openai_destination_id,
                    "meeting.openai.realtime.connect",
                    now,
                )
                .await?;
            established.push(response.established(Provider::OpenAiRealtime, now)?);
        }
        if plan.renderer_route == RendererRoute::ElevenLabs
            && self.config.elevenlabs_destination_id.is_none()
        {
            return Err(Error::ProviderDisabled);
        }
        if established.is_empty() {
            return Err(Error::ProviderDisabled);
        }
        Ok(RuntimeJoinReceipt {
            provider_session_set_sha256: canonical_digest(&established)?,
            established,
        })
    }

    async fn stop(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u32,
        now: DateTime<Utc>,
    ) -> Result<String, Error> {
        let reason_sha256 = hex::encode(Sha256::digest(b"snowman.meeting-media.stop"));
        let envelope = CancelEnvelope {
            schema_version: CANCEL_SCHEMA,
            tenant_id,
            session_id,
            generation: u64::from(generation),
            principal_id: &self.config.principal_id,
            reason_sha256: &reason_sha256,
            issued_at: now,
            deadline: now + Duration::seconds(30),
        };
        let signature = self
            .signer
            .sign(&serde_json::to_vec(&envelope).map_err(|_| Error::UntrustedAuthority)?)
            .await?;
        let wire = serde_json::to_vec(&CancelWire {
            envelope,
            signature_base64: STANDARD.encode(signature),
        })
        .map_err(|_| Error::UntrustedAuthority)?;
        let url = self
            .config
            .origin
            .join(&format!(
                "v1/tenants/{tenant_id}/sessions/{session_id}/generations/{generation}/cancel"
            ))
            .map_err(|_| Error::ProviderDisabled)?;
        let _ = self.http.post(url, wire).await?;
        canonical_digest(&(tenant_id, session_id, generation, reason_sha256, now))
    }
}

#[async_trait]
impl CallbackAuthenticator for ProviderProxyRuntime {
    async fn verify(&self, request: CallbackRequest<'_>) -> Result<VerifiedCallback, Error> {
        if !matches!(
            request.provider,
            Provider::Twilio | Provider::OpenAiRealtime
        ) {
            return Err(Error::ProviderDisabled);
        }
        let provider_path = match request.provider {
            Provider::Twilio => "twilio",
            Provider::OpenAiRealtime => "open_ai_realtime",
            _ => return Err(Error::ProviderDisabled),
        };
        let mut exact_url = self.callback_url(provider_path, request.callback_binding_id);
        if request.websocket_upgrade {
            exact_url = exact_url.replacen("https://", "wss://", 1);
        }
        let headers = callback_headers(request.headers)?;
        let envelope = CallbackEnvelope {
            schema_version: CALLBACK_SCHEMA,
            request_id: Uuid::new_v4(),
            principal_id: &self.config.principal_id,
            callback_binding_id: request.callback_binding_id,
            method: if request.websocket_upgrade {
                "GET"
            } else {
                "POST"
            },
            exact_public_url: &exact_url,
            headers,
            body_sha256: hex::encode(Sha256::digest(request.body)),
            websocket_upgrade: request.websocket_upgrade,
            issued_at: request.received_at,
            deadline: request.received_at + Duration::seconds(30),
        };
        let signature = self
            .signer
            .sign(&serde_json::to_vec(&envelope).map_err(|_| Error::UntrustedAuthority)?)
            .await?;
        let wire = serde_json::to_vec(&CallbackWire {
            envelope,
            body_base64: STANDARD.encode(request.body),
            signature_base64: STANDARD.encode(signature),
        })
        .map_err(|_| Error::UntrustedAuthority)?;
        let url = self
            .config
            .origin
            .join(&format!(
                "v1/callback-bindings/{}/verify",
                request.callback_binding_id
            ))
            .map_err(|_| Error::ProviderDisabled)?;
        let response: CallbackResponse = serde_json::from_slice(&self.http.post(url, wire).await?)
            .map_err(|_| Error::WebhookAuthentication)?;
        if response.provider != WireProvider::from(request.provider)
            || response.service_identity_id != self.config.service_identity_id
            || !matches!(
                response.classification.as_str(),
                "internal" | "confidential"
            )
        {
            return Err(Error::BoundaryMismatch);
        }
        for digest in [
            &response.delivery_id_sha256,
            &response.request_sha256,
            &response.authentication_key_version_sha256,
        ] {
            crate::validate_digest(digest, "provider callback digest")?;
        }
        Ok(VerifiedCallback {
            tenant_id: response.tenant_id,
            workspace_id: response.workspace_id,
            meeting_id: response.meeting_id,
            service_identity_id: response.service_identity_id,
            delivery_id_sha256: response.delivery_id_sha256,
            request_sha256: response.request_sha256,
            authentication_key_version_sha256: response.authentication_key_version_sha256,
            session_id: None,
            session_generation: None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireProvider {
    Twilio,
    OpenAi,
    ElevenLabs,
}

impl From<Provider> for WireProvider {
    fn from(value: Provider) -> Self {
        match value {
            Provider::Twilio => Self::Twilio,
            Provider::OpenAiRealtime => Self::OpenAi,
            Provider::ElevenLabs => Self::ElevenLabs,
            Provider::SnowmanHuddle | Provider::SnowmanAws => Self::OpenAi,
        }
    }
}

#[derive(Serialize)]
struct ProviderOperationPayload<'a> {
    schema_version: &'static str,
    tenant_id: Uuid,
    workspace_id: Uuid,
    meeting_id: Uuid,
    service_identity_id: Uuid,
    meeting_agent_identity_id: Uuid,
    session_id: Uuid,
    session_generation: u32,
    operation: &'a str,
    sealed_coordinate_ref: Option<&'a str>,
    conference_approval_sha256: &'a str,
    provider_binding_sha256: &'a str,
    max_duration_seconds: u32,
}

#[derive(Serialize)]
struct DispatchEnvelope<'a> {
    schema_version: &'static str,
    request_id: Uuid,
    principal_id: &'a str,
    tenant_id: Uuid,
    session_id: Uuid,
    generation: u64,
    provider: WireProvider,
    purpose: &'a str,
    classification: &'a str,
    budget_microusd: u64,
    policy_generation: u64,
    destination_id: &'a str,
    content_type: &'static str,
    payload_sha256: String,
    issued_at: DateTime<Utc>,
    deadline: DateTime<Utc>,
}

#[derive(Serialize)]
struct DispatchWire<'a> {
    envelope: DispatchEnvelope<'a>,
    payload_base64: String,
    signature_base64: String,
}

#[derive(Deserialize)]
struct DispatchResponse {
    receipt: DispatchReceipt,
    response_base64: Option<String>,
    replayed: bool,
}

#[derive(Deserialize)]
struct DispatchReceipt {
    request_id: Uuid,
    tenant_id: Uuid,
    session_id: Uuid,
    generation: u64,
    provider: WireProvider,
    purpose: String,
    classification: String,
    destination_id: String,
    request_sha256: String,
    response_sha256: String,
    status: String,
}

impl DispatchResponse {
    fn validate(
        &self,
        session: &MediaSession,
        plan: &ProviderPlan,
        provider: WireProvider,
        destination: &str,
        purpose: &str,
    ) -> Result<(), Error> {
        let receipt = &self.receipt;
        if self.replayed
            || receipt.tenant_id != session.grant.tenant_id
            || receipt.session_id != plan.session_id
            || receipt.generation != u64::from(plan.session_generation)
            || receipt.provider != provider
            || receipt.purpose != purpose
            || receipt.classification != data_class(session.grant.data_class)
            || receipt.destination_id != destination
            || receipt.status != "succeeded"
            || self.response_base64.is_none()
        {
            return Err(Error::BoundaryMismatch);
        }
        crate::validate_digest(&receipt.request_sha256, "provider request receipt")?;
        crate::validate_digest(&receipt.response_sha256, "provider response receipt")
    }

    fn established(
        &self,
        provider: Provider,
        now: DateTime<Utc>,
    ) -> Result<ProviderEstablished, Error> {
        let body = STANDARD
            .decode(
                self.response_base64
                    .as_deref()
                    .ok_or(Error::ProviderDisabled)?,
            )
            .map_err(|_| Error::ProviderDisabled)?;
        let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let provider_id = ["id", "sid", "call_sid", "session_id"]
            .iter()
            .find_map(|field| value.get(field).and_then(Value::as_str));
        let provider_session_id_sha256 = provider_id
            .map(|value| hex::encode(Sha256::digest(value.as_bytes())))
            .unwrap_or_else(|| self.receipt.response_sha256.clone());
        Ok(ProviderEstablished {
            provider,
            provider_session_id_sha256,
            handshake_sha256: canonical_digest(&(
                &self.receipt.request_sha256,
                &self.receipt.response_sha256,
                self.receipt.request_id,
            ))?,
            observed_at: now,
        })
    }
}

#[derive(Serialize)]
struct CancelEnvelope<'a> {
    schema_version: &'static str,
    tenant_id: Uuid,
    session_id: Uuid,
    generation: u64,
    principal_id: &'a str,
    reason_sha256: &'a str,
    issued_at: DateTime<Utc>,
    deadline: DateTime<Utc>,
}
#[derive(Serialize)]
struct CancelWire<'a> {
    envelope: CancelEnvelope<'a>,
    signature_base64: String,
}

#[derive(Serialize)]
struct CallbackEnvelope<'a> {
    schema_version: &'static str,
    request_id: Uuid,
    principal_id: &'a str,
    callback_binding_id: Uuid,
    method: &'static str,
    exact_public_url: &'a str,
    headers: BTreeMap<String, String>,
    body_sha256: String,
    websocket_upgrade: bool,
    issued_at: DateTime<Utc>,
    deadline: DateTime<Utc>,
}
#[derive(Serialize)]
struct CallbackWire<'a> {
    envelope: CallbackEnvelope<'a>,
    body_base64: String,
    signature_base64: String,
}
#[derive(Deserialize)]
struct CallbackResponse {
    tenant_id: Uuid,
    workspace_id: Uuid,
    meeting_id: Uuid,
    service_identity_id: Uuid,
    provider: WireProvider,
    classification: String,
    delivery_id_sha256: String,
    request_sha256: String,
    authentication_key_version_sha256: String,
}

fn callback_headers(headers: &axum::http::HeaderMap) -> Result<BTreeMap<String, String>, Error> {
    let mut result = BTreeMap::new();
    for (name, value) in headers {
        let name = name.as_str().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "authorization" | "cookie" | "proxy-authorization"
        ) {
            return Err(Error::WebhookAuthentication);
        }
        let value = value.to_str().map_err(|_| Error::WebhookAuthentication)?;
        if value.is_empty() || value.len() > 8192 || result.insert(name, value.into()).is_some() {
            return Err(Error::WebhookAuthentication);
        }
    }
    if result.len() > 64 {
        return Err(Error::WebhookAuthentication);
    }
    Ok(result)
}

fn deterministic_request_id(session_id: Uuid, generation: u32, purpose: &str) -> Uuid {
    Uuid::new_v5(&session_id, format!("{generation}:{purpose}").as_bytes())
}
fn data_class(value: snowman_meeting_control::DataClass) -> &'static str {
    match value {
        snowman_meeting_control::DataClass::Internal => "internal",
        snowman_meeting_control::DataClass::Confidential => "confidential",
        snowman_meeting_control::DataClass::Restricted => "restricted",
    }
}
fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}
fn exact_destination(value: &str, provider: &str) -> bool {
    value.starts_with(&format!("snowman.meeting.{provider}.")) && valid_identifier(value)
}
fn exact_kms_key_arn(value: &str) -> bool {
    let parts = value.split(':').collect::<Vec<_>>();
    parts.len() == 6
        && parts[0] == "arn"
        && parts[2] == "kms"
        && parts[4].len() == 12
        && parts[5].starts_with("key/")
        && !value.contains('*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ProviderProxyConfig {
        ProviderProxyConfig {
            origin: Url::parse("https://providers.staging.internal.snowmanai.org:8443/").unwrap(),
            principal_id: "snowman-meeting-media".into(),
            service_identity_id: Uuid::new_v4(),
            signing_key_arn:
                "arn:aws:kms:us-west-2:625242091862:key/00000000-0000-4000-8000-000000000001".into(),
            policy_generation: 1,
            twilio_destination_id: "snowman.meeting.twilio.start".into(),
            openai_destination_id: "snowman.meeting.openai.connect".into(),
            elevenlabs_destination_id: None,
            callback_public_origin: Url::parse("https://meetings.snowmanai.org/").unwrap(),
        }
    }

    #[test]
    fn config_rejects_non_snowman_and_mutable_destinations() {
        assert!(config().validate().is_ok());
        let mut bad = config();
        bad.origin = Url::parse("https://api.twilio.com:8443/").unwrap();
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.openai_destination_id = "https://api.openai.com".into();
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.callback_public_origin = Url::parse("https://meetings.block.xyz/").unwrap();
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.signing_key_arn = "arn:aws:kms:us-west-2:625242091862:key/*".into();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn callback_headers_reject_ambient_credentials_and_duplicates() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", "secret".parse().unwrap());
        assert!(callback_headers(&headers).is_err());
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("cookie", "secret".parse().unwrap());
        assert!(callback_headers(&headers).is_err());
    }
}
