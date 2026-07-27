#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Deny-by-default provider egress for governed Snowman meeting sessions.
//!
//! Callers select an operations-sealed destination identifier, never a URL or
//! credential. The proxy authenticates a canonical request, applies live
//! policy and cancellation fences, resolves the exact allowlisted hostname,
//! and hands a pinned address set plus TLS SNI name to an injected direct
//! transport. Only the transport may retrieve and inject a provider secret.

/// Private production HTTP, AWS, DNS, and PostgreSQL adapters.
pub mod server;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use url::Url;
use uuid::Uuid;

/// Maximum accepted provider request payload (8 MiB).
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
/// Absolute maximum transient provider response (16 MiB).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum time until a signed request deadline.
pub const MAX_DEADLINE_HORIZON_SECONDS: i64 = 120;
/// Maximum tolerated signed-request age.
pub const MAX_ASSERTION_AGE_SECONDS: i64 = 60;
/// Canonical request schema.
pub const REQUEST_SCHEMA: &str = "snowman.provider-egress.request.v1";
/// Redacted receipt schema.
pub const RECEIPT_SCHEMA: &str = "snowman.provider-egress.receipt.v1";

/// The only provider families the boundary can represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// Twilio voice and messaging APIs.
    Twilio,
    /// OpenAI APIs used by Snowman-owned workloads.
    OpenAi,
    /// Optional ElevenLabs voice synthesis APIs.
    ElevenLabs,
}

/// HTTP methods that may be sealed into provider routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// Retrieve a bounded resource.
    Get,
    /// Create one idempotency-fenced provider operation.
    Post,
    /// Delete one exact provider resource.
    Delete,
}

impl Provider {
    fn exact_hostname(self) -> &'static str {
        match self {
            Self::Twilio => "api.twilio.com",
            Self::OpenAi => "api.openai.com",
            Self::ElevenLabs => "api.elevenlabs.io",
        }
    }
}

/// Operations-owned reference to a secret in AWS Secrets Manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretReference {
    /// Exact same-account secret ARN.
    pub arn: String,
    /// Exact JSON key the direct transport may extract.
    pub json_key: String,
}

/// One sealed provider route. It is loaded from trusted operations
/// configuration and is never constructed from caller-supplied URLs.
#[derive(Debug, Clone)]
pub struct RoutePolicy {
    /// Stable identifier callers bind into their signed request.
    pub destination_id: String,
    /// Provider family.
    pub provider: Provider,
    /// Exact HTTPS endpoint, including an operations-selected path.
    pub endpoint: Url,
    /// Exact HTTP method sealed with the endpoint.
    pub method: HttpMethod,
    /// Provider credential reference. Only a transport implementation may use it.
    pub secret: SecretReference,
    /// Workload principals permitted to use the route.
    pub principal_ids: BTreeSet<String>,
    /// Tenant IDs permitted to use the route.
    pub tenant_ids: BTreeSet<Uuid>,
    /// Exact governed purposes permitted by the route.
    pub purposes: BTreeSet<String>,
    /// Exact data classifications permitted by the route.
    pub classifications: BTreeSet<String>,
    /// Exact accepted outbound content types.
    pub request_content_types: BTreeSet<String>,
    /// Exact accepted successful response content types.
    pub response_content_types: BTreeSet<String>,
    /// Maximum caller-authorized spend for one request.
    pub max_budget_microusd: u64,
    /// Route-specific request size ceiling.
    pub max_request_bytes: usize,
    /// Route-specific response size ceiling.
    pub max_response_bytes: usize,
    /// Direct transport timeout.
    pub timeout: Duration,
}

/// Signed, policy-bound request metadata. The raw payload is authenticated by
/// `payload_sha256` but excluded from the canonical JSON to keep it bounded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Exact schema version.
    pub schema_version: String,
    /// Unique idempotency and replay key.
    pub request_id: Uuid,
    /// Authenticated calling workload.
    pub principal_id: String,
    /// Tenant boundary.
    pub tenant_id: Uuid,
    /// Governed meeting session.
    pub session_id: Uuid,
    /// Monotonic session generation.
    pub generation: u64,
    /// Provider family expected by the sealed destination.
    pub provider: Provider,
    /// Exact governed purpose.
    pub purpose: String,
    /// Exact data classification.
    pub classification: String,
    /// Maximum authorized provider spend, in micro-USD.
    pub budget_microusd: u64,
    /// Current policy generation expected by the caller.
    pub policy_generation: u64,
    /// Operations-sealed destination identifier, never a URL.
    pub destination_id: String,
    /// Exact request media type.
    pub content_type: String,
    /// SHA-256 of the transient provider request body.
    pub payload_sha256: String,
    /// UTC time at which the caller signed the envelope.
    pub issued_at: DateTime<Utc>,
    /// Hard dispatch deadline.
    pub deadline: DateTime<Utc>,
}

/// Complete authenticated request accepted by the core.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// Signed policy metadata.
    pub envelope: RequestEnvelope,
    /// Opaque provider payload retained only for the in-flight request.
    pub payload: Vec<u8>,
    /// Detached signature verified by the configured Snowman identity provider.
    pub signature: Vec<u8>,
}

/// Canonical bytes signed by an authenticated caller.
pub fn canonical_request(envelope: &RequestEnvelope) -> Result<Vec<u8>, ProxyError> {
    serde_json::to_vec(envelope).map_err(|_| ProxyError::InvalidRequest)
}

/// A signature verifier backed by Snowman workload identity in production.
#[async_trait]
pub trait SignatureVerifier: Send + Sync {
    /// Verify the exact canonical bytes for `principal_id`.
    async fn verify(
        &self,
        principal_id: &str,
        canonical: &[u8],
        signature: &[u8],
    ) -> Result<(), ProxyError>;
}

/// DNS resolver used to pin a fresh public address set for each dispatch.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve the exact allowlisted hostname without search-domain expansion.
    async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, ProxyError>;
}

/// Request passed only to a direct transport implementation.
///
/// A production implementation must disable system proxy discovery and HTTP
/// redirects, connect only to `resolved_ips`, validate the certificate for
/// `tls_server_name`, and use that same value for TLS SNI and HTTP authority.
#[derive(Debug, Clone)]
pub struct TransportRequest {
    /// Exact HTTPS URL from trusted route configuration.
    pub endpoint: Url,
    /// Exact method from trusted route configuration.
    pub method: HttpMethod,
    /// Exact TLS hostname and SNI value.
    pub tls_server_name: String,
    /// Fresh public-only address set to which the connection is pinned.
    pub resolved_ips: Vec<IpAddr>,
    /// Provider family controlling credential injection.
    pub provider: Provider,
    /// Secret reference resolved only inside the transport.
    pub secret: SecretReference,
    /// Provider idempotency key.
    pub idempotency_key: Uuid,
    /// Exact request content type.
    pub content_type: String,
    /// Transient provider request body.
    pub body: Vec<u8>,
    /// Maximum response bytes accepted by the core.
    pub max_response_bytes: usize,
}

/// Bounded response from a direct provider transport.
#[derive(Debug, Clone)]
pub struct TransportResponse {
    /// HTTP status returned without following redirects.
    pub status: u16,
    /// Normalized response content type without parameters.
    pub content_type: String,
    /// Transient body; never sent to a receipt store.
    pub body: Vec<u8>,
}

/// Direct provider transport with exclusive access to provider secrets.
#[async_trait]
pub trait ProviderTransport: Send + Sync {
    /// Resolve the secret reference internally and make one direct HTTPS call.
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, ProxyError>;
}

/// Durable outcomes that an implementation of the replay fence may return.
#[derive(Debug, Clone)]
pub enum ClaimOutcome {
    /// This exact request digest has been claimed by this invocation.
    Claimed,
    /// The exact request already reached a durable outcome.
    Duplicate(Box<Receipt>),
    /// The same request ID was used with different signed content.
    Conflict,
    /// Cancellation won before the request was dispatched.
    Cancelled,
}

/// Replay and cancellation authority. It receives only digests and redacted
/// receipts, never provider request or response bodies.
#[async_trait]
pub trait RequestFence: Send + Sync {
    /// Atomically claim one request ID and digest, respecting cancellation.
    async fn claim(
        &self,
        envelope: &RequestEnvelope,
        request_sha256: &str,
    ) -> Result<ClaimOutcome, ProxyError>;

    /// Recheck cancellation immediately before dispatch.
    async fn is_cancelled(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u64,
    ) -> Result<bool, ProxyError>;

    /// Wait until cancellation wins for this generation.
    async fn wait_cancelled(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        generation: u64,
    ) -> Result<(), ProxyError>;

    /// Persist a sticky indeterminate marker before any provider bytes can be sent.
    async fn mark_dispatched(&self, receipt: &Receipt) -> Result<(), ProxyError>;

    /// Persist only the redacted terminal or indeterminate receipt.
    async fn complete(&self, receipt: &Receipt) -> Result<(), ProxyError>;
}

/// Receipt status. `Indeterminate` is deliberately sticky: retrying may
/// duplicate a provider-side effect after a timeout or mid-flight cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    /// Provider returned one accepted, bounded response.
    Succeeded,
    /// Provider rejected the request; its body was discarded.
    ProviderRejected,
    /// Cancellation won before transport dispatch.
    Cancelled,
    /// The signed deadline expired while waiting for bounded local authority.
    Expired,
    /// DNS or another direct-transport prerequisite failed before dispatch.
    PreDispatchDenied,
    /// Dispatch may have reached the provider but no authoritative result exists.
    Indeterminate,
}

/// Content-free provider dispatch receipt safe for audit persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Exact receipt schema.
    pub schema_version: String,
    /// Request identifier.
    pub request_id: Uuid,
    /// Tenant boundary.
    pub tenant_id: Uuid,
    /// Meeting session boundary.
    pub session_id: Uuid,
    /// Session generation.
    pub generation: u64,
    /// Provider family.
    pub provider: Provider,
    /// Governed purpose.
    pub purpose: String,
    /// Classification policy applied.
    pub classification: String,
    /// Authorized maximum spend.
    pub budget_microusd: u64,
    /// Policy generation applied.
    pub policy_generation: u64,
    /// Sealed destination identifier, never its URL.
    pub destination_id: String,
    /// SHA-256 of the signed envelope plus payload digest.
    pub request_sha256: String,
    /// SHA-256 of a successful response, or all zeroes when absent.
    pub response_sha256: String,
    /// Response byte count, or zero when absent/discarded.
    pub response_bytes: usize,
    /// Durable outcome.
    pub status: ReceiptStatus,
    /// Completion time.
    pub completed_at: DateTime<Utc>,
}

/// A completed proxy invocation. `response` is transient and is never passed
/// to the replay fence; exact replays return only the prior receipt.
#[derive(Debug, Clone)]
pub struct ProxyResult {
    /// Content-free receipt.
    pub receipt: Receipt,
    /// Successful response body for the live caller only.
    pub response: Option<Vec<u8>>,
    /// Successful response content type for the live caller only.
    pub response_content_type: Option<String>,
    /// Whether the receipt came from an exact replay.
    pub replayed: bool,
}

/// Fail-closed proxy failures. Display strings contain no caller or provider content.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// Request structure, hashes, time bounds, or policy binding are invalid.
    #[error("provider egress request is invalid")]
    InvalidRequest,
    /// Caller authentication failed.
    #[error("provider egress authentication failed")]
    Authentication,
    /// Exact policy does not authorize this request.
    #[error("provider egress policy denied the request")]
    PolicyDenied,
    /// Request identifier was reused with different signed content.
    #[error("provider egress replay conflict")]
    ReplayConflict,
    /// Resolver returned no safe public address set.
    #[error("provider egress resolution failed closed")]
    ResolutionDenied,
    /// Provider response violated transport, size, status, or media policy.
    #[error("provider egress transport failed closed")]
    TransportDenied,
    /// Internal authority is unavailable; no provider call may be attempted.
    #[error("provider egress authority unavailable")]
    AuthorityUnavailable,
}

/// Validated, bounded proxy core.
pub struct Proxy {
    policy_generation: u64,
    routes: BTreeMap<String, RoutePolicy>,
    verifier: Arc<dyn SignatureVerifier>,
    resolver: Arc<dyn Resolver>,
    transport: Arc<dyn ProviderTransport>,
    fence: Arc<dyn RequestFence>,
    concurrency: Arc<Semaphore>,
}

impl Proxy {
    /// Construct a proxy only when every trusted route satisfies the exact
    /// public-provider and secret-reference policy.
    pub fn new(
        policy_generation: u64,
        routes: Vec<RoutePolicy>,
        max_concurrency: usize,
        verifier: Arc<dyn SignatureVerifier>,
        resolver: Arc<dyn Resolver>,
        transport: Arc<dyn ProviderTransport>,
        fence: Arc<dyn RequestFence>,
    ) -> Result<Self, ProxyError> {
        if policy_generation == 0 || !(1..=128).contains(&max_concurrency) || routes.is_empty() {
            return Err(ProxyError::InvalidRequest);
        }
        let mut indexed = BTreeMap::new();
        for route in routes {
            validate_route(&route)?;
            if indexed
                .insert(route.destination_id.clone(), route)
                .is_some()
            {
                return Err(ProxyError::InvalidRequest);
            }
        }
        Ok(Self {
            policy_generation,
            routes: indexed,
            verifier,
            resolver,
            transport,
            fence,
            concurrency: Arc::new(Semaphore::new(max_concurrency)),
        })
    }

    /// Authenticate, authorize, and perform at most one bounded provider call.
    pub async fn execute(&self, request: SignedRequest) -> Result<ProxyResult, ProxyError> {
        let now = Utc::now();
        self.validate_request_structure(&request, now)?;
        let canonical = canonical_request(&request.envelope)?;
        self.verifier
            .verify(
                &request.envelope.principal_id,
                &canonical,
                &request.signature,
            )
            .await?;
        let route = self.authorize_request(&request)?;
        let request_sha256 = sha256(&canonical);
        match self.fence.claim(&request.envelope, &request_sha256).await? {
            ClaimOutcome::Duplicate(receipt) => {
                if receipt.request_sha256 != request_sha256 {
                    return Err(ProxyError::ReplayConflict);
                }
                return Ok(ProxyResult {
                    receipt: *receipt,
                    response: None,
                    response_content_type: None,
                    replayed: true,
                });
            }
            ClaimOutcome::Conflict => return Err(ProxyError::ReplayConflict),
            ClaimOutcome::Cancelled => {
                return self
                    .finish(
                        &request.envelope,
                        request_sha256,
                        ReceiptStatus::Cancelled,
                        None,
                    )
                    .await
            }
            ClaimOutcome::Claimed => {}
        }

        let _permit = self
            .concurrency
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ProxyError::AuthorityUnavailable)?;
        if Utc::now() >= request.envelope.deadline {
            return self
                .finish(
                    &request.envelope,
                    request_sha256,
                    ReceiptStatus::Expired,
                    None,
                )
                .await;
        }
        if self
            .fence
            .is_cancelled(
                request.envelope.tenant_id,
                request.envelope.session_id,
                request.envelope.generation,
            )
            .await?
        {
            return self
                .finish(
                    &request.envelope,
                    request_sha256,
                    ReceiptStatus::Cancelled,
                    None,
                )
                .await;
        }

        let hostname = route
            .endpoint
            .host_str()
            .ok_or(ProxyError::PolicyDenied)?
            .to_owned();
        let addresses = match self.resolver.resolve(&hostname).await {
            Ok(addresses) => addresses,
            Err(_) => {
                return self
                    .finish(
                        &request.envelope,
                        request_sha256,
                        ReceiptStatus::PreDispatchDenied,
                        None,
                    )
                    .await
            }
        };
        if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(*address)) {
            return self
                .finish(
                    &request.envelope,
                    request_sha256,
                    ReceiptStatus::PreDispatchDenied,
                    None,
                )
                .await;
        }
        if Utc::now() >= request.envelope.deadline {
            return self
                .finish(
                    &request.envelope,
                    request_sha256,
                    ReceiptStatus::Expired,
                    None,
                )
                .await;
        }
        if self
            .fence
            .is_cancelled(
                request.envelope.tenant_id,
                request.envelope.session_id,
                request.envelope.generation,
            )
            .await?
        {
            return self
                .finish(
                    &request.envelope,
                    request_sha256,
                    ReceiptStatus::Cancelled,
                    None,
                )
                .await;
        }

        let outbound = TransportRequest {
            endpoint: route.endpoint.clone(),
            method: route.method,
            tls_server_name: hostname,
            resolved_ips: addresses,
            provider: route.provider,
            secret: route.secret.clone(),
            idempotency_key: request.envelope.request_id,
            content_type: request.envelope.content_type.clone(),
            body: request.payload,
            max_response_bytes: route.max_response_bytes,
        };
        let remaining = (request.envelope.deadline - Utc::now())
            .to_std()
            .map_err(|_| ProxyError::InvalidRequest)?
            .min(route.timeout);
        let dispatched_receipt = build_receipt(
            &request.envelope,
            request_sha256.clone(),
            ReceiptStatus::Indeterminate,
            None,
        );
        self.fence.mark_dispatched(&dispatched_receipt).await?;
        let transport = self.transport.send(outbound);
        let cancelled = self.fence.wait_cancelled(
            request.envelope.tenant_id,
            request.envelope.session_id,
            request.envelope.generation,
        );
        let response = tokio::select! {
            biased;
            cancel = cancelled => {
                cancel?;
                return self.finish(
                    &request.envelope,
                    request_sha256,
                    ReceiptStatus::Indeterminate,
                    None,
                ).await;
            }
            result = tokio::time::timeout(remaining, transport) => {
                match result {
                    Ok(Ok(response)) => response,
                    Ok(Err(_)) | Err(_) => {
                        return self.finish(
                            &request.envelope,
                            request_sha256,
                            ReceiptStatus::Indeterminate,
                            None,
                        ).await;
                    }
                }
            }
        };

        if response.body.len() > route.max_response_bytes
            || response.body.len() > MAX_RESPONSE_BYTES
            || (300..400).contains(&response.status)
        {
            return self
                .finish(
                    &request.envelope,
                    request_sha256,
                    ReceiptStatus::Indeterminate,
                    None,
                )
                .await;
        }
        let content_type = normalize_content_type(&response.content_type)?;
        if !(200..300).contains(&response.status) {
            return self
                .finish(
                    &request.envelope,
                    request_sha256,
                    ReceiptStatus::ProviderRejected,
                    None,
                )
                .await;
        }
        if !route.response_content_types.contains(content_type) {
            return self
                .finish(
                    &request.envelope,
                    request_sha256,
                    ReceiptStatus::Indeterminate,
                    None,
                )
                .await;
        }
        let body = response.body;
        let result_material = (sha256(&body), body.len(), body, content_type.to_owned());
        self.finish(
            &request.envelope,
            request_sha256,
            ReceiptStatus::Succeeded,
            Some(result_material),
        )
        .await
    }

    fn validate_request_structure(
        &self,
        request: &SignedRequest,
        now: DateTime<Utc>,
    ) -> Result<(), ProxyError> {
        let envelope = &request.envelope;
        if envelope.schema_version != REQUEST_SCHEMA
            || envelope.request_id.is_nil()
            || envelope.tenant_id.is_nil()
            || envelope.session_id.is_nil()
            || envelope.generation == 0
            || envelope.policy_generation != self.policy_generation
            || envelope.budget_microusd == 0
            || request.payload.is_empty()
            || request.payload.len() > MAX_REQUEST_BYTES
            || request.signature.is_empty()
            || request.signature.len() > 16 * 1024
            || !valid_identifier(&envelope.principal_id)
            || !valid_identifier(&envelope.destination_id)
            || !valid_identifier(&envelope.purpose)
            || !valid_identifier(&envelope.classification)
            || !is_sha256(&envelope.payload_sha256)
            || envelope.payload_sha256 != sha256(&request.payload)
            || envelope.issued_at > now + chrono::Duration::seconds(10)
            || envelope.issued_at < now - chrono::Duration::seconds(MAX_ASSERTION_AGE_SECONDS)
            || envelope.deadline <= now
            || envelope.deadline > now + chrono::Duration::seconds(MAX_DEADLINE_HORIZON_SECONDS)
            || envelope.deadline <= envelope.issued_at
        {
            return Err(ProxyError::InvalidRequest);
        }
        Ok(())
    }

    fn authorize_request<'a>(
        &'a self,
        request: &SignedRequest,
    ) -> Result<&'a RoutePolicy, ProxyError> {
        let envelope = &request.envelope;
        let route = self
            .routes
            .get(&envelope.destination_id)
            .ok_or(ProxyError::PolicyDenied)?;
        if route.provider != envelope.provider
            || !route.principal_ids.contains(&envelope.principal_id)
            || !route.tenant_ids.contains(&envelope.tenant_id)
            || !route.purposes.contains(&envelope.purpose)
            || !route.classifications.contains(&envelope.classification)
            || !route.request_content_types.contains(&envelope.content_type)
            || envelope.budget_microusd > route.max_budget_microusd
            || request.payload.len() > route.max_request_bytes
        {
            return Err(ProxyError::PolicyDenied);
        }
        Ok(route)
    }

    async fn finish(
        &self,
        envelope: &RequestEnvelope,
        request_sha256: String,
        status: ReceiptStatus,
        response: Option<(String, usize, Vec<u8>, String)>,
    ) -> Result<ProxyResult, ProxyError> {
        let (response_sha256, response_bytes, body, content_type) = match response {
            Some((digest, size, body, content_type)) => {
                (digest, size, Some(body), Some(content_type))
            }
            None => ("0".repeat(64), 0, None, None),
        };
        let receipt = build_receipt(
            envelope,
            request_sha256,
            status,
            Some((response_sha256, response_bytes)),
        );
        self.fence.complete(&receipt).await?;
        Ok(ProxyResult {
            receipt,
            response: body,
            response_content_type: content_type,
            replayed: false,
        })
    }
}

fn build_receipt(
    envelope: &RequestEnvelope,
    request_sha256: String,
    status: ReceiptStatus,
    response: Option<(String, usize)>,
) -> Receipt {
    let (response_sha256, response_bytes) = response.unwrap_or_else(|| ("0".repeat(64), 0));
    Receipt {
        schema_version: RECEIPT_SCHEMA.to_owned(),
        request_id: envelope.request_id,
        tenant_id: envelope.tenant_id,
        session_id: envelope.session_id,
        generation: envelope.generation,
        provider: envelope.provider,
        purpose: envelope.purpose.clone(),
        classification: envelope.classification.clone(),
        budget_microusd: envelope.budget_microusd,
        policy_generation: envelope.policy_generation,
        destination_id: envelope.destination_id.clone(),
        request_sha256,
        response_sha256,
        response_bytes,
        status,
        completed_at: Utc::now(),
    }
}

fn validate_route(route: &RoutePolicy) -> Result<(), ProxyError> {
    let host = route
        .endpoint
        .host_str()
        .ok_or(ProxyError::InvalidRequest)?;
    if !valid_identifier(&route.destination_id)
        || route.endpoint.scheme() != "https"
        || host != route.provider.exact_hostname()
        || route.endpoint.port_or_known_default() != Some(443)
        || !route.endpoint.username().is_empty()
        || route.endpoint.password().is_some()
        || route.endpoint.query().is_some()
        || route.endpoint.fragment().is_some()
        || !valid_provider_path(route.provider, route.endpoint.path())
        || route.endpoint.path().contains("..")
        || route.endpoint.path().contains("//")
        || route.endpoint.path().contains('%')
        || !valid_secret_reference(&route.secret)
        || route.principal_ids.is_empty()
        || route.tenant_ids.is_empty()
        || route.purposes.is_empty()
        || route.classifications.is_empty()
        || route.request_content_types.is_empty()
        || route.response_content_types.is_empty()
        || route.max_budget_microusd == 0
        || route.max_request_bytes == 0
        || route.max_request_bytes > MAX_REQUEST_BYTES
        || route.max_response_bytes == 0
        || route.max_response_bytes > MAX_RESPONSE_BYTES
        || route.timeout.is_zero()
        || route.timeout > Duration::from_secs(120)
        || route
            .principal_ids
            .iter()
            .any(|value| !valid_identifier(value))
        || route.purposes.iter().any(|value| !valid_identifier(value))
        || route
            .classifications
            .iter()
            .any(|value| !valid_identifier(value))
        || route
            .request_content_types
            .iter()
            .chain(route.response_content_types.iter())
            .any(|value| normalize_content_type(value).ok() != Some(value.as_str()))
    {
        return Err(ProxyError::InvalidRequest);
    }
    Ok(())
}

fn valid_provider_path(provider: Provider, path: &str) -> bool {
    match provider {
        Provider::Twilio => path.starts_with("/2010-04-01/"),
        Provider::OpenAi | Provider::ElevenLabs => path.starts_with("/v1/"),
    }
}

fn valid_secret_reference(reference: &SecretReference) -> bool {
    reference.arn.starts_with("arn:aws:secretsmanager:")
        && reference.arn.contains(":secret:snowman-")
        && !reference.arn.contains('*')
        && valid_identifier(&reference.json_key)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn normalize_content_type(value: &str) -> Result<&str, ProxyError> {
    let normalized = value
        .split(';')
        .next()
        .map(str::trim)
        .ok_or(ProxyError::TransportDenied)?;
    if normalized.is_empty()
        || normalized.len() > 100
        || normalized.bytes().any(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'/' | b'-' | b'+' | b'.'))
        })
        || !normalized.contains('/')
    {
        return Err(ProxyError::TransportDenied);
    }
    Ok(normalized)
}

fn sha256(bytes: &[u8]) -> String {
    hex_lower(Sha256::digest(bytes).as_slice())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113))
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || address
            .to_ipv4_mapped()
            .is_some_and(|mapped| !is_public_ipv4(mapped)))
}

/// Format a timestamp consistently for external receipt serialization and logs.
pub fn format_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::Ipv4Addr, sync::Mutex};

    use tokio::sync::Notify;

    use super::*;

    #[derive(Default)]
    struct MockVerifier {
        reject: bool,
    }

    #[async_trait]
    impl SignatureVerifier for MockVerifier {
        async fn verify(
            &self,
            _principal_id: &str,
            canonical: &[u8],
            signature: &[u8],
        ) -> Result<(), ProxyError> {
            if self.reject || signature != Sha256::digest(canonical).as_slice() {
                return Err(ProxyError::Authentication);
            }
            Ok(())
        }
    }

    struct MockResolver(Vec<IpAddr>);

    #[async_trait]
    impl Resolver for MockResolver {
        async fn resolve(&self, _hostname: &str) -> Result<Vec<IpAddr>, ProxyError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Default)]
    struct MockTransport {
        requests: Mutex<Vec<TransportRequest>>,
        block: bool,
    }

    #[async_trait]
    impl ProviderTransport for MockTransport {
        async fn send(&self, request: TransportRequest) -> Result<TransportResponse, ProxyError> {
            self.requests
                .lock()
                .map_err(|_| ProxyError::AuthorityUnavailable)?
                .push(request);
            if self.block {
                std::future::pending().await
            } else {
                Ok(TransportResponse {
                    status: 200,
                    content_type: "application/json".into(),
                    body: br#"{"ok":true}"#.to_vec(),
                })
            }
        }
    }

    #[derive(Default)]
    struct MockFence {
        claims: Mutex<HashMap<Uuid, (String, Option<Receipt>)>>,
        cancelled: Mutex<bool>,
        completed: Mutex<Vec<Receipt>>,
        notify: Notify,
    }

    impl MockFence {
        fn cancel(&self) {
            if let Ok(mut cancelled) = self.cancelled.lock() {
                *cancelled = true;
            }
            self.notify.notify_waiters();
        }
    }

    #[async_trait]
    impl RequestFence for MockFence {
        async fn claim(
            &self,
            envelope: &RequestEnvelope,
            request_sha256: &str,
        ) -> Result<ClaimOutcome, ProxyError> {
            if *self
                .cancelled
                .lock()
                .map_err(|_| ProxyError::AuthorityUnavailable)?
            {
                return Ok(ClaimOutcome::Cancelled);
            }
            let mut claims = self
                .claims
                .lock()
                .map_err(|_| ProxyError::AuthorityUnavailable)?;
            if let Some((digest, receipt)) = claims.get(&envelope.request_id) {
                if digest != request_sha256 {
                    return Ok(ClaimOutcome::Conflict);
                }
                return receipt
                    .clone()
                    .map(Box::new)
                    .map(ClaimOutcome::Duplicate)
                    .ok_or(ProxyError::AuthorityUnavailable);
            }
            claims.insert(envelope.request_id, (request_sha256.to_owned(), None));
            Ok(ClaimOutcome::Claimed)
        }

        async fn is_cancelled(
            &self,
            _tenant_id: Uuid,
            _session_id: Uuid,
            _generation: u64,
        ) -> Result<bool, ProxyError> {
            self.cancelled
                .lock()
                .map(|value| *value)
                .map_err(|_| ProxyError::AuthorityUnavailable)
        }

        async fn wait_cancelled(
            &self,
            tenant_id: Uuid,
            _session_id: Uuid,
            _generation: u64,
        ) -> Result<(), ProxyError> {
            if self.is_cancelled(tenant_id, Uuid::nil(), 0).await? {
                return Ok(());
            }
            self.notify.notified().await;
            Ok(())
        }

        async fn mark_dispatched(&self, receipt: &Receipt) -> Result<(), ProxyError> {
            self.complete(receipt).await
        }

        async fn complete(&self, receipt: &Receipt) -> Result<(), ProxyError> {
            if let Some((_, stored)) = self
                .claims
                .lock()
                .map_err(|_| ProxyError::AuthorityUnavailable)?
                .get_mut(&receipt.request_id)
            {
                *stored = Some(receipt.clone());
            }
            self.completed
                .lock()
                .map_err(|_| ProxyError::AuthorityUnavailable)?
                .push(receipt.clone());
            Ok(())
        }
    }

    fn route(provider: Provider, endpoint: &str) -> RoutePolicy {
        RoutePolicy {
            destination_id: "openai.realtime.calls.v1".into(),
            provider,
            endpoint: Url::parse(endpoint).unwrap_or_else(|error| panic!("test URL: {error}")),
            method: HttpMethod::Post,
            secret: SecretReference {
                arn: "arn:aws:secretsmanager:us-west-2:123456789012:secret:snowman-openai-abc"
                    .into(),
                json_key: "api_key".into(),
            },
            principal_ids: BTreeSet::from(["meeting-media".into()]),
            tenant_ids: BTreeSet::from([Uuid::from_u128(1)]),
            purposes: BTreeSet::from(["meeting_realtime".into()]),
            classifications: BTreeSet::from(["internal".into()]),
            request_content_types: BTreeSet::from(["application/json".into()]),
            response_content_types: BTreeSet::from(["application/json".into()]),
            max_budget_microusd: 1_000_000,
            max_request_bytes: 1024,
            max_response_bytes: 1024,
            timeout: Duration::from_secs(5),
        }
    }

    fn unsigned_request() -> SignedRequest {
        let payload = br#"{"model":"realtime"}"#.to_vec();
        SignedRequest {
            envelope: RequestEnvelope {
                schema_version: REQUEST_SCHEMA.into(),
                request_id: Uuid::from_u128(2),
                principal_id: "meeting-media".into(),
                tenant_id: Uuid::from_u128(1),
                session_id: Uuid::from_u128(3),
                generation: 1,
                provider: Provider::OpenAi,
                purpose: "meeting_realtime".into(),
                classification: "internal".into(),
                budget_microusd: 1000,
                policy_generation: 7,
                destination_id: "openai.realtime.calls.v1".into(),
                content_type: "application/json".into(),
                payload_sha256: sha256(&payload),
                issued_at: Utc::now(),
                deadline: Utc::now() + chrono::Duration::seconds(30),
            },
            payload,
            signature: Vec::new(),
        }
    }

    fn sign(mut request: SignedRequest) -> SignedRequest {
        request.signature = Sha256::digest(
            canonical_request(&request.envelope)
                .unwrap_or_else(|error| panic!("canonical request: {error}")),
        )
        .to_vec();
        request
    }

    fn fixture(
        route: RoutePolicy,
        addresses: Vec<IpAddr>,
        transport: Arc<MockTransport>,
        fence: Arc<MockFence>,
    ) -> Proxy {
        Proxy::new(
            7,
            vec![route],
            2,
            Arc::new(MockVerifier::default()),
            Arc::new(MockResolver(addresses)),
            transport,
            fence,
        )
        .unwrap_or_else(|error| panic!("proxy fixture: {error}"))
    }

    #[tokio::test]
    async fn dispatches_only_sealed_route_with_pinned_tls_identity() {
        let transport = Arc::new(MockTransport::default());
        let fence = Arc::new(MockFence::default());
        let proxy = fixture(
            route(Provider::OpenAi, "https://api.openai.com/v1/realtime/calls"),
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            transport.clone(),
            fence,
        );
        let result = proxy
            .execute(sign(unsigned_request()))
            .await
            .unwrap_or_else(|error| panic!("execute: {error}"));
        assert_eq!(result.receipt.status, ReceiptStatus::Succeeded);
        assert_eq!(result.response, Some(br#"{"ok":true}"#.to_vec()));
        let requests = transport
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].endpoint.as_str(),
            "https://api.openai.com/v1/realtime/calls"
        );
        assert_eq!(requests[0].tls_server_name, "api.openai.com");
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert_eq!(
            requests[0].resolved_ips,
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
        );
        assert!(requests[0].secret.arn.contains("snowman-openai"));
    }

    #[test]
    fn rejects_unapproved_provider_hostname_and_url_features() {
        let block_endpoint = format!("https://api.{}.xyz/v1/realtime/calls", "block");
        for endpoint in [
            block_endpoint.as_str(),
            "https://api.openai.com.evil.example/v1/realtime/calls",
            "https://user@api.openai.com/v1/realtime/calls",
            "https://api.openai.com/v1/../admin",
            "https://api.openai.com/v1/%2e%2e/admin",
            "https://api.openai.com/v1/realtime/calls?target=http://169.254.169.254",
            "http://api.openai.com/v1/realtime/calls",
        ] {
            assert_eq!(
                validate_route(&route(Provider::OpenAi, endpoint)),
                Err(ProxyError::InvalidRequest),
                "accepted {endpoint}"
            );
        }
    }

    #[test]
    fn exact_provider_hosts_are_the_only_valid_hosts() {
        assert!(validate_route(&route(
            Provider::Twilio,
            "https://api.twilio.com/2010-04-01/Calls.json"
        ))
        .is_ok());
        assert!(validate_route(&route(
            Provider::ElevenLabs,
            "https://api.elevenlabs.io/v1/text-to-speech/voice"
        ))
        .is_ok());
        assert_eq!(
            validate_route(&route(
                Provider::Twilio,
                "https://api.openai.com/v1/realtime/calls"
            )),
            Err(ProxyError::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn rejects_private_reserved_and_mixed_dns_answers() {
        let cases = vec![
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
            vec![IpAddr::V4(Ipv4Addr::new(100, 64, 1, 1))],
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
            vec!["fc00::1".parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))],
            vec![
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ],
        ];
        for addresses in cases {
            let proxy = fixture(
                route(Provider::OpenAi, "https://api.openai.com/v1/realtime/calls"),
                addresses,
                Arc::new(MockTransport::default()),
                Arc::new(MockFence::default()),
            );
            let result = proxy
                .execute(sign(unsigned_request()))
                .await
                .unwrap_or_else(|error| panic!("resolution receipt: {error}"));
            assert_eq!(result.receipt.status, ReceiptStatus::PreDispatchDenied);
        }
    }

    #[tokio::test]
    async fn authentication_and_payload_digest_fail_closed_before_transport() {
        let transport = Arc::new(MockTransport::default());
        let proxy = fixture(
            route(Provider::OpenAi, "https://api.openai.com/v1/realtime/calls"),
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            transport.clone(),
            Arc::new(MockFence::default()),
        );
        let mut unauthenticated = unsigned_request();
        unauthenticated.signature = vec![1];
        assert!(matches!(
            proxy.execute(unauthenticated).await,
            Err(ProxyError::Authentication)
        ));
        let mut request = sign(unsigned_request());
        request.payload.push(0);
        assert!(matches!(
            proxy.execute(request).await,
            Err(ProxyError::InvalidRequest)
        ));
        assert!(transport
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty());
    }

    #[tokio::test]
    async fn exact_replay_does_not_reinvoke_or_return_raw_body() {
        let transport = Arc::new(MockTransport::default());
        let fence = Arc::new(MockFence::default());
        let proxy = fixture(
            route(Provider::OpenAi, "https://api.openai.com/v1/realtime/calls"),
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            transport.clone(),
            fence,
        );
        let request = sign(unsigned_request());
        let first = proxy
            .execute(request.clone())
            .await
            .unwrap_or_else(|error| panic!("first: {error}"));
        let replay = proxy
            .execute(request)
            .await
            .unwrap_or_else(|error| panic!("replay: {error}"));
        assert!(!first.replayed);
        assert!(replay.replayed);
        assert!(replay.response.is_none());
        assert_eq!(
            transport
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn replay_id_with_different_signed_content_is_rejected() {
        let proxy = fixture(
            route(Provider::OpenAi, "https://api.openai.com/v1/realtime/calls"),
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            Arc::new(MockTransport::default()),
            Arc::new(MockFence::default()),
        );
        proxy
            .execute(sign(unsigned_request()))
            .await
            .unwrap_or_else(|error| panic!("first: {error}"));
        let mut changed = unsigned_request();
        changed.envelope.budget_microusd += 1;
        assert!(matches!(
            proxy.execute(sign(changed)).await,
            Err(ProxyError::ReplayConflict)
        ));
    }

    #[tokio::test]
    async fn cancellation_before_dispatch_never_calls_provider() {
        let transport = Arc::new(MockTransport::default());
        let fence = Arc::new(MockFence::default());
        fence.cancel();
        let proxy = fixture(
            route(Provider::OpenAi, "https://api.openai.com/v1/realtime/calls"),
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            transport.clone(),
            fence,
        );
        let result = proxy
            .execute(sign(unsigned_request()))
            .await
            .unwrap_or_else(|error| panic!("cancel: {error}"));
        assert_eq!(result.receipt.status, ReceiptStatus::Cancelled);
        assert!(transport
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty());
    }

    #[tokio::test]
    async fn cancellation_after_dispatch_is_sticky_indeterminate() {
        let transport = Arc::new(MockTransport {
            requests: Mutex::default(),
            block: true,
        });
        let fence = Arc::new(MockFence::default());
        let proxy = Arc::new(fixture(
            route(Provider::OpenAi, "https://api.openai.com/v1/realtime/calls"),
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            transport.clone(),
            fence.clone(),
        ));
        let task = tokio::spawn({
            let proxy = proxy.clone();
            async move { proxy.execute(sign(unsigned_request())).await }
        });
        while transport
            .requests
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
        fence.cancel();
        let result = task
            .await
            .unwrap_or_else(|error| panic!("join: {error}"))
            .unwrap_or_else(|error| panic!("execute: {error}"));
        assert_eq!(result.receipt.status, ReceiptStatus::Indeterminate);
        assert!(result.response.is_none());
    }

    #[tokio::test]
    async fn policy_fields_are_all_enforced() {
        let base_route = route(Provider::OpenAi, "https://api.openai.com/v1/realtime/calls");
        for mutation in 0..8 {
            let transport = Arc::new(MockTransport::default());
            let proxy = fixture(
                base_route.clone(),
                vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
                transport.clone(),
                Arc::new(MockFence::default()),
            );
            let mut request = unsigned_request();
            match mutation {
                0 => request.envelope.tenant_id = Uuid::from_u128(99),
                1 => request.envelope.provider = Provider::Twilio,
                2 => request.envelope.purpose = "other".into(),
                3 => request.envelope.classification = "restricted".into(),
                4 => request.envelope.budget_microusd = 1_000_001,
                5 => request.envelope.policy_generation = 8,
                6 => request.envelope.destination_id = "other.route".into(),
                _ => request.envelope.content_type = "audio/raw".into(),
            }
            let result = proxy.execute(sign(request)).await;
            assert!(matches!(
                result,
                Err(ProxyError::InvalidRequest | ProxyError::PolicyDenied)
            ));
            assert!(transport
                .requests
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty());
        }
    }

    #[tokio::test]
    async fn redirects_and_oversized_responses_are_never_exposed() {
        struct BadTransport(u16, usize);
        #[async_trait]
        impl ProviderTransport for BadTransport {
            async fn send(
                &self,
                _request: TransportRequest,
            ) -> Result<TransportResponse, ProxyError> {
                Ok(TransportResponse {
                    status: self.0,
                    content_type: "application/json".into(),
                    body: vec![0; self.1],
                })
            }
        }
        for (status, size) in [(302, 0), (200, 1025)] {
            let proxy = Proxy::new(
                7,
                vec![route(
                    Provider::OpenAi,
                    "https://api.openai.com/v1/realtime/calls",
                )],
                1,
                Arc::new(MockVerifier::default()),
                Arc::new(MockResolver(vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])),
                Arc::new(BadTransport(status, size)),
                Arc::new(MockFence::default()),
            )
            .unwrap_or_else(|error| panic!("proxy: {error}"));
            let result = proxy
                .execute(sign(unsigned_request()))
                .await
                .unwrap_or_else(|error| panic!("transport receipt: {error}"));
            assert_eq!(result.receipt.status, ReceiptStatus::Indeterminate);
            assert!(result.response.is_none());
        }
    }

    #[tokio::test]
    async fn receipt_is_content_free_and_provider_errors_discard_body() {
        struct Rejected;
        #[async_trait]
        impl ProviderTransport for Rejected {
            async fn send(
                &self,
                _request: TransportRequest,
            ) -> Result<TransportResponse, ProxyError> {
                Ok(TransportResponse {
                    status: 400,
                    content_type: "application/json".into(),
                    body: b"sensitive provider error".to_vec(),
                })
            }
        }
        let fence = Arc::new(MockFence::default());
        let proxy = Proxy::new(
            7,
            vec![route(
                Provider::OpenAi,
                "https://api.openai.com/v1/realtime/calls",
            )],
            1,
            Arc::new(MockVerifier::default()),
            Arc::new(MockResolver(vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))])),
            Arc::new(Rejected),
            fence.clone(),
        )
        .unwrap_or_else(|error| panic!("proxy: {error}"));
        let result = proxy
            .execute(sign(unsigned_request()))
            .await
            .unwrap_or_else(|error| panic!("execute: {error}"));
        assert_eq!(result.receipt.status, ReceiptStatus::ProviderRejected);
        assert_eq!(result.receipt.response_bytes, 0);
        assert!(result.response.is_none());
        let json = serde_json::to_string(&result.receipt)
            .unwrap_or_else(|error| panic!("receipt JSON: {error}"));
        assert!(!json.contains("sensitive"));
        assert!(!json.contains("api.openai.com"));
        assert!(!json.contains("secretsmanager"));
    }
}
