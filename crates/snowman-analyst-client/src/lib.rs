#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Narrow, evidence-preserving command boundary from the Snowman Command Center
//! to Analyst 360.
//!
//! The client accepts only the v1 minimized command contract, signs each exact
//! request with a tenant-bound asymmetric AWS KMS key, refuses redirects and
//! ambient proxies, and accepts responses only when their digests and
//! tenant/client/project coordinates match the request. It never receives a
//! database credential or an object-store location.

use std::time::Duration;

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{header, redirect::Policy, Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

const COMMAND_PATH: &str = "/api/v1/snowman-command-center/commands";
const STATUS_PATH: &str = "/api/v1/snowman-command-center/status";
const CONTRACT_VERSION: &str = "snowman.command-center.v1";
const ASSERTION_VERSION: &str = "snowman.service-request.v1";
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_INSTRUCTION_BYTES: usize = 4_000;

/// Errors are intentionally bounded and contain no response body, prompt, or
/// client content so they are safe for centralized operational logs.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Static client configuration violates the Snowman trust boundary.
    #[error("Analyst command client configuration is invalid: {0}")]
    InvalidConfiguration(&'static str),
    /// The proposed command violates the minimized contract.
    #[error("Analyst command is invalid: {0}")]
    InvalidCommand(&'static str),
    /// AWS KMS could not sign the exact request assertion.
    #[error("Analyst command assertion signing failed")]
    Signing,
    /// The private Analyst service could not be reached.
    #[error("Analyst command transport failed")]
    Transport,
    /// Analyst rejected the command with a bounded HTTP status.
    #[error("Analyst command was rejected with HTTP {0}")]
    Rejected(u16),
    /// Analyst returned an oversized or non-contract response.
    #[error("Analyst command response is invalid: {0}")]
    InvalidResponse(&'static str),
}

/// Exact Analyst capability that a governed specialist may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    /// Run a governed, evidence-producing analysis.
    #[serde(rename = "analytics.query")]
    AnalyticsQuery,
    /// Build a governed work product from authorized references.
    #[serde(rename = "artifact.build")]
    ArtifactBuild,
    /// Resolve a minimized context packet under Analyst authorization.
    #[serde(rename = "context.read")]
    ContextRead,
    /// Read a metadata-only evidence manifest.
    #[serde(rename = "evidence.manifest.read")]
    EvidenceManifestRead,
    /// Propose a governed recommendation.
    #[serde(rename = "recommendation.propose")]
    RecommendationPropose,
    /// Request a governed recommendation lifecycle transition.
    #[serde(rename = "recommendation.transition")]
    RecommendationTransition,
}

/// Data classification retained across the service boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Snowman internal information.
    Internal,
    /// Client-confidential information.
    Confidential,
    /// Highly restricted information.
    Restricted,
}

/// Immutable, re-authorized Analyst artifact coordinate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    /// Analyst artifact identifier.
    pub artifact_id: String,
    /// Machine-readable artifact type.
    pub artifact_type: String,
    /// Always `analyst360`.
    pub authority: String,
    /// Artifact classification.
    pub classification: Classification,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// Lowercase SHA-256 digest.
    pub sha256: String,
    /// Immutable artifact version.
    pub version_id: String,
}

/// Inputs supplied by a leased specialist worker. Scope fields and actor
/// identity are injected from immutable client configuration.
#[derive(Debug, Clone)]
pub struct Command {
    /// Stable command identifier.
    pub command_id: String,
    /// Cross-service correlation identifier.
    pub correlation_id: String,
    /// Stable retry key for exactly-once logical acceptance.
    pub idempotency_key: String,
    /// Capability requested from Analyst 360.
    pub capability: Capability,
    /// Exact evaluated Snowman model identifier selected for this specialist.
    /// The command deliberately carries no gateway or provider endpoint.
    pub model_id: String,
    /// Bounded instruction; never raw rows, transcripts, or model output.
    pub instruction: String,
    /// Authorized immutable Analyst references.
    pub input_refs: Vec<ArtifactReference>,
    /// Snowman workforce identity on whose behalf the service dispatches.
    pub delegated_agent_id: Option<String>,
    /// Command classification.
    pub classification: Classification,
    /// Stable request-derived submission time. It must not change across lease
    /// recovery, otherwise an idempotent retry would become a different command.
    pub submitted_at: DateTime<Utc>,
    /// Command expiry.
    pub expires_at: DateTime<Utc>,
}

/// Tenant-bound client settings. The endpoint must be an exact HTTPS
/// `snowmanai.org` authority; redirects and system proxy variables are ignored.
#[derive(Debug, Clone)]
pub struct Config {
    /// Private Analyst 360 origin, without path/query/fragment.
    pub endpoint: Url,
    /// Analyst-bound Snowman service principal.
    pub service_principal: String,
    /// Asymmetric signing key ARN bound to that principal.
    pub signing_key_arn: String,
    /// Analyst tenant identifier.
    pub tenant_id: String,
    /// Analyst client identifier; v1 requires it to equal `tenant_id`.
    pub client_id: String,
    /// Analyst project identifier.
    pub project_id: String,
    /// Hard request timeout.
    pub timeout: Duration,
}

/// Validated acceptance returned by Analyst 360.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedCommand {
    /// Analyst job identifier.
    pub job_id: String,
    /// Digest-bound command receipt.
    pub receipt: CommandReceipt,
    /// Initial digest-bound lifecycle event.
    pub status_event: JobStatusEvent,
    /// Whether this was an exact idempotent replay.
    pub idempotent_replay: bool,
}

/// Digest-bound Analyst command receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandReceipt {
    /// Contract version.
    pub schema_version: String,
    /// Receipt identifier.
    pub receipt_id: String,
    /// Command identifier.
    pub command_id: String,
    /// Correlation identifier.
    pub correlation_id: String,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Client identifier.
    pub client_id: String,
    /// Project identifier.
    pub project_id: String,
    /// RFC 3339 persistence time.
    pub recorded_at: String,
    /// Whether Analyst accepted the command.
    pub accepted: bool,
    /// Optional bounded rejection code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_code: Option<String>,
    /// Exact command digest.
    pub request_sha256: String,
    /// Canonical receipt digest.
    pub receipt_sha256: String,
}

/// Initial or current Analyst lifecycle event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStatusEvent {
    /// Contract version.
    pub schema_version: String,
    /// Event identifier.
    pub event_id: String,
    /// Command identifier.
    pub command_id: String,
    /// Correlation identifier.
    pub correlation_id: String,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Client identifier.
    pub client_id: String,
    /// Project identifier.
    pub project_id: String,
    /// RFC 3339 occurrence time.
    pub occurred_at: String,
    /// Monotonic lifecycle sequence.
    pub sequence: i64,
    /// Bounded lifecycle state.
    pub status: String,
    /// Optional bounded failure code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    /// Immutable Analyst output references.
    pub output_refs: Vec<ArtifactReference>,
    /// Canonical event digest.
    pub event_sha256: String,
}

#[derive(Debug, Serialize)]
struct Actor<'a> {
    subject_id: &'a str,
    actor_type: &'static str,
}

#[derive(Debug, Serialize)]
struct UnsignedCommandRequest<'a> {
    schema_version: &'static str,
    command_id: &'a str,
    correlation_id: &'a str,
    idempotency_key: &'a str,
    tenant_id: &'a str,
    client_id: &'a str,
    project_id: &'a str,
    submitted_at: String,
    expires_at: String,
    classification: Classification,
    actor: Actor<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegated_agent_id: Option<&'a str>,
    capability: Capability,
    model_id: &'a str,
    instruction: &'a str,
    input_refs: &'a [ArtifactReference],
}

#[derive(Debug, Serialize)]
struct ServiceAssertion<'a> {
    body_sha256: &'a str,
    key_id: &'a str,
    method: &'a str,
    nonce: &'a str,
    operation: &'a str,
    principal_id: &'a str,
    request_target: &'a str,
    signed_at: &'a str,
    version: &'static str,
}

/// Private Analyst command client.
pub struct AnalystClient {
    config: Config,
    http: Client,
    kms: aws_sdk_kms::Client,
}

impl AnalystClient {
    /// Load the AWS workload identity and construct a fail-closed client.
    pub async fn new(config: Config) -> Result<Self, Error> {
        validate_config(&config)?;
        let http = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .no_proxy()
            .https_only(true)
            .build()
            .map_err(|_| Error::InvalidConfiguration("HTTP client could not be built"))?;
        let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Ok(Self {
            config,
            http,
            kms: aws_sdk_kms::Client::new(&sdk),
        })
    }

    /// Submit one exact minimized command and verify its acceptance evidence.
    pub async fn submit(&self, command: &Command) -> Result<AcceptedCommand, Error> {
        validate_command(command, Utc::now())?;
        let request = build_command_request(&self.config, command)?;
        let body = canonical_json_bytes(&request)?;
        let body_sha256 = sha256_hex(&body);
        let assertion = self
            .sign_assertion("POST", "commands.submit", COMMAND_PATH, &body_sha256)
            .await?;
        let url = self
            .config
            .endpoint
            .join(COMMAND_PATH)
            .map_err(|_| Error::InvalidConfiguration("command URL could not be built"))?;
        let response = self
            .http
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header("X-Snowman-Assertion-Version", ASSERTION_VERSION)
            .header(
                "X-Snowman-Service-Principal",
                &self.config.service_principal,
            )
            .header("X-Snowman-Key-Id", &self.config.signing_key_arn)
            .header("X-Snowman-Nonce", assertion.nonce)
            .header("X-Snowman-Signed-At", assertion.signed_at)
            .header("X-Snowman-Signature", assertion.signature)
            .body(body)
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        if response.status() != StatusCode::ACCEPTED {
            return Err(Error::Rejected(response.status().as_u16()));
        }
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or("");
        if content_type != "application/json" {
            return Err(Error::InvalidResponse(
                "content type is not application/json",
            ));
        }
        let bytes = read_bounded(response).await?;
        let accepted: AcceptedCommand = serde_json::from_slice(&bytes)
            .map_err(|_| Error::InvalidResponse("response JSON violates the contract"))?;
        validate_acceptance(&accepted, &request, &self.config)?;
        Ok(accepted)
    }

    /// Read the current minimized lifecycle event for an accepted Analyst job.
    /// The query string is included in the one-time KMS assertion, preventing a
    /// valid signature for one job from being replayed against another.
    pub async fn read_status(
        &self,
        job_id: &str,
        expected_command_id: &str,
        expected_correlation_id: &str,
    ) -> Result<JobStatusEvent, Error> {
        if !valid_job_id(job_id)
            || !valid_identifier(expected_command_id)
            || !valid_identifier(expected_correlation_id)
        {
            return Err(Error::InvalidCommand("status identifiers are invalid"));
        }
        let request_target = format!("{STATUS_PATH}?job_id={job_id}");
        let empty_sha256 = sha256_hex(&[]);
        let assertion = self
            .sign_assertion("GET", "status.read", &request_target, &empty_sha256)
            .await?;
        let mut url = self
            .config
            .endpoint
            .join(STATUS_PATH)
            .map_err(|_| Error::InvalidConfiguration("status URL could not be built"))?;
        url.query_pairs_mut().append_pair("job_id", job_id);
        let response = self
            .http
            .get(url)
            .header(header::ACCEPT, "application/json")
            .header("X-Snowman-Assertion-Version", ASSERTION_VERSION)
            .header(
                "X-Snowman-Service-Principal",
                &self.config.service_principal,
            )
            .header("X-Snowman-Key-Id", &self.config.signing_key_arn)
            .header("X-Snowman-Nonce", assertion.nonce)
            .header("X-Snowman-Signed-At", assertion.signed_at)
            .header("X-Snowman-Signature", assertion.signature)
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        if response.status() != StatusCode::OK {
            return Err(Error::Rejected(response.status().as_u16()));
        }
        require_json_content_type(&response)?;
        let bytes = read_bounded(response).await?;
        let event: JobStatusEvent = serde_json::from_slice(&bytes)
            .map_err(|_| Error::InvalidResponse("status JSON violates the contract"))?;
        validate_status_event(
            &event,
            expected_command_id,
            expected_correlation_id,
            &self.config,
        )?;
        Ok(event)
    }

    async fn sign_assertion(
        &self,
        method: &str,
        operation: &str,
        request_target: &str,
        body_sha256: &str,
    ) -> Result<SignedAssertion, Error> {
        let signed_at = rfc3339(Utc::now());
        let nonce = Uuid::new_v4().to_string();
        let assertion = ServiceAssertion {
            body_sha256,
            key_id: &self.config.signing_key_arn,
            method,
            nonce: &nonce,
            operation,
            principal_id: &self.config.service_principal,
            request_target,
            signed_at: &signed_at,
            version: ASSERTION_VERSION,
        };
        let assertion_bytes = canonical_json_bytes(&assertion)?;
        let signature = self
            .kms
            .sign()
            .key_id(&self.config.signing_key_arn)
            .message(Blob::new(assertion_bytes))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPssSha256)
            .send()
            .await
            .map_err(|_| Error::Signing)?
            .signature
            .ok_or(Error::Signing)?;
        if !(128..=1024).contains(&signature.as_ref().len()) {
            return Err(Error::Signing);
        }
        Ok(SignedAssertion {
            nonce,
            signed_at,
            signature: STANDARD.encode(signature.as_ref()),
        })
    }
}

struct SignedAssertion {
    nonce: String,
    signed_at: String,
    signature: String,
}

fn build_command_request(config: &Config, command: &Command) -> Result<Value, Error> {
    let unsigned = UnsignedCommandRequest {
        schema_version: CONTRACT_VERSION,
        command_id: &command.command_id,
        correlation_id: &command.correlation_id,
        idempotency_key: &command.idempotency_key,
        tenant_id: &config.tenant_id,
        client_id: &config.client_id,
        project_id: &config.project_id,
        submitted_at: rfc3339(command.submitted_at),
        expires_at: rfc3339(command.expires_at),
        classification: command.classification,
        actor: Actor {
            subject_id: &config.service_principal,
            actor_type: "service",
        },
        delegated_agent_id: command.delegated_agent_id.as_deref(),
        capability: command.capability,
        model_id: &command.model_id,
        instruction: &command.instruction,
        input_refs: &command.input_refs,
    };
    let mut value = serde_json::to_value(unsigned)
        .map_err(|_| Error::InvalidCommand("request could not be serialized"))?;
    let request_sha256 = canonical_sha256(&value)?;
    value
        .as_object_mut()
        .ok_or(Error::InvalidCommand("request is not an object"))?
        .insert("request_sha256".to_string(), Value::String(request_sha256));
    Ok(value)
}

fn validate_config(config: &Config) -> Result<(), Error> {
    let host = config.endpoint.host_str().unwrap_or("");
    if config.endpoint.scheme() != "https"
        || !(host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
        || config.endpoint.username() != ""
        || config.endpoint.password().is_some()
        || config.endpoint.query().is_some()
        || config.endpoint.fragment().is_some()
        || !matches!(config.endpoint.path(), "" | "/")
        || !matches!(config.endpoint.port(), None | Some(443))
    {
        return Err(Error::InvalidConfiguration(
            "endpoint must be an exact HTTPS snowmanai.org origin on port 443",
        ));
    }
    if !valid_identifier(&config.service_principal)
        || !valid_identifier(&config.tenant_id)
        || config.client_id != config.tenant_id
        || !valid_identifier(&config.project_id)
    {
        return Err(Error::InvalidConfiguration(
            "principal and tenant scope are invalid or inconsistent",
        ));
    }
    if !valid_kms_key_arn(&config.signing_key_arn) {
        return Err(Error::InvalidConfiguration(
            "signing key must be an asymmetric AWS KMS key ARN",
        ));
    }
    if config.timeout.is_zero() || config.timeout > Duration::from_secs(60) {
        return Err(Error::InvalidConfiguration(
            "timeout must be between one millisecond and 60 seconds",
        ));
    }
    Ok(())
}

fn validate_command(command: &Command, now: DateTime<Utc>) -> Result<(), Error> {
    if !valid_identifier(&command.command_id)
        || !valid_identifier(&command.correlation_id)
        || !valid_identifier(&command.idempotency_key)
        || command
            .delegated_agent_id
            .as_deref()
            .is_some_and(|value| !valid_identifier(value))
    {
        return Err(Error::InvalidCommand("identifiers are invalid"));
    }
    if command.model_id.is_empty()
        || command.model_id.len() > 256
        || command.model_id.contains("://")
        || command.model_id.chars().any(char::is_control)
    {
        return Err(Error::InvalidCommand("model identifier is invalid"));
    }
    if command.instruction.is_empty() || command.instruction.len() > MAX_INSTRUCTION_BYTES {
        return Err(Error::InvalidCommand("instruction is empty or oversized"));
    }
    if command.input_refs.len() > 50
        || command.expires_at <= command.submitted_at
        || command.expires_at <= now
    {
        return Err(Error::InvalidCommand(
            "references exceed the limit or command is expired",
        ));
    }
    for reference in &command.input_refs {
        if !valid_artifact_reference(reference) {
            return Err(Error::InvalidCommand("artifact reference is invalid"));
        }
    }
    Ok(())
}

fn validate_acceptance(
    accepted: &AcceptedCommand,
    request: &Value,
    config: &Config,
) -> Result<(), Error> {
    let request_sha256 = request
        .get("request_sha256")
        .and_then(Value::as_str)
        .ok_or(Error::InvalidResponse("request digest is absent"))?;
    let command_id = request
        .get("command_id")
        .and_then(Value::as_str)
        .ok_or(Error::InvalidResponse("command identifier is absent"))?;
    let correlation_id = request
        .get("correlation_id")
        .and_then(Value::as_str)
        .ok_or(Error::InvalidResponse("correlation identifier is absent"))?;
    if !accepted.job_id.starts_with("cc_job_")
        || accepted.job_id.len() != 47
        || accepted.receipt.schema_version != CONTRACT_VERSION
        || !accepted.receipt.accepted
        || accepted.receipt.rejection_code.is_some()
        || accepted.receipt.command_id != command_id
        || accepted.receipt.correlation_id != correlation_id
        || accepted.receipt.tenant_id != config.tenant_id
        || accepted.receipt.client_id != config.client_id
        || accepted.receipt.project_id != config.project_id
        || accepted.receipt.request_sha256 != request_sha256
        || DateTime::parse_from_rfc3339(&accepted.receipt.recorded_at).is_err()
    {
        return Err(Error::InvalidResponse(
            "receipt scope or identity does not match",
        ));
    }
    let mut receipt = serde_json::to_value(&accepted.receipt)
        .map_err(|_| Error::InvalidResponse("receipt could not be serialized"))?;
    let claimed = take_digest(&mut receipt, "receipt_sha256")?;
    if canonical_sha256(&receipt)? != claimed {
        return Err(Error::InvalidResponse("receipt digest does not match"));
    }
    validate_status_event(&accepted.status_event, command_id, correlation_id, config)
}

fn validate_status_event(
    event: &JobStatusEvent,
    command_id: &str,
    correlation_id: &str,
    config: &Config,
) -> Result<(), Error> {
    const STATUSES: &[&str] = &[
        "accepted",
        "queued",
        "running",
        "awaiting_approval",
        "succeeded",
        "failed",
        "cancelled",
        "expired",
    ];
    if event.schema_version != CONTRACT_VERSION
        || event.command_id != command_id
        || event.correlation_id != correlation_id
        || event.tenant_id != config.tenant_id
        || event.client_id != config.client_id
        || event.project_id != config.project_id
        || event.sequence < 0
        || !STATUSES.contains(&event.status.as_str())
        || DateTime::parse_from_rfc3339(&event.occurred_at).is_err()
        || event.output_refs.len() > 50
        || event
            .output_refs
            .iter()
            .any(|reference| !valid_artifact_reference(reference))
    {
        return Err(Error::InvalidResponse(
            "status event scope or lifecycle is invalid",
        ));
    }
    let mut value = serde_json::to_value(event)
        .map_err(|_| Error::InvalidResponse("status event could not be serialized"))?;
    let claimed = take_digest(&mut value, "event_sha256")?;
    if canonical_sha256(&value)? != claimed {
        return Err(Error::InvalidResponse("status event digest does not match"));
    }
    Ok(())
}

async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Transport)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(Error::InvalidResponse("response exceeds 256 KiB"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn require_json_content_type(response: &reqwest::Response) -> Result<(), Error> {
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .unwrap_or("");
    if content_type != "application/json" {
        return Err(Error::InvalidResponse(
            "content type is not application/json",
        ));
    }
    Ok(())
}

fn take_digest(value: &mut Value, field: &str) -> Result<String, Error> {
    value
        .as_object_mut()
        .and_then(|object| object.remove(field))
        .and_then(|digest| digest.as_str().map(str::to_string))
        .filter(|digest| is_sha256(digest))
        .ok_or(Error::InvalidResponse("digest is absent or malformed"))
}

fn canonical_json_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|_| Error::InvalidCommand("canonical JSON failed"))
}

fn canonical_sha256<T: Serialize + ?Sized>(value: &T) -> Result<String, Error> {
    Ok(sha256_hex(&canonical_json_bytes(value)?))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn valid_identifier(value: &str) -> bool {
    (3..=200).contains(&value.len())
        && value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_alphanumeric()
                || (index > 0 && matches!(character, '.' | '_' | ':' | '/' | '-'))
        })
}

fn valid_kms_key_arn(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 6
        && parts[0] == "arn"
        && parts[1].starts_with("aws")
        && parts[2] == "kms"
        && !parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].chars().all(|character| character.is_ascii_digit())
        && parts[5].starts_with("key/")
        && Uuid::parse_str(&parts[5][4..]).is_ok()
}

fn valid_job_id(value: &str) -> bool {
    value.len() == 47
        && value.starts_with("cc_job_")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_artifact_reference(reference: &ArtifactReference) -> bool {
    reference.authority == "analyst360"
        && is_sha256(&reference.sha256)
        && valid_identifier(&reference.artifact_id)
        && !reference.artifact_type.is_empty()
        && reference.artifact_type.len() <= 300
        && !reference.version_id.is_empty()
        && reference.version_id.len() <= 300
        && DateTime::parse_from_rfc3339(&reference.created_at).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            endpoint: Url::parse("https://analyst360.internal.snowmanai.org").unwrap(),
            service_principal: "snowman-command-gateway".to_string(),
            signing_key_arn:
                "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc"
                    .to_string(),
            tenant_id: "aptive".to_string(),
            client_id: "aptive".to_string(),
            project_id: "governed-intelligence".to_string(),
            timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn refuses_non_snowman_and_credentialed_origins() {
        let mut cfg = config();
        cfg.endpoint = Url::parse("https://api.openai.com").unwrap();
        assert!(matches!(
            validate_config(&cfg),
            Err(Error::InvalidConfiguration(_))
        ));
        cfg.endpoint = Url::parse("https://user:password@analyst360.snowmanai.org").unwrap();
        assert!(matches!(
            validate_config(&cfg),
            Err(Error::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn assertion_canonical_form_matches_analyst_contract() {
        let assertion = ServiceAssertion {
            body_sha256: &"a".repeat(64),
            key_id: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc",
            method: "POST",
            nonce: "abcdefghijklmnopqrstuvwxyz123456",
            operation: "commands.submit",
            principal_id: "snowman-command-gateway",
            request_target: COMMAND_PATH,
            signed_at: "2026-07-26T18:00:00.000Z",
            version: ASSERTION_VERSION,
        };
        let encoded = String::from_utf8(canonical_json_bytes(&assertion).unwrap()).unwrap();
        assert_eq!(encoded, concat!(
            "{\"body_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
            "\"key_id\":\"arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc\",",
            "\"method\":\"POST\",\"nonce\":\"abcdefghijklmnopqrstuvwxyz123456\",",
            "\"operation\":\"commands.submit\",\"principal_id\":\"snowman-command-gateway\",",
            "\"request_target\":\"/api/v1/snowman-command-center/commands\",",
            "\"signed_at\":\"2026-07-26T18:00:00.000Z\",\"version\":\"snowman.service-request.v1\"}"
        ));
    }

    #[test]
    fn status_assertion_binds_the_exact_job_query() {
        let request_target = concat!(
            "/api/v1/snowman-command-center/status?job_id=cc_job_",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        let assertion = ServiceAssertion {
            body_sha256: &sha256_hex(&[]),
            key_id: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789abc",
            method: "GET",
            nonce: "abcdefghijklmnopqrstuvwxyz123456",
            operation: "status.read",
            principal_id: "snowman-command-gateway",
            request_target,
            signed_at: "2026-07-26T18:00:00.000Z",
            version: ASSERTION_VERSION,
        };
        let encoded = String::from_utf8(canonical_json_bytes(&assertion).unwrap()).unwrap();
        assert!(encoded.contains(&format!("\"request_target\":\"{request_target}\"")));
        assert!(encoded.contains("\"operation\":\"status.read\""));
        assert!(valid_job_id(&format!("cc_job_{}", "a".repeat(40))));
        assert!(!valid_job_id(&format!("cc_job_{}", "A".repeat(40))));
    }

    #[test]
    fn request_is_scoped_to_service_and_delegated_agent() {
        let client_config = config();
        let command = Command {
            command_id: "command-123".to_string(),
            correlation_id: "request-123".to_string(),
            idempotency_key: "task-123-generation-1".to_string(),
            capability: Capability::ArtifactBuild,
            model_id: "snowman-artifact-best".to_string(),
            instruction: "Build the authorized client-ready work product.".to_string(),
            input_refs: Vec::new(),
            delegated_agent_id: Some("agent-artifact-builder".to_string()),
            classification: Classification::Confidential,
            submitted_at: "2026-07-26T18:00:00Z".parse().unwrap(),
            expires_at: "2026-07-26T19:00:00Z".parse().unwrap(),
        };
        let value = build_command_request(&client_config, &command).unwrap();
        assert_eq!(value["tenant_id"], "aptive");
        assert_eq!(value["actor"]["subject_id"], "snowman-command-gateway");
        assert_eq!(value["actor"]["actor_type"], "service");
        assert_eq!(value["delegated_agent_id"], "agent-artifact-builder");
        let mut unsigned = value.clone();
        let claimed = unsigned
            .as_object_mut()
            .unwrap()
            .remove("request_sha256")
            .unwrap();
        assert_eq!(
            canonical_sha256(&unsigned).unwrap(),
            claimed.as_str().unwrap()
        );
    }

    #[test]
    fn rejects_empty_instructions() {
        let command = Command {
            command_id: "command-123".into(),
            correlation_id: "request-123".into(),
            idempotency_key: "task-123-generation-1".into(),
            capability: Capability::AnalyticsQuery,
            model_id: "snowman-analytics-best".to_string(),
            instruction: String::new(),
            input_refs: Vec::new(),
            delegated_agent_id: None,
            classification: Classification::Restricted,
            submitted_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        assert!(matches!(
            validate_command(&command, Utc::now()),
            Err(Error::InvalidCommand(_))
        ));
    }
}
