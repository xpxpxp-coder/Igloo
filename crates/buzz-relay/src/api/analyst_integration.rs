//! Private Analyst 360 lifecycle-event ingress.
//!
//! Requests and receipts use separate asymmetric AWS KMS keys. The relay
//! derives community scope from the Snowman host, validates a strict minimized
//! contract, consumes a one-time assertion, persists the event idempotently,
//! and only then signs a digest-bound receipt.

use std::collections::BTreeMap;
use std::sync::Arc;

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use buzz_auth::LimitType;
use buzz_db::analyst_integration::{
    AnalystEventAcceptance, AnalystIntegrationBinding, AnalystRequestNonce, NewAnalystEvent,
    StoredAnalystReceipt,
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

use crate::state::AppState;

use super::{api_error, internal_error};

const PATH: &str = "/internal/snowman/v1/analyst-events";
const ASSERTION_VERSION: &str = "snowman.service-request.v1";
const CONTRACT_VERSION: &str = "snowman.command-center.v1";
const OPERATION: &str = "events.ingest";
const MAX_ASSERTION_AGE_SECONDS: i64 = 90;
const MAX_FUTURE_SKEW_SECONDS: i64 = 30;
const RECEIPT_SIGNATURE_VERSION: &str = "snowman.event-delivery-receipt-signature.v1";
const MAX_OUTPUT_REFS: usize = 50;

static KMS_CLIENT: OnceCell<aws_sdk_kms::Client> = OnceCell::const_new();

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AnalystStatusEvent {
    schema_version: String,
    event_id: String,
    command_id: String,
    correlation_id: String,
    tenant_id: String,
    client_id: String,
    project_id: String,
    occurred_at: String,
    sequence: i64,
    status: String,
    #[serde(default)]
    failure_code: Option<String>,
    output_refs: Vec<ArtifactReference>,
    event_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactReference {
    artifact_id: String,
    artifact_type: String,
    authority: String,
    classification: String,
    created_at: String,
    sha256: String,
    version_id: String,
}

#[derive(Debug)]
struct ServiceAssertion {
    principal_id: String,
    key_id: String,
    nonce: String,
    signed_at: DateTime<Utc>,
    signature: Vec<u8>,
    body_sha256: [u8; 32],
}

#[derive(Serialize)]
struct CanonicalAssertion<'a> {
    body_sha256: String,
    key_id: &'a str,
    method: &'static str,
    nonce: &'a str,
    operation: &'static str,
    principal_id: &'a str,
    request_target: &'static str,
    signed_at: String,
    version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct DeliveryReceipt {
    schema_version: &'static str,
    receipt_id: String,
    event_id: String,
    receiver_service_id: String,
    receiver_key_id: String,
    receiver_signature: String,
    received_at: String,
    payload_sha256: String,
    receipt_sha256: String,
}

#[derive(Serialize)]
struct ReceiptSignatureMessage<'a> {
    receipt_sha256: &'a str,
    version: &'static str,
}

/// Receive one exact, minimized Analyst 360 lifecycle event.
pub async fn receive_analyst_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    if !state.config.snowman_analyst_event_api_enabled {
        return Err(api_error(StatusCode::NOT_FOUND, "not found"));
    }
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "not found"))?;
    let binding = state
        .db
        .analyst_integration_binding(tenant.community())
        .await
        .map_err(|_| internal_error("Analyst integration binding lookup failed"))?
        .ok_or_else(|| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Analyst integration is not active for this workspace",
            )
        })?;
    let event: AnalystStatusEvent = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid Analyst event JSON"))?;
    let (event_value, event_sha256, payload_sha256) = validate_event(&event, &binding)?;
    let assertion = parse_assertion(&headers, payload_sha256)?;
    if assertion.principal_id != binding.analyst_service_id
        || assertion.key_id != binding.request_kms_key_arn
    {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "Analyst service assertion is not bound to this workspace",
        ));
    }
    validate_assertion_freshness(assertion.signed_at, Utc::now())?;
    enforce_service_admission(&state, &tenant, &assertion).await?;
    verify_kms_signature(&assertion).await.map_err(|error| {
        tracing::warn!(%error, "Analyst KMS request verification failed");
        api_error(
            StatusCode::UNAUTHORIZED,
            "Analyst service assertion is invalid",
        )
    })?;

    let request = AnalystRequestNonce {
        analyst_service_id: assertion.principal_id.clone(),
        nonce: assertion.nonce,
        request_target_sha256: Sha256::digest(PATH.as_bytes()).into(),
        body_sha256: assertion.body_sha256,
        used_at: Utc::now(),
    };
    let new_event = NewAnalystEvent {
        event_id: event.event_id.clone(),
        command_id: event.command_id.clone(),
        correlation_id: event.correlation_id.clone(),
        tenant_id: event.tenant_id.clone(),
        client_id: event.client_id.clone(),
        project_id: event.project_id.clone(),
        occurred_at: event
            .occurred_at
            .parse()
            .map_err(|_| unprocessable("Analyst event timestamp is invalid"))?,
        sequence: event.sequence,
        status: event.status.clone(),
        payload: event_value,
        event_sha256,
        payload_sha256,
    };
    let acceptance = state
        .db
        .accept_analyst_event(tenant.community(), &request, &new_event)
        .await
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("nonce was already used") {
                api_error(
                    StatusCode::CONFLICT,
                    "Analyst service assertion was already used",
                )
            } else if message.contains("reused with different content") {
                api_error(StatusCode::CONFLICT, "Analyst event identifier conflicts")
            } else {
                tracing::error!(%error, "Analyst event persistence failed");
                internal_error("Analyst event persistence failed")
            }
        })?;
    let stored = match acceptance {
        AnalystEventAcceptance::Complete(receipt) => receipt,
        AnalystEventAcceptance::Pending => {
            let signed_at = Utc::now();
            let unsigned = unsigned_receipt(&event, &binding, payload_sha256, signed_at);
            let receipt_sha256: [u8; 32] = Sha256::digest(canonical_json_bytes(&unsigned)).into();
            let signature = sign_receipt(&binding.receipt_kms_key_arn, &receipt_sha256)
                .await
                .map_err(|error| {
                    tracing::error!(%error, "Analyst event receipt signing failed");
                    api_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Analyst event is durable but receipt signing is temporarily unavailable",
                    )
                })?;
            let receipt_id = receipt_id(&event.event_id);
            state
                .db
                .complete_analyst_receipt(
                    tenant.community(),
                    &event.event_id,
                    &StoredAnalystReceipt {
                        receipt_id,
                        receipt_sha256,
                        receipt_signature: signature,
                        receipt_signed_at: signed_at,
                    },
                )
                .await
                .map_err(|_| internal_error("Analyst event receipt persistence failed"))?
        }
    };
    let receipt = render_receipt(&event, &binding, payload_sha256, &stored);
    metrics::counter!("snowman_analyst_events_total", "status" => event.status).increment(1);
    Ok((
        StatusCode::OK,
        Json(
            serde_json::to_value(receipt)
                .map_err(|_| internal_error("Analyst event receipt serialization failed"))?,
        ),
    ))
}

fn validate_event(
    event: &AnalystStatusEvent,
    binding: &AnalystIntegrationBinding,
) -> Result<(Value, [u8; 32], [u8; 32]), (StatusCode, Json<Value>)> {
    if event.schema_version != CONTRACT_VERSION {
        return Err(unprocessable("unsupported Analyst event contract version"));
    }
    for value in [
        &event.event_id,
        &event.command_id,
        &event.correlation_id,
        &event.tenant_id,
        &event.client_id,
        &event.project_id,
    ] {
        if value.is_empty() || value.len() > 300 {
            return Err(unprocessable("Analyst event identifier is invalid"));
        }
    }
    if event.tenant_id != binding.tenant_id
        || event.client_id != binding.client_id
        || event.project_id != binding.project_id
    {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "Analyst event scope does not match this workspace",
        ));
    }
    if event.sequence < 0
        || !matches!(
            event.status.as_str(),
            "accepted"
                | "queued"
                | "running"
                | "awaiting_approval"
                | "succeeded"
                | "failed"
                | "cancelled"
                | "expired"
        )
    {
        return Err(unprocessable("Analyst event lifecycle state is invalid"));
    }
    event
        .occurred_at
        .parse::<DateTime<Utc>>()
        .map_err(|_| unprocessable("Analyst event timestamp is invalid"))?;
    match (&event.status[..], &event.failure_code) {
        ("failed", Some(code)) if bounded_code(code) => {}
        ("failed", _) => {
            return Err(unprocessable(
                "failed Analyst event requires a failure code",
            ))
        }
        (_, None) => {}
        (_, Some(_)) => {
            return Err(unprocessable(
                "Analyst event failure code is allowed only for failed status",
            ))
        }
    }
    if event.output_refs.len() > MAX_OUTPUT_REFS {
        return Err(unprocessable(
            "Analyst event has too many output references",
        ));
    }
    for reference in &event.output_refs {
        validate_reference(reference)?;
    }
    let mut value = serde_json::to_value(event)
        .map_err(|_| unprocessable("Analyst event serialization failed"))?;
    let claimed = parse_sha256(&event.event_sha256)
        .ok_or_else(|| unprocessable("Analyst event digest is invalid"))?;
    value
        .as_object_mut()
        .ok_or_else(|| unprocessable("Analyst event must be an object"))?
        .remove("event_sha256");
    let computed: [u8; 32] = Sha256::digest(canonical_json_bytes(&value)).into();
    if claimed != computed {
        return Err(unprocessable(
            "Analyst event digest does not match its content",
        ));
    }
    let complete = serde_json::to_value(event)
        .map_err(|_| unprocessable("Analyst event serialization failed"))?;
    let payload_sha256 = Sha256::digest(canonical_json_bytes(&complete)).into();
    Ok((complete, claimed, payload_sha256))
}

fn validate_reference(reference: &ArtifactReference) -> Result<(), (StatusCode, Json<Value>)> {
    if reference.authority != "analyst360"
        || !matches!(
            reference.classification.as_str(),
            "internal" | "confidential" | "restricted"
        )
        || parse_sha256(&reference.sha256).is_none()
    {
        return Err(unprocessable("Analyst artifact reference is invalid"));
    }
    reference
        .created_at
        .parse::<DateTime<Utc>>()
        .map_err(|_| unprocessable("Analyst artifact timestamp is invalid"))?;
    for value in [
        &reference.artifact_id,
        &reference.artifact_type,
        &reference.version_id,
    ] {
        if value.is_empty() || value.len() > 300 {
            return Err(unprocessable("Analyst artifact identifier is invalid"));
        }
    }
    Ok(())
}

fn parse_assertion(
    headers: &HeaderMap,
    body_sha256: [u8; 32],
) -> Result<ServiceAssertion, (StatusCode, Json<Value>)> {
    let version = required_header(headers, "x-snowman-assertion-version", 80)?;
    if version != ASSERTION_VERSION {
        return Err(unauthorized("Analyst service assertion version is invalid"));
    }
    let principal_id = required_header(headers, "x-snowman-service-principal", 200)?;
    let key_id = required_header(headers, "x-snowman-key-id", 300)?;
    let nonce = required_header(headers, "x-snowman-nonce", 200)?;
    let signed_at = required_header(headers, "x-snowman-signed-at", 80)?
        .parse::<DateTime<Utc>>()
        .map_err(|_| unauthorized("Analyst service assertion timestamp is invalid"))?;
    let signature = STANDARD
        .decode(required_header(headers, "x-snowman-signature", 2048)?)
        .map_err(|_| unauthorized("Analyst service assertion signature encoding is invalid"))?;
    if !bounded_identifier(&principal_id)
        || !bounded_nonce(&nonce)
        || !kms_key_arn(&key_id)
        || !(128..=1024).contains(&signature.len())
    {
        return Err(unauthorized("Analyst service assertion is malformed"));
    }
    Ok(ServiceAssertion {
        principal_id,
        key_id,
        nonce,
        signed_at,
        signature,
        body_sha256,
    })
}

fn validate_assertion_freshness(
    signed_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), (StatusCode, Json<Value>)> {
    if now - signed_at > Duration::seconds(MAX_ASSERTION_AGE_SECONDS) {
        return Err(unauthorized("Analyst service assertion has expired"));
    }
    if signed_at - now > Duration::seconds(MAX_FUTURE_SKEW_SECONDS) {
        return Err(unauthorized(
            "Analyst service assertion was signed in the future",
        ));
    }
    Ok(())
}

async fn enforce_service_admission(
    state: &AppState,
    tenant: &buzz_core::TenantContext,
    assertion: &ServiceAssertion,
) -> Result<(), (StatusCode, Json<Value>)> {
    let material = format!(
        "snowman-analyst-admission\x1f{}\x1f{}",
        assertion.principal_id, assertion.key_id
    );
    let secret =
        nostr::SecretKey::from_slice(&Sha256::digest(material.as_bytes())).map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "service admission unavailable",
            )
        })?;
    let public_key = nostr::Keys::new(secret).public_key();
    let limit = state
        .auth
        .config()
        .rate_limits
        .agent_standard_api_calls_per_min;
    match crate::admission::check_principal(
        state.admission_rate_limiter.as_ref(),
        tenant,
        &public_key,
        LimitType::ApiCalls,
        60,
        limit,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(crate::admission::AdmissionError::Exceeded { reset_in_secs }) => Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Analyst event quota exceeded; retry in {reset_in_secs}s"),
        )),
        Err(crate::admission::AdmissionError::Unavailable) => Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Analyst event admission is unavailable",
        )),
    }
}

async fn verify_kms_signature(assertion: &ServiceAssertion) -> Result<(), String> {
    let output = kms_client()
        .await
        .verify()
        .key_id(&assertion.key_id)
        .message(Blob::new(canonical_assertion_message(assertion)?))
        .message_type(MessageType::Raw)
        .signature(Blob::new(assertion.signature.clone()))
        .signing_algorithm(SigningAlgorithmSpec::RsassaPssSha256)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if output.signature_valid() {
        Ok(())
    } else {
        Err("signature is not valid".to_string())
    }
}

async fn sign_receipt(key_id: &str, receipt_sha256: &[u8; 32]) -> Result<Vec<u8>, String> {
    let digest_hex = hex::encode(receipt_sha256);
    let message = serde_json::to_vec(&ReceiptSignatureMessage {
        receipt_sha256: &digest_hex,
        version: RECEIPT_SIGNATURE_VERSION,
    })
    .map_err(|error| error.to_string())?;
    kms_client()
        .await
        .sign()
        .key_id(key_id)
        .message(Blob::new(message))
        .message_type(MessageType::Raw)
        .signing_algorithm(SigningAlgorithmSpec::RsassaPssSha256)
        .send()
        .await
        .map_err(|error| error.to_string())?
        .signature()
        .map(|blob| blob.as_ref().to_vec())
        .ok_or_else(|| "KMS did not return a receipt signature".to_string())
}

async fn kms_client() -> &'static aws_sdk_kms::Client {
    KMS_CLIENT
        .get_or_init(|| async {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            aws_sdk_kms::Client::new(&config)
        })
        .await
}

fn canonical_assertion_message(assertion: &ServiceAssertion) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&CanonicalAssertion {
        body_sha256: hex::encode(assertion.body_sha256),
        key_id: &assertion.key_id,
        method: "POST",
        nonce: &assertion.nonce,
        operation: OPERATION,
        principal_id: &assertion.principal_id,
        request_target: PATH,
        signed_at: rfc3339(assertion.signed_at),
        version: ASSERTION_VERSION,
    })
    .map_err(|error| error.to_string())
}

fn unsigned_receipt(
    event: &AnalystStatusEvent,
    binding: &AnalystIntegrationBinding,
    payload_sha256: [u8; 32],
    signed_at: DateTime<Utc>,
) -> Value {
    json!({
        "event_id": event.event_id,
        "payload_sha256": hex::encode(payload_sha256),
        "receipt_id": receipt_id(&event.event_id),
        "received_at": rfc3339(signed_at),
        "receiver_key_id": binding.receipt_kms_key_arn,
        "receiver_service_id": binding.receiver_service_id,
        "schema_version": CONTRACT_VERSION
    })
}

fn render_receipt(
    event: &AnalystStatusEvent,
    binding: &AnalystIntegrationBinding,
    payload_sha256: [u8; 32],
    stored: &StoredAnalystReceipt,
) -> DeliveryReceipt {
    DeliveryReceipt {
        schema_version: CONTRACT_VERSION,
        receipt_id: stored.receipt_id.clone(),
        event_id: event.event_id.clone(),
        receiver_service_id: binding.receiver_service_id.clone(),
        receiver_key_id: binding.receipt_kms_key_arn.clone(),
        receiver_signature: STANDARD.encode(&stored.receipt_signature),
        received_at: rfc3339(stored.receipt_signed_at),
        payload_sha256: hex::encode(payload_sha256),
        receipt_sha256: hex::encode(stored.receipt_sha256),
    }
}

fn receipt_id(event_id: &str) -> String {
    format!(
        "cc_receipt_{}",
        &hex::encode(Sha256::digest(event_id.as_bytes()))[..40]
    )
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut output = Vec::new();
    write_canonical(value, &mut output);
    output
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            if let Ok(encoded) = serde_json::to_vec(value) {
                output.extend(encoded);
            }
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical(value, output);
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let sorted: BTreeMap<&str, &Value> = values
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            for (index, (key, value)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                if let Ok(encoded_key) = serde_json::to_vec(key) {
                    output.extend(encoded_key);
                }
                output.push(b':');
                write_canonical(value, output);
            }
            output.push(b'}');
        }
    }
}

fn required_header(
    headers: &HeaderMap,
    name: &str,
    maximum: usize,
) -> Result<String, (StatusCode, Json<Value>)> {
    let value = headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if value.is_empty() || value.len() > maximum || value.contains('\r') || value.contains('\n') {
        Err(unauthorized(
            "Analyst service assertion header is missing or invalid",
        ))
    } else {
        Ok(value.to_string())
    }
}

fn bounded_identifier(value: &str) -> bool {
    (3..=200).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn bounded_nonce(value: &str) -> bool {
    (24..=200).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn bounded_code(value: &str) -> bool {
    (1..=200).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn kms_key_arn(value: &str) -> bool {
    value.starts_with("arn:aws:kms:")
        && value.contains(":key/")
        && (60..=300).contains(&value.len())
        && !value.contains('*')
}

fn parse_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

fn rfc3339(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn unauthorized(message: &str) -> (StatusCode, Json<Value>) {
    api_error(StatusCode::UNAUTHORIZED, message)
}

fn unprocessable(message: &str) -> (StatusCode, Json<Value>) {
    api_error(StatusCode::UNPROCESSABLE_ENTITY, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> AnalystIntegrationBinding {
        AnalystIntegrationBinding {
            analyst_service_id: "analyst360-event-delivery".to_string(),
            tenant_id: "aptive".to_string(),
            client_id: "aptive".to_string(),
            project_id: "direct_mail_matchback".to_string(),
            request_kms_key_arn:
                "arn:aws:kms:us-west-2:625242091862:key/12345678-1234-1234-1234-1234567890ab"
                    .to_string(),
            receipt_kms_key_arn:
                "arn:aws:kms:us-west-2:625242091862:key/87654321-4321-4321-4321-ba0987654321"
                    .to_string(),
            receiver_service_id: "snowman-command-center-ingress".to_string(),
        }
    }

    fn event() -> AnalystStatusEvent {
        let mut event = AnalystStatusEvent {
            schema_version: CONTRACT_VERSION.to_string(),
            event_id: "event_cc_job_123_1_queued".to_string(),
            command_id: "cmd-1".to_string(),
            correlation_id: "corr-1".to_string(),
            tenant_id: "aptive".to_string(),
            client_id: "aptive".to_string(),
            project_id: "direct_mail_matchback".to_string(),
            occurred_at: "2026-07-26T18:00:00.000Z".to_string(),
            sequence: 1,
            status: "queued".to_string(),
            failure_code: None,
            output_refs: vec![],
            event_sha256: String::new(),
        };
        let mut value = serde_json::to_value(&event).expect("event JSON");
        value
            .as_object_mut()
            .expect("object")
            .remove("event_sha256");
        event.event_sha256 = hex::encode(Sha256::digest(canonical_json_bytes(&value)));
        event
    }

    #[test]
    fn strict_event_validation_binds_scope_and_digest() {
        let event = event();
        let (_, digest, payload) = validate_event(&event, &binding()).expect("valid event");
        assert_eq!(hex::encode(digest), event.event_sha256);
        assert_ne!(digest, payload);

        let mut wrong_scope = event.clone();
        wrong_scope.client_id = "other".to_string();
        assert_eq!(
            validate_event(&wrong_scope, &binding()).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn canonical_json_sorts_nested_object_keys() {
        let value = json!({"z": {"b": 2, "a": 1}, "a": [true, null]});
        assert_eq!(
            String::from_utf8(canonical_json_bytes(&value)).expect("UTF-8"),
            r#"{"a":[true,null],"z":{"a":1,"b":2}}"#
        );
    }

    #[test]
    fn assertion_message_matches_analyst_canonical_contract() {
        let assertion = ServiceAssertion {
            principal_id: "analyst360-event-delivery".to_string(),
            key_id: binding().request_kms_key_arn,
            nonce: "abcdefghijklmnopqrstuvwxyz123456".to_string(),
            signed_at: "2026-07-26T18:00:00Z".parse().expect("timestamp"),
            signature: vec![1; 256],
            body_sha256: [7; 32],
        };
        let value: Value =
            serde_json::from_slice(&canonical_assertion_message(&assertion).expect("canonical"))
                .expect("JSON");
        assert_eq!(value["operation"], OPERATION);
        assert_eq!(value["request_target"], PATH);
        assert_eq!(value["signed_at"], "2026-07-26T18:00:00.000Z");
    }

    #[test]
    fn receipt_digest_excludes_signature_and_is_stable() {
        let event = event();
        let signed_at = "2026-07-26T18:00:01Z".parse().expect("timestamp");
        let unsigned = unsigned_receipt(&event, &binding(), [9; 32], signed_at);
        let digest = Sha256::digest(canonical_json_bytes(&unsigned));
        assert_eq!(digest.len(), 32);
        assert!(unsigned.get("receiver_signature").is_none());
        assert!(unsigned.get("receipt_sha256").is_none());
    }
}
