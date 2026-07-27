//! Snowman workforce human-session enrollment.
//!
//! Google Workspace tokens terminate at the Snowman identity authority. This
//! private boundary accepts only a fresh one-time AWS KMS assertion containing
//! a pseudonymous provider-subject digest and a separately verified Nostr
//! device-possession proof. Tenant, role, capabilities, assurance, lifetime,
//! and stable identity are all derived or constrained by the receiver.

use std::{collections::HashMap, sync::Arc};

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use buzz_audit::{AuditAction, NewAuditEntry};
use buzz_auth::LimitType;
use buzz_db::workforce_identity::{
    NewHumanWorkforceRevocation, NewHumanWorkforceSession, WorkforceIdentityBroker,
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::state::AppState;

use super::{api_error, internal_error};

const PATH: &str = "/internal/snowman/v1/workforce/sessions/enroll";
const REVOCATION_PATH: &str = "/internal/snowman/v1/workforce/sessions/revoke";
const ASSERTION_VERSION: &str = "snowman.workforce-identity-assertion.v1";
const CONTRACT_VERSION: &str = "snowman.workforce-session-enrollment.v1";
const REVOCATION_CONTRACT_VERSION: &str = "snowman.workforce-session-revocation.v1";
const OPERATION: &str = "sessions.enroll";
const REVOCATION_OPERATION: &str = "sessions.revoke";
const DEVICE_PROOF_PURPOSE: &str = "snowman-workforce-session-enrollment";
const DEVICE_PROOF_PROTOCOL: &str = "snowman-workforce-device-proof";
const DEVICE_PROOF_VERSION: &str = "1";
const MAX_BODY_BYTES: usize = 32 * 1024;
const MAX_ASSERTION_AGE_SECONDS: i64 = 90;
const MAX_FUTURE_SKEW_SECONDS: i64 = 30;
const MAX_AUTHENTICATION_AGE_SECONDS: i64 = 600;
const MAX_DEVICE_PROOF_AGE_SECONDS: i64 = 300;
const MAX_ASSURANCE_EVIDENCE_AGE_DAYS: i64 = 120;

static KMS_CLIENT: OnceCell<aws_sdk_kms::Client> = OnceCell::const_new();

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentRequest {
    schema_version: String,
    assertion_id: Uuid,
    broker_id: String,
    provider: String,
    provider_subject_sha256: String,
    hosted_domain: String,
    tenant_id: String,
    client_id: String,
    project_id: String,
    display_name: String,
    source_role: String,
    authenticated_at: DateTime<Utc>,
    device_proof: nostr::Event,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RevocationRequest {
    schema_version: String,
    assertion_id: Uuid,
    broker_id: String,
    provider: String,
    provider_subject_sha256: String,
    hosted_domain: String,
    tenant_id: String,
    client_id: String,
    project_id: String,
    revocation_scope: String,
    session_id: Option<Uuid>,
    reason: String,
}

#[derive(Debug)]
struct AuthorityAssertion {
    principal_id: String,
    key_id: String,
    nonce: String,
    signed_at: DateTime<Utc>,
    signature: Vec<u8>,
    body_sha256: [u8; 32],
    operation: &'static str,
    request_target: &'static str,
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

/// Enroll or rotate one Google-authenticated human device session.
pub async fn enroll_human_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    if !state.config.snowman_workforce_identity_api_enabled {
        return Err(api_error(StatusCode::NOT_FOUND, "not found"));
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "workforce enrollment request is too large",
        ));
    }
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "not found"))?;
    let payload_sha256: [u8; 32] = Sha256::digest(&body).into();
    let request: EnrollmentRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid workforce enrollment JSON"))?;
    validate_request_shape(&request)?;
    let assertion = parse_assertion(&headers, payload_sha256, OPERATION, PATH)?;
    if assertion.principal_id != request.broker_id
        || assertion.nonce != request.assertion_id.to_string()
    {
        return Err(unauthorized(
            "workforce identity assertion is not bound to this request",
        ));
    }
    validate_assertion_freshness(assertion.signed_at, Utc::now())?;

    let broker = state
        .db
        .workforce_identity_broker(tenant.community(), &request.broker_id)
        .await
        .map_err(|_| internal_error("workforce identity authority lookup failed"))?
        .ok_or_else(|| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "workforce identity authority is not active for this workspace",
            )
        })?;
    validate_broker_binding(&request, &assertion, &broker, Utc::now())?;
    enforce_admission(&state, &tenant, &assertion).await?;
    verify_kms_signature(&assertion).await.map_err(|error| {
        tracing::warn!(%error, "Snowman workforce identity KMS verification failed");
        unauthorized("workforce identity assertion is invalid")
    })?;

    let device_pubkey = validate_device_proof(&request, tenant.community(), Utc::now()).await?;
    let provider_subject_sha256 = parse_sha256(&request.provider_subject_sha256)
        .ok_or_else(|| unprocessable("provider subject digest is invalid"))?;
    let role = snowman_role(&request.source_role)
        .ok_or_else(|| api_error(StatusCode::FORBIDDEN, "source role is not authorized"))?;
    let identity_id = stable_identity_id(tenant.community().as_uuid(), &provider_subject_sha256);
    let enrolled_at = Utc::now();
    let expires_at = enrolled_at + Duration::seconds(i64::from(broker.max_session_seconds));
    let session_id = Uuid::new_v4();
    let enrollment = NewHumanWorkforceSession {
        assertion_id: request.assertion_id,
        broker_id: request.broker_id.clone(),
        identity_id,
        session_id,
        provider_subject_sha256,
        display_name: request.display_name.clone(),
        role: role.to_string(),
        assurance_level: broker.assurance_level.clone(),
        authenticated_at: request.authenticated_at,
        expires_at,
        device_pubkey,
        device_proof_event_id: request.device_proof.id.to_bytes(),
        assertion_body_sha256: assertion.body_sha256,
        capabilities: human_capabilities(role),
        enrolled_at,
    };
    let enrolled = state
        .db
        .enroll_human_workforce_session(tenant.community(), &enrollment)
        .await
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("already used") {
                api_error(
                    StatusCode::CONFLICT,
                    "workforce identity assertion was already used",
                )
            } else if message.contains("device limit") {
                api_error(
                    StatusCode::CONFLICT,
                    "workforce identity reached its active device limit",
                )
            } else if message.contains("conflict") || message.contains("already bound") {
                api_error(
                    StatusCode::CONFLICT,
                    "workforce identity enrollment conflicts with existing authority",
                )
            } else {
                tracing::error!(%error, "Snowman workforce human enrollment failed");
                internal_error("workforce human enrollment failed")
            }
        })?;

    if !enrolled.replayed {
        if let Some(audit_tx) = &state.audit_tx {
            if let Err(error) = audit_tx
                .send(NewAuditEntry {
                    community_id: tenant.community(),
                    action: AuditAction::AuthSuccess,
                    actor_pubkey: Some(device_pubkey.to_vec()),
                    object_id: Some(enrolled.session_id.to_string()),
                    detail: json!({
                        "authentication_method": "snowman_google_workspace",
                        "broker_id": request.broker_id,
                        "identity_id": enrolled.identity_id,
                        "role": enrolled.role,
                        "assurance_level": broker.assurance_level,
                        "assurance_evidence_sha256": hex::encode(&broker.assurance_evidence_sha256),
                        "provider_subject_excluded": true,
                        "raw_email_excluded": true,
                        "token_excluded": true
                    }),
                })
                .await
            {
                tracing::error!(%error, "workforce enrollment audit channel closed");
                metrics::counter!("buzz_audit_send_errors_total").increment(1);
            }
        }
    }
    if enrolled.replayed {
        metrics::counter!("snowman_workforce_human_enrollment_replays_total").increment(1);
    } else {
        metrics::counter!(
            "snowman_workforce_human_enrollments_total",
            "role" => enrolled.role.clone(),
            "assurance" => enrollment.assurance_level.clone()
        )
        .increment(1);
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "schema_version": "snowman.workforce-session.v1",
            "identity_id": enrolled.identity_id,
            "session_id": enrolled.session_id,
            "role": enrolled.role,
            "assurance_level": enrollment.assurance_level,
            "expires_at": rfc3339(enrolled.expires_at),
            "device_pubkey": hex::encode(device_pubkey),
            "provider_token_persisted": false
        })),
    ))
}

/// Revoke one session, all sessions, or one Google-authenticated human identity.
pub async fn revoke_human_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    if !state.config.snowman_workforce_identity_api_enabled {
        return Err(api_error(StatusCode::NOT_FOUND, "not found"));
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "workforce revocation request is too large",
        ));
    }
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let tenant = crate::tenant::bind_community(&state.db, raw_host)
        .await
        .map_err(|_| api_error(StatusCode::NOT_FOUND, "not found"))?;
    let payload_sha256: [u8; 32] = Sha256::digest(&body).into();
    let request: RevocationRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid workforce revocation JSON"))?;
    validate_revocation_shape(&request)?;
    let assertion = parse_assertion(
        &headers,
        payload_sha256,
        REVOCATION_OPERATION,
        REVOCATION_PATH,
    )?;
    if assertion.principal_id != request.broker_id
        || assertion.nonce != request.assertion_id.to_string()
    {
        return Err(unauthorized(
            "workforce revocation assertion is not bound to this request",
        ));
    }
    validate_assertion_freshness(assertion.signed_at, Utc::now())?;
    let broker = state
        .db
        .workforce_identity_broker(tenant.community(), &request.broker_id)
        .await
        .map_err(|_| internal_error("workforce identity authority lookup failed"))?
        .ok_or_else(|| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "workforce identity authority is not active for this workspace",
            )
        })?;
    if assertion.key_id != broker.signing_kms_key_arn
        || request.provider != broker.provider
        || request.hosted_domain != broker.hosted_domain
        || request.tenant_id != broker.tenant_id
        || request.client_id != broker.client_id
        || request.project_id != broker.project_id
    {
        return Err(unauthorized(
            "workforce revocation assertion is not bound to this workspace",
        ));
    }
    enforce_admission(&state, &tenant, &assertion).await?;
    verify_kms_signature(&assertion).await.map_err(|error| {
        tracing::warn!(%error, "Snowman workforce revocation KMS verification failed");
        unauthorized("workforce revocation assertion is invalid")
    })?;
    let subject_sha256 = parse_sha256(&request.provider_subject_sha256)
        .ok_or_else(|| unprocessable("provider subject digest is invalid"))?;
    let identity_id = stable_identity_id(tenant.community().as_uuid(), &subject_sha256);
    let revoked = state
        .db
        .revoke_human_workforce_session(
            tenant.community(),
            &NewHumanWorkforceRevocation {
                assertion_id: request.assertion_id,
                broker_id: request.broker_id.clone(),
                identity_id,
                provider_subject_sha256: subject_sha256,
                session_id: request.session_id,
                revocation_scope: request.revocation_scope.clone(),
                reason: request.reason.clone(),
                assertion_body_sha256: assertion.body_sha256,
                revoked_at: Utc::now(),
            },
        )
        .await
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("already used") {
                api_error(
                    StatusCode::CONFLICT,
                    "workforce revocation assertion was already used",
                )
            } else if message.contains("not enrolled") || message.contains("not bound") {
                api_error(
                    StatusCode::NOT_FOUND,
                    "workforce revocation target was not found",
                )
            } else if message.contains("conflict") {
                api_error(
                    StatusCode::CONFLICT,
                    "workforce revocation authority conflicts",
                )
            } else {
                tracing::error!(%error, "Snowman workforce revocation failed");
                internal_error("workforce revocation failed")
            }
        })?;
    if let Some(audit_tx) = &state.audit_tx {
        if let Err(error) = audit_tx
            .send(NewAuditEntry {
                community_id: tenant.community(),
                action: AuditAction::AuthRevoked,
                actor_pubkey: None,
                object_id: Some(
                    request
                        .session_id
                        .map_or_else(|| identity_id.to_string(), |value| value.to_string()),
                ),
                detail: json!({
                    "broker_id": request.broker_id,
                    "identity_id": identity_id,
                    "revocation_scope": request.revocation_scope,
                    "reason": request.reason,
                    "revoked_session_count": revoked.revoked_session_count,
                    "revoked_device_count": revoked.revoked_device_count,
                    "revoked_grant_count": revoked.revoked_grant_count,
                    "revoked_member_count": revoked.revoked_member_count,
                    "identity_revoked": revoked.identity_revoked,
                    "provider_subject_excluded": true,
                    "raw_email_excluded": true,
                    "token_excluded": true
                }),
            })
            .await
        {
            tracing::error!(%error, "workforce revocation audit channel closed");
            metrics::counter!("buzz_audit_send_errors_total").increment(1);
        }
    }
    metrics::counter!(
        "snowman_workforce_human_revocations_total",
        "scope" => request.revocation_scope.clone(),
        "reason" => request.reason.clone()
    )
    .increment(1);
    Ok((
        StatusCode::OK,
        Json(json!({
            "schema_version": REVOCATION_CONTRACT_VERSION,
            "identity_id": revoked.identity_id,
            "session_id": request.session_id,
            "revocation_scope": request.revocation_scope,
            "reason": request.reason,
            "revoked_session_count": revoked.revoked_session_count,
            "revoked_device_count": revoked.revoked_device_count,
            "revoked_grant_count": revoked.revoked_grant_count,
            "revoked_member_count": revoked.revoked_member_count,
            "identity_revoked": revoked.identity_revoked,
            "provider_token_persisted": false
        })),
    ))
}

fn validate_revocation_shape(request: &RevocationRequest) -> Result<(), (StatusCode, Json<Value>)> {
    let valid_scope = matches!(
        request.revocation_scope.as_str(),
        "session" | "all_sessions" | "identity"
    );
    let valid_reason = matches!(
        request.reason.as_str(),
        "user_logout"
            | "device_removed"
            | "global_logout"
            | "identity_inactive"
            | "assignment_changed"
            | "security_response"
    );
    if request.schema_version != REVOCATION_CONTRACT_VERSION
        || request.assertion_id.is_nil()
        || !bounded_identifier(&request.broker_id)
        || request.provider != "google_workspace"
        || parse_sha256(&request.provider_subject_sha256).is_none()
        || !snowman_scope(&request.tenant_id)
        || !snowman_scope(&request.client_id)
        || !snowman_scope(&request.project_id)
        || !valid_hosted_domain(&request.hosted_domain)
        || !valid_scope
        || !valid_reason
        || (request.revocation_scope == "session") != request.session_id.is_some()
        || request.session_id.is_some_and(|value| value.is_nil())
    {
        return Err(unprocessable("workforce revocation contract is invalid"));
    }
    Ok(())
}

fn validate_request_shape(request: &EnrollmentRequest) -> Result<(), (StatusCode, Json<Value>)> {
    if request.schema_version != CONTRACT_VERSION
        || request.assertion_id.is_nil()
        || !bounded_identifier(&request.broker_id)
        || request.provider != "google_workspace"
        || parse_sha256(&request.provider_subject_sha256).is_none()
        || !snowman_scope(&request.tenant_id)
        || !snowman_scope(&request.client_id)
        || !snowman_scope(&request.project_id)
        || !valid_hosted_domain(&request.hosted_domain)
        || request.display_name.trim() != request.display_name
        || request.display_name.is_empty()
        || request.display_name.len() > 256
        || request.display_name.contains('@')
        || snowman_role(&request.source_role).is_none()
    {
        return Err(unprocessable("workforce enrollment contract is invalid"));
    }
    Ok(())
}

fn validate_broker_binding(
    request: &EnrollmentRequest,
    assertion: &AuthorityAssertion,
    broker: &WorkforceIdentityBroker,
    now: DateTime<Utc>,
) -> Result<(), (StatusCode, Json<Value>)> {
    if assertion.key_id != broker.signing_kms_key_arn
        || request.provider != broker.provider
        || request.hosted_domain != broker.hosted_domain
        || request.tenant_id != broker.tenant_id
        || request.client_id != broker.client_id
        || request.project_id != broker.project_id
    {
        return Err(unauthorized(
            "workforce identity assertion is not bound to this workspace",
        ));
    }
    if broker.assurance_evidence_sha256.len() != 32
        || !matches!(
            broker.assurance_level.as_str(),
            "mfa" | "phishing_resistant"
        )
        || now - broker.assurance_evaluated_at > Duration::days(MAX_ASSURANCE_EVIDENCE_AGE_DAYS)
        || broker.assurance_evaluated_at - now > Duration::seconds(MAX_FUTURE_SKEW_SECONDS)
    {
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "workforce assurance evidence is missing or stale",
        ));
    }
    if now - request.authenticated_at > Duration::seconds(MAX_AUTHENTICATION_AGE_SECONDS)
        || request.authenticated_at - now > Duration::seconds(MAX_FUTURE_SKEW_SECONDS)
    {
        return Err(unauthorized(
            "workforce source authentication is not recent",
        ));
    }
    Ok(())
}

async fn validate_device_proof(
    request: &EnrollmentRequest,
    community: buzz_core::CommunityId,
    now: DateTime<Utc>,
) -> Result<[u8; 32], (StatusCode, Json<Value>)> {
    let event = request.device_proof.clone();
    tokio::task::spawn_blocking(move || buzz_core::verification::verify_event(&event))
        .await
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "device proof verifier unavailable",
            )
        })?
        .map_err(|_| unauthorized("workforce device proof is invalid"))?;
    if request.device_proof.kind.as_u16() != buzz_core::kind::KIND_NOSTR_IDENTITY_BINDING as u16
        || !request.device_proof.content.is_empty()
    {
        return Err(unauthorized(
            "workforce device proof has an invalid purpose",
        ));
    }
    let proof_time =
        DateTime::<Utc>::from_timestamp(request.device_proof.created_at.as_secs() as i64, 0)
            .ok_or_else(|| unauthorized("workforce device proof timestamp is invalid"))?;
    if now - proof_time > Duration::seconds(MAX_DEVICE_PROOF_AGE_SECONDS)
        || proof_time - now > Duration::seconds(MAX_FUTURE_SKEW_SECONDS)
    {
        return Err(unauthorized("workforce device proof is not fresh"));
    }
    let mut fields = HashMap::new();
    if request.device_proof.tags.len() != 10 {
        return Err(unauthorized(
            "workforce device proof is not bound to this enrollment",
        ));
    }
    for tag in request.device_proof.tags.iter() {
        let values = tag.as_slice();
        if values.len() != 2
            || fields
                .insert(values[0].to_string(), values[1].to_string())
                .is_some()
        {
            return Err(unauthorized(
                "workforce device proof is not bound to this enrollment",
            ));
        }
    }
    let expected = [
        ("assertion", request.assertion_id.to_string()),
        ("broker", request.broker_id.clone()),
        ("community", community.to_string()),
        ("purpose", DEVICE_PROOF_PURPOSE.to_string()),
        ("protocol", DEVICE_PROOF_PROTOCOL.to_string()),
        ("version", DEVICE_PROOF_VERSION.to_string()),
    ];
    let nonce = fields.get("nonce").map(String::as_str).unwrap_or_default();
    let verification_code = fields
        .get("verification_code")
        .map(String::as_str)
        .unwrap_or_default();
    let origin = fields.get("origin").map(String::as_str).unwrap_or_default();
    let expires_at = fields
        .get("expires_at")
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc));
    let origin = url::Url::parse(origin).ok();
    let origin_is_snowman = origin.as_ref().is_some_and(|value| {
        let host = value.host_str().unwrap_or_default();
        value.scheme() == "https"
            && value.username().is_empty()
            && value.password().is_none()
            && value.port().is_none()
            && value.path() == "/"
            && value.query().is_none()
            && value.fragment().is_none()
            && (host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
    });
    if expected
        .iter()
        .any(|(name, value)| fields.get(*name) != Some(value))
        || nonce.len() != 43
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || verification_code.len() != 6
        || !verification_code.bytes().all(|byte| byte.is_ascii_digit())
        || !origin_is_snowman
        || expires_at.is_none_or(|expiry| {
            expiry <= now || expiry - now > Duration::seconds(MAX_DEVICE_PROOF_AGE_SECONDS + 30)
        })
    {
        return Err(unauthorized(
            "workforce device proof is not bound to this enrollment",
        ));
    }
    Ok(request.device_proof.pubkey.to_bytes())
}

fn stable_identity_id(community_id: &Uuid, subject_sha256: &[u8; 32]) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"snowman.workforce-human.v1\0");
    digest.update(community_id.as_bytes());
    digest.update(subject_sha256);
    let output = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&output[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn snowman_role(source_role: &str) -> Option<&'static str> {
    match source_role {
        "admin" => Some("owner"),
        "reviewer" => Some("admin"),
        "analyst" | "viewer" => Some("member"),
        _ => None,
    }
}

fn human_capabilities(role: &str) -> Vec<String> {
    let capabilities: &[&str] = match role {
        "owner" | "admin" => &[
            "workforce.requests.create",
            "workforce.requests.read",
            "workforce.requests.cancel",
            "workforce.tasks.approve",
            "workforce.schedules.manage",
        ],
        "member" => &["workforce.requests.create", "workforce.requests.read"],
        _ => &[],
    };
    capabilities
        .iter()
        .map(|value| (*value).to_string())
        .collect()
}

fn parse_assertion(
    headers: &HeaderMap,
    body_sha256: [u8; 32],
    operation: &'static str,
    request_target: &'static str,
) -> Result<AuthorityAssertion, (StatusCode, Json<Value>)> {
    if required_header(headers, "x-snowman-assertion-version", 80)? != ASSERTION_VERSION {
        return Err(unauthorized(
            "workforce identity assertion version is invalid",
        ));
    }
    let principal_id = required_header(headers, "x-snowman-service-principal", 200)?;
    let key_id = required_header(headers, "x-snowman-key-id", 300)?;
    let nonce = required_header(headers, "x-snowman-nonce", 200)?;
    let signed_at = required_header(headers, "x-snowman-signed-at", 80)?
        .parse::<DateTime<Utc>>()
        .map_err(|_| unauthorized("workforce identity assertion timestamp is invalid"))?;
    let signature = STANDARD
        .decode(required_header(headers, "x-snowman-signature", 2048)?)
        .map_err(|_| unauthorized("workforce identity assertion signature is invalid"))?;
    if !bounded_identifier(&principal_id)
        || !bounded_nonce(&nonce)
        || !kms_key_arn(&key_id)
        || !(128..=1024).contains(&signature.len())
    {
        return Err(unauthorized("workforce identity assertion is malformed"));
    }
    Ok(AuthorityAssertion {
        principal_id,
        key_id,
        nonce,
        signed_at,
        signature,
        body_sha256,
        operation,
        request_target,
    })
}

fn validate_assertion_freshness(
    signed_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), (StatusCode, Json<Value>)> {
    if now - signed_at > Duration::seconds(MAX_ASSERTION_AGE_SECONDS)
        || signed_at - now > Duration::seconds(MAX_FUTURE_SKEW_SECONDS)
    {
        return Err(unauthorized("workforce identity assertion is not fresh"));
    }
    Ok(())
}

async fn enforce_admission(
    state: &AppState,
    tenant: &buzz_core::TenantContext,
    assertion: &AuthorityAssertion,
) -> Result<(), (StatusCode, Json<Value>)> {
    let material = format!(
        "snowman-identity-admission\x1f{}\x1f{}",
        assertion.principal_id, assertion.key_id
    );
    let secret =
        nostr::SecretKey::from_slice(&Sha256::digest(material.as_bytes())).map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "identity admission unavailable",
            )
        })?;
    let public_key = nostr::Keys::new(secret).public_key();
    let limit = state.auth.config().rate_limits.human_api_calls_per_min;
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
            &format!("identity enrollment quota exceeded; retry in {reset_in_secs}s"),
        )),
        Err(crate::admission::AdmissionError::Unavailable) => Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "identity enrollment admission is unavailable",
        )),
    }
}

async fn verify_kms_signature(assertion: &AuthorityAssertion) -> Result<(), String> {
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
    output
        .signature_valid()
        .then_some(())
        .ok_or_else(|| "signature is not valid".to_string())
}

async fn kms_client() -> &'static aws_sdk_kms::Client {
    KMS_CLIENT
        .get_or_init(|| async {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            aws_sdk_kms::Client::new(&config)
        })
        .await
}

fn canonical_assertion_message(assertion: &AuthorityAssertion) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&CanonicalAssertion {
        body_sha256: hex::encode(assertion.body_sha256),
        key_id: &assertion.key_id,
        method: "POST",
        nonce: &assertion.nonce,
        operation: assertion.operation,
        principal_id: &assertion.principal_id,
        request_target: assertion.request_target,
        signed_at: rfc3339(assertion.signed_at),
        version: ASSERTION_VERSION,
    })
    .map_err(|error| error.to_string())
}

fn required_header(
    headers: &HeaderMap,
    name: &'static str,
    maximum: usize,
) -> Result<String, (StatusCode, Json<Value>)> {
    let value = headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if value.is_empty() || value.len() > maximum || value.contains(['\r', '\n']) {
        return Err(unauthorized(
            "required workforce identity header is invalid",
        ));
    }
    Ok(value.to_string())
}

fn bounded_identifier(value: &str) -> bool {
    (3..=200).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
        })
}

fn bounded_nonce(value: &str) -> bool {
    (24..=200).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn kms_key_arn(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    parts.len() == 6
        && (parts[0] == "arn")
        && parts[1].starts_with("aws")
        && parts[2] == "kms"
        && !parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
        && parts[5].starts_with("key/")
        && parts[5].len() == 40
}

fn snowman_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 120
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_hosted_domain(value: &str) -> bool {
    value == value.to_ascii_lowercase()
        && (3..=253).contains(&value.len())
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn parse_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || value != value.to_ascii_lowercase() {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
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

    #[test]
    fn role_mapping_and_capabilities_are_receiver_owned() {
        assert_eq!(snowman_role("admin"), Some("owner"));
        assert_eq!(snowman_role("reviewer"), Some("admin"));
        assert_eq!(snowman_role("analyst"), Some("member"));
        assert_eq!(snowman_role("service"), None);
        assert!(human_capabilities("member").contains(&"workforce.requests.read".to_string()));
        assert!(!human_capabilities("member").contains(&"workforce.tasks.approve".to_string()));
    }

    #[test]
    fn stable_identity_is_tenant_bound() {
        let subject = [7_u8; 32];
        let first = stable_identity_id(&Uuid::from_u128(1), &subject);
        assert_eq!(first, stable_identity_id(&Uuid::from_u128(1), &subject));
        assert_ne!(first, stable_identity_id(&Uuid::from_u128(2), &subject));
        assert_eq!(first.get_version_num(), 8);
    }

    #[test]
    fn hosted_domain_and_scope_are_strict() {
        assert!(valid_hosted_domain("snowmanai.org"));
        assert!(!valid_hosted_domain("SnowmanAI.org"));
        assert!(!valid_hosted_domain("snowmanai.org.evil.example"));
        assert!(snowman_scope("aptive"));
        assert!(!snowman_scope("aptive client"));
    }

    #[test]
    fn revocation_contract_rejects_mismatched_targets_and_unapproved_reasons() {
        let valid = RevocationRequest {
            schema_version: REVOCATION_CONTRACT_VERSION.to_string(),
            assertion_id: Uuid::from_u128(1),
            broker_id: "snowman-analyst360-identity".to_string(),
            provider: "google_workspace".to_string(),
            provider_subject_sha256: "11".repeat(32),
            hosted_domain: "snowmanai.org".to_string(),
            tenant_id: "aptive".to_string(),
            client_id: "aptive".to_string(),
            project_id: "direct_mail_matchback".to_string(),
            revocation_scope: "session".to_string(),
            session_id: Some(Uuid::from_u128(2)),
            reason: "user_logout".to_string(),
        };
        assert!(validate_revocation_shape(&valid).is_ok());
        assert!(validate_revocation_shape(&RevocationRequest {
            session_id: None,
            ..valid
        })
        .is_err());
        assert!(validate_revocation_shape(&RevocationRequest {
            revocation_scope: "identity".to_string(),
            session_id: None,
            reason: "caller_supplied_reason".to_string(),
            ..RevocationRequest {
                schema_version: REVOCATION_CONTRACT_VERSION.to_string(),
                assertion_id: Uuid::from_u128(3),
                broker_id: "snowman-analyst360-identity".to_string(),
                provider: "google_workspace".to_string(),
                provider_subject_sha256: "22".repeat(32),
                hosted_domain: "snowmanai.org".to_string(),
                tenant_id: "aptive".to_string(),
                client_id: "aptive".to_string(),
                project_id: "direct_mail_matchback".to_string(),
                revocation_scope: "identity".to_string(),
                session_id: None,
                reason: "security_response".to_string(),
            }
        })
        .is_err());
    }

    #[test]
    fn canonical_assertions_bind_enrollment_and_revocation_to_distinct_routes() {
        let base = AuthorityAssertion {
            principal_id: "snowman-analyst360-identity".to_string(),
            key_id: "arn:aws:kms:us-west-2:333333333333:key/00000000-0000-4000-8000-000000000030"
                .to_string(),
            nonce: Uuid::from_u128(1).to_string(),
            signed_at: DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            signature: vec![7; 256],
            body_sha256: [9; 32],
            operation: OPERATION,
            request_target: PATH,
        };
        let enrollment: Value =
            serde_json::from_slice(&canonical_assertion_message(&base).unwrap()).unwrap();
        let revocation: Value = serde_json::from_slice(
            &canonical_assertion_message(&AuthorityAssertion {
                operation: REVOCATION_OPERATION,
                request_target: REVOCATION_PATH,
                ..base
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(enrollment["operation"], OPERATION);
        assert_eq!(enrollment["request_target"], PATH);
        assert_eq!(revocation["operation"], REVOCATION_OPERATION);
        assert_eq!(revocation["request_target"], REVOCATION_PATH);
        assert_ne!(enrollment, revocation);
    }
}
