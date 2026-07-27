#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Private NIP-98 authenticated repository adapter for Analyst meeting commands.
//!
//! The service accepts one exact digest-only Analyst 360 contract. It does not
//! accept raw mail, conference URLs, phone numbers, provider credentials, or
//! model-selected authority. Every state transition is tenant locked and every
//! successful response is signed by a dedicated AWS KMS receipt key.

use std::{collections::BTreeMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use async_trait::async_trait;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use nostr::TagKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use snowman_meeting_control::{CalendarObservation, CancellationCommand, MeetingAdmission};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;
use uuid::Uuid;

/// Exact Analyst command schema.
pub const MEETING_COMMAND_SCHEMA: &str = "snowman.meeting.command.v1";
/// Exact signed receipt schema expected by Analyst 360.
pub const MEETING_RECEIPT_SCHEMA: &str = "snowman.meeting.command-receipt.v1";
const REQUIRED_CAPABILITY: &str = "meeting.commands.submit";
const MAX_REQUEST_BYTES: usize = 256 * 1024;
const AUTH_TTL_SECONDS: i64 = 60;

/// Stable failure classes safe to expose without request content.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Request authentication or workforce authority is not live.
    #[error("meeting command is not authorized")]
    Unauthorized,
    /// Contract fields or their digest bindings are invalid.
    #[error("meeting command is invalid")]
    Invalid,
    /// A stale revision, cancellation fence, or idempotency conflict won.
    #[error("meeting command conflicts with durable authority")]
    Conflict,
    /// Dedicated persistence was unavailable.
    #[error("meeting command persistence failed")]
    Database,
    /// The dedicated receipt signer was unavailable.
    #[error("meeting command receipt signing failed")]
    Signing,
}

/// Exact trusted authority section projected by Analyst policy.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandAuthority {
    /// Digest of the canonical Calendar observation.
    pub observation_sha256: String,
    /// Organizer pseudonym copied from the observation.
    pub organizer_subject_sha256: String,
    /// Independent policy result; must be true.
    pub organizer_approved: bool,
    /// Monotonic Analyst policy generation.
    pub policy_generation: u64,
    /// Digest of the sealed conference resolution.
    pub conference_resolution_sha256: String,
    /// Digest of the complete admission/cancellation evidence packet.
    pub admission_evidence_sha256: String,
}

/// Exact schedule, reschedule, or cancellation envelope from Analyst 360.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeetingCommand {
    /// Contract schema.
    pub schema_version: String,
    /// Tenant-scoped idempotency identifier.
    pub command_id: Uuid,
    /// One of schedule, reschedule, or cancel.
    pub command_kind: String,
    /// Operations-bound Analyst service principal.
    pub service_principal: String,
    /// Immutable source observation time.
    pub issued_at: DateTime<Utc>,
    /// Exact accepted Calendar observation or cancellation tombstone.
    pub calendar_observation: CalendarObservation,
    /// Independent policy evidence.
    pub authority: CommandAuthority,
    /// Present only for schedule/reschedule.
    pub admission: Option<MeetingAdmission>,
    /// Present only for cancellation.
    pub cancellation: Option<CancellationCommand>,
}

impl MeetingCommand {
    fn validate(&self, path_tenant: Uuid, now: DateTime<Utc>) -> Result<CommandParts, Error> {
        if self.schema_version != MEETING_COMMAND_SCHEMA
            || self.calendar_observation.tenant_id != path_tenant
            || self.authority.policy_generation == 0
            || !self.authority.organizer_approved
            || self.issued_at > now + ChronoDuration::seconds(30)
        {
            return Err(Error::Invalid);
        }
        self.calendar_observation
            .validate()
            .map_err(|_| Error::Invalid)?;
        if self.authority.organizer_subject_sha256
            != self.calendar_observation.organizer_subject_sha256
            || self.authority.observation_sha256 != canonical_sha256(&self.calendar_observation)?
        {
            return Err(Error::Invalid);
        }
        match self.command_kind.as_str() {
            "schedule" | "reschedule" => {
                let admission = self.admission.clone().ok_or(Error::Invalid)?;
                if self.cancellation.is_some()
                    || admission.tenant_id != path_tenant
                    || admission.meeting_id == Uuid::nil()
                    || admission.ends_at <= now
                {
                    return Err(Error::Invalid);
                }
                MeetingAdmission::from_calendar(&self.calendar_observation, admission.clone())
                    .map_err(|_| Error::Invalid)?;
                self.validate_policy_digests(&admission)?;
                Ok(CommandParts::Admission(Box::new(admission)))
            }
            "cancel" => {
                let cancellation = self.cancellation.clone().ok_or(Error::Invalid)?;
                if self.admission.is_some()
                    || cancellation.command_id != self.command_id
                    || cancellation.tenant_id != path_tenant
                    || cancellation.provider_event_id_sha256
                        != self.calendar_observation.provider_event_id_sha256
                    || cancellation.provider_revision != self.calendar_observation.revision
                    || cancellation.cancellation_evidence_sha256
                        != self.authority.admission_evidence_sha256
                    || serde_json::to_value(self.calendar_observation.attendance)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .as_deref()
                        != Some("cancelled")
                {
                    return Err(Error::Invalid);
                }
                Ok(CommandParts::Cancellation(cancellation))
            }
            _ => Err(Error::Invalid),
        }
    }

    fn validate_policy_digests(&self, admission: &MeetingAdmission) -> Result<(), Error> {
        let conference = canonical_sha256(&serde_json::json!({
            "meeting_id": admission.meeting_id,
            "conference_kind": admission.conference.kind,
            "entrypoint_sha256": admission.conference.entrypoint_sha256,
            "sealed_coordinate_ref": admission.conference.sealed_coordinate_ref,
            "approval_evidence_sha256": admission.conference.approval_evidence_sha256,
        }))?;
        if conference != self.authority.conference_resolution_sha256
            || admission.admission_evidence_sha256 != self.authority.admission_evidence_sha256
        {
            return Err(Error::Invalid);
        }
        let evidence = canonical_sha256(&serde_json::json!({
            "observation_sha256": self.authority.observation_sha256,
            "organizer_subject_sha256": self.authority.organizer_subject_sha256,
            "organizer_approved": true,
            "policy_generation": self.authority.policy_generation,
            "conference_resolution_sha256": self.authority.conference_resolution_sha256,
            "processor_policy_evidence_sha256": admission.processing.policy_evidence_sha256,
            "consent_policy_evidence_sha256": admission.consent.policy_evidence_sha256,
        }))?;
        if evidence != self.authority.admission_evidence_sha256 {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

enum CommandParts {
    Admission(Box<MeetingAdmission>),
    Cancellation(CancellationCommand),
}

/// Signed receipt returned to the exact Analyst lease.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MeetingCommandReceipt {
    /// Receipt contract schema.
    pub schema_version: String,
    /// Exact command ID.
    pub command_id: Uuid,
    /// Exact tenant.
    pub tenant_id: Uuid,
    /// Exact meeting.
    pub meeting_id: Uuid,
    /// Exact provider event digest.
    pub provider_event_id_sha256: String,
    /// Exact provider revision.
    pub provider_revision: u64,
    /// SHA-256 of the raw authenticated command body.
    pub command_sha256: String,
    /// Snowman meeting-controller service identity.
    pub receiver_identity_id: Uuid,
    /// Exact AWS KMS signing key ARN.
    pub receiver_key_id: String,
    /// Applied or duplicate.
    pub status: String,
    /// Resulting Snowman schedule revision.
    pub schedule_revision: u64,
    /// Trusted controller receipt time.
    pub received_at: DateTime<Utc>,
    /// Base64 AWS KMS signature over canonical receipt fields.
    pub receiver_signature: String,
}

#[derive(Clone)]
struct VerifiedAuth {
    pubkey: [u8; 32],
    event_id: [u8; 32],
    created_at: DateTime<Utc>,
}

#[derive(Debug)]
struct ApplyOutcome {
    meeting_id: Uuid,
    provider_event_id_sha256: String,
    provider_revision: u64,
    schedule_revision: u64,
    duplicate: bool,
}

/// Receipt signing boundary; production uses one asymmetric AWS KMS key.
#[async_trait]
pub trait ReceiptSigner: Send + Sync {
    /// Exact key ARN included in the receipt.
    fn key_id(&self) -> &str;
    /// Sign canonical receipt bytes without exposing private key material.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

struct KmsReceiptSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
}

#[async_trait]
impl ReceiptSigner for KmsReceiptSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let output = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(message))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|_| Error::Signing)?;
        output
            .signature()
            .map(|value| value.as_ref().to_vec())
            .ok_or(Error::Signing)
    }
}

/// Exact service configuration. Secrets come from the dedicated task secret.
pub struct Config {
    bind_addr: SocketAddr,
    database_url: String,
    database_role: String,
    max_connections: u32,
    public_origin: Url,
    receiver_identity_id: Uuid,
    receipt_key_arn: String,
}

/// Non-sensitive startup failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Static or secret-backed configuration failed closed.
    #[error("Snowman meeting command configuration is invalid: {0}")]
    Invalid(&'static str),
    /// Dedicated database identity could not be verified.
    #[error("Snowman meeting command database initialization failed")]
    Database,
}

impl Config {
    /// Load production configuration without accepting ambient keys or origins.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = value("SNOWMAN_MEETING_COMMAND_BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8080".into())
            .parse()
            .map_err(|_| ConfigError::Invalid("bind address"))?;
        let database_url = required("SNOWMAN_MEETING_COMMAND_DATABASE_URL")?;
        let database_role = required("SNOWMAN_MEETING_COMMAND_DATABASE_ROLE")?;
        buzz_db::runtime_security::validate_role_name(&database_role)
            .map_err(|_| ConfigError::Invalid("database role"))?;
        let max_connections = value("SNOWMAN_MEETING_COMMAND_MAX_CONNECTIONS")
            .unwrap_or_else(|| "8".into())
            .parse::<u32>()
            .map_err(|_| ConfigError::Invalid("connection limit"))?;
        let public_origin =
            parse_private_origin(&required("SNOWMAN_MEETING_COMMAND_PUBLIC_ORIGIN")?)?;
        let receiver_identity_id = required("SNOWMAN_MEETING_COMMAND_RECEIVER_IDENTITY_ID")?
            .parse()
            .map_err(|_| ConfigError::Invalid("receiver identity"))?;
        let receipt_key_arn = required("SNOWMAN_MEETING_COMMAND_RECEIPT_KEY_ARN")?;
        if !(1..=16).contains(&max_connections)
            || !valid_database_url(&database_url)
            || !valid_kms_key_arn(&receipt_key_arn)
            || value("SNOWMAN_MEETING_COMMAND_NETWORK_POLICY").as_deref()
                != Some("private-snowman-only")
        {
            return Err(ConfigError::Invalid("private service boundary"));
        }
        Ok(Self {
            bind_addr,
            database_url,
            database_role,
            max_connections,
            public_origin,
            receiver_identity_id,
            receipt_key_arn,
        })
    }
}

/// Shared private-service state.
#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    signer: Arc<dyn ReceiptSigner>,
    bind_addr: SocketAddr,
    public_origin: Url,
    receiver_identity_id: Uuid,
}

impl AppState {
    /// Initialize and verify the dedicated DB and KMS identities.
    pub async fn new(config: Config) -> Result<Self, ConfigError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&config.database_url)
            .await
            .map_err(|_| ConfigError::Database)?;
        buzz_db::runtime_security::verify_meeting_control_role(&pool, &config.database_role)
            .await
            .map_err(|_| ConfigError::Database)?;
        let sdk = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        let signer = Arc::new(KmsReceiptSigner {
            client: aws_sdk_kms::Client::new(&sdk),
            key_id: config.receipt_key_arn,
        });
        Ok(Self {
            pool,
            signer,
            bind_addr: config.bind_addr,
            public_origin: config.public_origin,
            receiver_identity_id: config.receiver_identity_id,
        })
    }

    /// Private listener address.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

/// Build the health and private command routes.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/_liveness", get(|| async { StatusCode::NO_CONTENT }))
        .route("/_readiness", get(readiness))
        .route(
            "/v1/tenants/{tenant_id}/meeting-commands",
            post(post_command),
        )
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .with_state(state)
}

async fn readiness(State(state): State<AppState>) -> StatusCode {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(1) => StatusCode::NO_CONTENT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn post_command(
    State(state): State<AppState>,
    Path(tenant_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<MeetingCommandReceipt>, ApiError> {
    if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
        return Err(ApiError(Error::Invalid));
    }
    let expected_url = state
        .public_origin
        .join(&format!("v1/tenants/{tenant_id}/meeting-commands"))
        .map_err(|_| ApiError(Error::Invalid))?;
    let auth = verify_auth(&headers, expected_url.as_str(), &body)?;
    let command: MeetingCommand =
        serde_json::from_slice(&body).map_err(|_| ApiError(Error::Invalid))?;
    let now = Utc::now();
    let parts = command.validate(tenant_id, now).map_err(ApiError)?;
    let command_sha256: [u8; 32] = Sha256::digest(&body).into();
    let outcome = apply_command(
        &state.pool,
        &command,
        parts,
        &auth,
        command_sha256,
        (state.receiver_identity_id, state.signer.key_id()),
        now,
    )
    .await
    .map_err(ApiError)?;
    let status = if outcome.duplicate {
        "duplicate"
    } else {
        "applied"
    };
    let unsigned = serde_json::json!({
        "schema_version": MEETING_RECEIPT_SCHEMA,
        "command_id": command.command_id,
        "tenant_id": tenant_id,
        "meeting_id": outcome.meeting_id,
        "provider_event_id_sha256": outcome.provider_event_id_sha256,
        "provider_revision": outcome.provider_revision,
        "command_sha256": hex::encode(command_sha256),
        "receiver_identity_id": state.receiver_identity_id,
        "receiver_key_id": state.signer.key_id(),
        "status": status,
        "schedule_revision": outcome.schedule_revision,
        "received_at": now,
    });
    let canonical = canonical_json(&unsigned).map_err(ApiError)?;
    let signature = state.signer.sign(&canonical).await.map_err(ApiError)?;
    if !(64..=1024).contains(&signature.len()) {
        return Err(ApiError(Error::Signing));
    }
    persist_receipt(
        &state.pool,
        PersistReceipt {
            tenant_id,
            command_id: command.command_id,
            auth_event_id: auth.event_id,
            payload_sha256: Sha256::digest(&canonical).into(),
            signature: &signature,
            key_id: state.signer.key_id(),
            issued_at: now,
        },
    )
    .await
    .map_err(ApiError)?;
    Ok(Json(MeetingCommandReceipt {
        schema_version: MEETING_RECEIPT_SCHEMA.into(),
        command_id: command.command_id,
        tenant_id,
        meeting_id: outcome.meeting_id,
        provider_event_id_sha256: outcome.provider_event_id_sha256,
        provider_revision: outcome.provider_revision,
        command_sha256: hex::encode(command_sha256),
        receiver_identity_id: state.receiver_identity_id,
        receiver_key_id: state.signer.key_id().into(),
        status: status.into(),
        schedule_revision: outcome.schedule_revision,
        received_at: now,
        receiver_signature: STANDARD.encode(signature),
    }))
}

fn verify_auth(headers: &HeaderMap, url: &str, body: &[u8]) -> Result<VerifiedAuth, ApiError> {
    let encoded = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Nostr "))
        .ok_or(ApiError(Error::Unauthorized))?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| ApiError(Error::Unauthorized))?;
    if bytes.len() > 32 * 1024 {
        return Err(ApiError(Error::Unauthorized));
    }
    let event_json = String::from_utf8(bytes).map_err(|_| ApiError(Error::Unauthorized))?;
    let event: nostr::Event =
        serde_json::from_str(&event_json).map_err(|_| ApiError(Error::Unauthorized))?;
    if !event.tags.iter().any(|tag| tag.kind() == TagKind::Payload) {
        return Err(ApiError(Error::Unauthorized));
    }
    let pubkey = buzz_auth::verify_nip98_event(&event_json, url, "POST", Some(body))
        .map_err(|_| ApiError(Error::Unauthorized))?;
    let created_at = DateTime::from_timestamp(event.created_at.as_secs() as i64, 0)
        .ok_or(ApiError(Error::Unauthorized))?;
    if Utc::now() > created_at + ChronoDuration::seconds(AUTH_TTL_SECONDS) {
        return Err(ApiError(Error::Unauthorized));
    }
    Ok(VerifiedAuth {
        pubkey: pubkey.to_bytes(),
        event_id: event.id.to_bytes(),
        created_at,
    })
}

async fn apply_command(
    pool: &PgPool,
    command: &MeetingCommand,
    parts: CommandParts,
    auth: &VerifiedAuth,
    command_sha256: [u8; 32],
    receiver: (Uuid, &str),
    now: DateTime<Utc>,
) -> Result<ApplyOutcome, Error> {
    let tenant_id = command.calendar_observation.tenant_id;
    let mut tx = pool.begin().await.map_err(|_| Error::Database)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Database)?;
    authorize(&mut tx, tenant_id, command, auth, receiver.0, receiver.1).await?;
    let inserted = sqlx::query(
        "INSERT INTO snowman_meeting_command_auth_events \
         (community_id,auth_event_id,request_sha256,requester_pubkey,service_principal,observed_at,expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
        .bind(tenant_id).bind(auth.event_id.as_slice()).bind(command_sha256.as_slice())
        .bind(auth.pubkey.as_slice()).bind(&command.service_principal).bind(now)
        .bind(auth.created_at + ChronoDuration::seconds(AUTH_TTL_SECONDS))
        .execute(&mut *tx).await.map_err(|_| Error::Database)?;
    if inserted.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    if let Some(row) = sqlx::query(
        "SELECT meeting_id,command_sha256,provider_revision,result_schedule_revision \
         FROM snowman_meeting_commands WHERE community_id=$1 AND command_id=$2",
    )
    .bind(tenant_id)
    .bind(command.command_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| Error::Database)?
    {
        let prior: Vec<u8> = row.try_get("command_sha256").map_err(|_| Error::Database)?;
        if prior != command_sha256 {
            return Err(Error::Conflict);
        }
        let meeting_id = row.try_get("meeting_id").map_err(|_| Error::Database)?;
        tx.commit().await.map_err(|_| Error::Database)?;
        return Ok(ApplyOutcome {
            meeting_id,
            provider_event_id_sha256: command
                .calendar_observation
                .provider_event_id_sha256
                .clone(),
            provider_revision: row
                .try_get::<i64, _>("provider_revision")
                .map_err(|_| Error::Database)? as u64,
            schedule_revision: row
                .try_get::<i64, _>("result_schedule_revision")
                .map_err(|_| Error::Database)? as u64,
            duplicate: true,
        });
    }
    let outcome = match parts {
        CommandParts::Admission(admission) => {
            apply_admission(&mut tx, command, &admission, command_sha256, now).await?
        }
        CommandParts::Cancellation(cancel) => {
            apply_cancellation(&mut tx, command, &cancel, command_sha256, now).await?
        }
    };
    tx.commit().await.map_err(|_| Error::Database)?;
    Ok(outcome)
}

async fn authorize(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    command: &MeetingCommand,
    auth: &VerifiedAuth,
    receiver_identity_id: Uuid,
    receiver_key_id: &str,
) -> Result<(), Error> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM snowman_meeting_command_callers c \
         JOIN snowman_workforce_identities i ON i.community_id=c.community_id AND i.identity_id=c.service_identity_id \
         JOIN snowman_workforce_key_bindings k ON k.community_id=i.community_id AND k.identity_id=i.identity_id \
         JOIN snowman_workforce_capability_grants g ON g.community_id=i.community_id AND g.identity_id=i.identity_id \
         JOIN snowman_meeting_mailboxes m ON m.community_id=c.community_id AND m.mailbox_identity_id=c.mailbox_identity_id \
         JOIN snowman_meeting_command_receivers r ON r.community_id=c.community_id \
         JOIN snowman_workforce_identities ri ON ri.community_id=r.community_id AND ri.identity_id=r.receiver_identity_id \
         WHERE c.community_id=$1 AND c.workspace_id=$2 AND c.mailbox_identity_id=$3 \
           AND c.service_principal=$4 AND c.status='active' AND c.policy_generation=$5 \
           AND k.pubkey=$6 AND k.binding_type='service_runtime' AND k.revoked_at IS NULL \
           AND (k.expires_at IS NULL OR k.expires_at>NOW()) \
           AND i.identity_type='service' AND i.provider='snowman_service' AND i.status='active' \
           AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at>NOW()) \
           AND g.capability=$7 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>NOW()) \
           AND m.workspace_id=$2 AND m.status='active' \
           AND r.receiver_identity_id=$8 AND r.receiver_key_id=$9 AND r.status='active' \
           AND r.receiver_identity_id<>c.service_identity_id \
           AND ri.identity_type='service' AND ri.provider='snowman_service' AND ri.status='active' \
           AND ri.revoked_at IS NULL AND (ri.expires_at IS NULL OR ri.expires_at>NOW()))")
        .bind(tenant_id).bind(command.calendar_observation.workspace_id)
        .bind(command.calendar_observation.mailbox_identity_id).bind(&command.service_principal)
        .bind(command.authority.policy_generation as i64).bind(auth.pubkey.as_slice())
        .bind(REQUIRED_CAPABILITY).bind(receiver_identity_id).bind(receiver_key_id)
        .fetch_one(&mut **tx).await.map_err(|_| Error::Database)?;
    if !authorized {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

async fn apply_admission(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &MeetingCommand,
    a: &MeetingAdmission,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ApplyOutcome, Error> {
    let existing = sqlx::query(
        "SELECT provider_event_id_sha256,provider_revision,schedule_revision,status \
         FROM snowman_meetings WHERE community_id=$1 AND meeting_id=$2 FOR UPDATE",
    )
    .bind(a.tenant_id)
    .bind(a.meeting_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| Error::Database)?;
    let schedule_revision = if let Some(row) = existing {
        let provider: Vec<u8> = row
            .try_get("provider_event_id_sha256")
            .map_err(|_| Error::Database)?;
        let prior_revision: i64 = row
            .try_get("provider_revision")
            .map_err(|_| Error::Database)?;
        let status: String = row.try_get("status").map_err(|_| Error::Database)?;
        if command.command_kind != "reschedule"
            || provider != decode_digest(&a.provider_event_id_sha256)?
            || a.provider_revision <= prior_revision as u64
            || status == "cancelled"
        {
            return Err(Error::Conflict);
        }
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM snowman_meeting_commands WHERE community_id=$1 \
             AND meeting_id=$2 AND command_kind='cancel' AND provider_revision >= $3)",
        )
        .bind(a.tenant_id)
        .bind(a.meeting_id)
        .bind(a.provider_revision as i64)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| Error::Database)?;
        if blocked {
            return Err(Error::Conflict);
        }
        let next = row
            .try_get::<i64, _>("schedule_revision")
            .map_err(|_| Error::Database)?
            + 1;
        update_meeting(tx, a, next, now).await?;
        sqlx::query("UPDATE snowman_meeting_sessions SET status='stopping',updated_at=$3 \
                     WHERE community_id=$1 AND meeting_id=$2 AND status IN ('joining','awaiting_consent','active')")
            .bind(a.tenant_id).bind(a.meeting_id).bind(now).execute(&mut **tx).await.map_err(|_| Error::Database)?;
        next
    } else {
        if command.command_kind != "schedule" {
            return Err(Error::Conflict);
        }
        insert_meeting(tx, a, now).await?;
        1
    };
    insert_command(
        tx,
        CommandInsert {
            command,
            meeting_id: a.meeting_id,
            command_sha256: digest,
            provider_revision: a.provider_revision,
            schedule_revision,
            evidence_sha256: &a.admission_evidence_sha256,
            applied_at: now,
        },
    )
    .await?;
    Ok(ApplyOutcome {
        meeting_id: a.meeting_id,
        provider_event_id_sha256: a.provider_event_id_sha256.clone(),
        provider_revision: a.provider_revision,
        schedule_revision: schedule_revision as u64,
        duplicate: false,
    })
}

async fn apply_cancellation(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &MeetingCommand,
    c: &CancellationCommand,
    digest: [u8; 32],
    now: DateTime<Utc>,
) -> Result<ApplyOutcome, Error> {
    let row = sqlx::query(
        "SELECT provider_event_id_sha256,provider_revision,schedule_revision,status \
         FROM snowman_meetings WHERE community_id=$1 AND meeting_id=$2 FOR UPDATE",
    )
    .bind(c.tenant_id)
    .bind(c.meeting_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| Error::Database)?
    .ok_or(Error::Conflict)?;
    let provider: Vec<u8> = row
        .try_get("provider_event_id_sha256")
        .map_err(|_| Error::Database)?;
    let prior_revision: i64 = row
        .try_get("provider_revision")
        .map_err(|_| Error::Database)?;
    let status: String = row.try_get("status").map_err(|_| Error::Database)?;
    if provider != decode_digest(&c.provider_event_id_sha256)?
        || c.provider_revision < prior_revision as u64
        || status == "cancelled"
    {
        return Err(Error::Conflict);
    }
    let next = row
        .try_get::<i64, _>("schedule_revision")
        .map_err(|_| Error::Database)?
        + 1;
    sqlx::query("UPDATE snowman_meetings SET provider_revision=$3,schedule_revision=$4, \
                 session_generation=session_generation+1,status='cancelled',activation_enabled=FALSE,updated_at=$5 \
                 WHERE community_id=$1 AND meeting_id=$2")
        .bind(c.tenant_id).bind(c.meeting_id).bind(c.provider_revision as i64).bind(next).bind(now)
        .execute(&mut **tx).await.map_err(|_| Error::Database)?;
    sqlx::query("UPDATE snowman_meeting_sessions SET status='stopping',updated_at=$3 \
                 WHERE community_id=$1 AND meeting_id=$2 AND status IN ('joining','awaiting_consent','active')")
        .bind(c.tenant_id).bind(c.meeting_id).bind(now).execute(&mut **tx).await.map_err(|_| Error::Database)?;
    insert_command(
        tx,
        CommandInsert {
            command,
            meeting_id: c.meeting_id,
            command_sha256: digest,
            provider_revision: c.provider_revision,
            schedule_revision: next,
            evidence_sha256: &c.cancellation_evidence_sha256,
            applied_at: now,
        },
    )
    .await?;
    Ok(ApplyOutcome {
        meeting_id: c.meeting_id,
        provider_event_id_sha256: c.provider_event_id_sha256.clone(),
        provider_revision: c.provider_revision,
        schedule_revision: next as u64,
        duplicate: false,
    })
}

async fn insert_meeting(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    a: &MeetingAdmission,
    now: DateTime<Utc>,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO snowman_meetings \
      (community_id,meeting_id,workspace_id,mailbox_identity_id,meeting_agent_identity_id,parent_thread_sha256,data_class, \
       provider_event_id_sha256,provider_revision,organizer_approved,conference_kind,conference_entrypoint_sha256, \
       sealed_coordinate_ref,conference_approval_sha256,starts_at,ends_at,join_not_before,join_not_after,voice_route, \
       speech_output_route,external_processing_allowed,restricted_external_approval_sha256,processor_policy_sha256, \
       consent_policy_sha256,disclosure_required,transcription_consent_required,recording_enabled, \
       external_processing_consent_required,raw_audio_retention,transcript_retention,max_cost_microusd,max_duration_seconds, \
       source_analyst_artifact_id,source_content_sha256,admission_evidence_sha256,schedule_revision,status,activation_enabled,created_at,updated_at) \
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,TRUE,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,1,'scheduled',FALSE,$34,$34)")
        .bind(a.tenant_id).bind(a.meeting_id).bind(a.workspace_id).bind(a.mailbox_identity_id)
        .bind(a.meeting_agent_identity_id).bind(decode_digest(&a.parent_thread_sha256)?).bind(enum_json(&a.data_class)?)
        .bind(decode_digest(&a.provider_event_id_sha256)?).bind(a.provider_revision as i64)
        .bind(enum_json(&a.conference.kind)?).bind(decode_digest(&a.conference.entrypoint_sha256)?)
        .bind(&a.conference.sealed_coordinate_ref).bind(decode_digest(&a.conference.approval_evidence_sha256)?)
        .bind(a.starts_at).bind(a.ends_at).bind(a.join_not_before).bind(a.join_not_after)
        .bind(enum_json(&a.processing.voice_route)?).bind(enum_json(&a.processing.speech_output_route)?)
        .bind(a.processing.external_processing_allowed)
        .bind(optional_digest(&a.processing.restricted_external_approval_sha256)?)
        .bind(decode_digest(&a.processing.policy_evidence_sha256)?)
        .bind(decode_digest(&a.consent.policy_evidence_sha256)?)
        .bind(a.consent.transcription_consent_required).bind(a.consent.recording_enabled)
        .bind(a.consent.external_processing_consent_required).bind(enum_json(&a.consent.raw_audio_retention)?)
        .bind(enum_json(&a.consent.transcript_retention)?).bind(a.processing.max_cost_microusd as i64)
        .bind(a.processing.max_duration_seconds as i32).bind(a.source_context.artifact_id)
        .bind(decode_digest(&a.source_context.content_sha256)?).bind(decode_digest(&a.admission_evidence_sha256)?)
        .bind(now).execute(&mut **tx).await.map_err(|_| Error::Database)?;
    Ok(())
}

async fn update_meeting(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    a: &MeetingAdmission,
    rev: i64,
    now: DateTime<Utc>,
) -> Result<(), Error> {
    sqlx::query("UPDATE snowman_meetings SET provider_revision=$3,starts_at=$4,ends_at=$5,join_not_before=$6,join_not_after=$7, \
      conference_kind=$8,conference_entrypoint_sha256=$9,sealed_coordinate_ref=$10,conference_approval_sha256=$11, \
      voice_route=$12,speech_output_route=$13,external_processing_allowed=$14,restricted_external_approval_sha256=$15, \
      processor_policy_sha256=$16,consent_policy_sha256=$17,disclosure_required=TRUE,transcription_consent_required=$18, \
      recording_enabled=$19,external_processing_consent_required=$20,raw_audio_retention=$21,transcript_retention=$22, \
      max_cost_microusd=$23,max_duration_seconds=$24,source_analyst_artifact_id=$25,source_content_sha256=$26, \
      admission_evidence_sha256=$27,schedule_revision=$28,session_generation=session_generation+1,status='scheduled', \
      activation_enabled=FALSE,updated_at=$29 WHERE community_id=$1 AND meeting_id=$2")
        .bind(a.tenant_id).bind(a.meeting_id).bind(a.provider_revision as i64).bind(a.starts_at).bind(a.ends_at)
        .bind(a.join_not_before).bind(a.join_not_after).bind(enum_json(&a.conference.kind)?)
        .bind(decode_digest(&a.conference.entrypoint_sha256)?).bind(&a.conference.sealed_coordinate_ref)
        .bind(decode_digest(&a.conference.approval_evidence_sha256)?).bind(enum_json(&a.processing.voice_route)?)
        .bind(enum_json(&a.processing.speech_output_route)?).bind(a.processing.external_processing_allowed)
        .bind(optional_digest(&a.processing.restricted_external_approval_sha256)?)
        .bind(decode_digest(&a.processing.policy_evidence_sha256)?).bind(decode_digest(&a.consent.policy_evidence_sha256)?)
        .bind(a.consent.transcription_consent_required).bind(a.consent.recording_enabled)
        .bind(a.consent.external_processing_consent_required).bind(enum_json(&a.consent.raw_audio_retention)?)
        .bind(enum_json(&a.consent.transcript_retention)?).bind(a.processing.max_cost_microusd as i64)
        .bind(a.processing.max_duration_seconds as i32).bind(a.source_context.artifact_id)
        .bind(decode_digest(&a.source_context.content_sha256)?).bind(decode_digest(&a.admission_evidence_sha256)?)
        .bind(rev).bind(now).execute(&mut **tx).await.map_err(|_| Error::Database)?;
    Ok(())
}

struct CommandInsert<'a> {
    command: &'a MeetingCommand,
    meeting_id: Uuid,
    command_sha256: [u8; 32],
    provider_revision: u64,
    schedule_revision: i64,
    evidence_sha256: &'a str,
    applied_at: DateTime<Utc>,
}

async fn insert_command(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    insert: CommandInsert<'_>,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO snowman_meeting_commands \
      (community_id,command_id,meeting_id,command_kind,command_sha256,provider_revision,result_schedule_revision,evidence_sha256,applied_at) \
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(insert.command.calendar_observation.tenant_id)
        .bind(insert.command.command_id)
        .bind(insert.meeting_id)
        .bind(&insert.command.command_kind)
        .bind(insert.command_sha256.as_slice())
        .bind(insert.provider_revision as i64)
        .bind(insert.schedule_revision)
        .bind(decode_digest(insert.evidence_sha256)?)
        .bind(insert.applied_at)
        .execute(&mut **tx).await.map_err(|_| Error::Database)?;
    Ok(())
}

struct PersistReceipt<'a> {
    tenant_id: Uuid,
    command_id: Uuid,
    auth_event_id: [u8; 32],
    payload_sha256: [u8; 32],
    signature: &'a [u8],
    key_id: &'a str,
    issued_at: DateTime<Utc>,
}

async fn persist_receipt(pool: &PgPool, receipt: PersistReceipt<'_>) -> Result<(), Error> {
    sqlx::query("INSERT INTO snowman_meeting_command_receipts \
      (community_id,receipt_id,command_id,auth_event_id,receipt_payload_sha256,receiver_key_id,receiver_signature,issued_at) \
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(receipt.tenant_id)
        .bind(Uuid::new_v4())
        .bind(receipt.command_id)
        .bind(receipt.auth_event_id.as_slice())
        .bind(receipt.payload_sha256.as_slice())
        .bind(receipt.key_id)
        .bind(receipt.signature)
        .bind(receipt.issued_at)
        .execute(pool).await.map_err(|_| Error::Database)?;
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let value = serde_json::to_value(value).map_err(|_| Error::Invalid)?;
    serde_json::to_vec(&sort_value(value)).map_err(|_| Error::Invalid)
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, Error> {
    Ok(hex::encode(Sha256::digest(canonical_json(value)?)))
}

fn sort_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<_, _> = map.into_iter().map(|(k, v)| (k, sort_value(v))).collect();
            serde_json::to_value(sorted).unwrap_or(Value::Null)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_value).collect()),
        other => other,
    }
}

fn decode_digest(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = hex::decode(value).map_err(|_| Error::Invalid)?;
    if bytes.len() != 32 {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

fn optional_digest(value: &Option<String>) -> Result<Option<Vec<u8>>, Error> {
    value.as_deref().map(decode_digest).transpose()
}

fn enum_json<T: Serialize>(value: &T) -> Result<String, Error> {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(Error::Invalid)
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    value(name).ok_or(ConfigError::Invalid(name))
}
fn value(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn parse_private_origin(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::Invalid("public origin"))?;
    let host = url.host_str().unwrap_or("");
    if value != value.to_ascii_lowercase()
        || url.scheme() != "https"
        || !(host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ConfigError::Invalid("private Snowman origin"));
    }
    Ok(url)
}

fn valid_database_url(value: &str) -> bool {
    if sqlx::postgres::PgConnectOptions::from_str(value).is_err() {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let modes: Vec<_> = url
        .query_pairs()
        .filter_map(|(k, v)| (k == "sslmode").then_some(v.into_owned()))
        .collect();
    url.scheme() == "postgresql"
        && url.host_str().is_some_and(|h| {
            h.ends_with(".rds.amazonaws.com") || h.ends_with(".rds.amazonaws.com.cn")
        })
        && url.port_or_known_default() == Some(5432)
        && !url.username().is_empty()
        && url.password().is_some_and(|p| p.len() >= 32)
        && modes == ["verify-full"]
}

fn valid_kms_key_arn(value: &str) -> bool {
    let p: Vec<_> = value.split(':').collect();
    p.len() == 6
        && p[0] == "arn"
        && p[1].starts_with("aws")
        && p[2] == "kms"
        && !p[3].is_empty()
        && p[4].len() == 12
        && p[4].bytes().all(|b| b.is_ascii_digit())
        && p[5].starts_with("key/")
        && p[5].len() >= 40
}

#[derive(Debug)]
struct ApiError(Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self.0 {
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Error::Invalid => (StatusCode::BAD_REQUEST, "invalid_request"),
            Error::Conflict => (StatusCode::CONFLICT, "conflict"),
            Error::Database | Error::Signing => {
                (StatusCode::SERVICE_UNAVAILABLE, "dependency_unavailable")
            }
        };
        (status, Json(serde_json::json!({"schema_version":"snowman.meeting.command-error.v1","error":code}))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag};

    fn auth_header(keys: &Keys, url: &str, body: &[u8]) -> HeaderMap {
        let digest = hex::encode(Sha256::digest(body));
        let event = EventBuilder::new(Kind::Custom(27235), "")
            .tags([
                Tag::parse(["u", url]).unwrap(),
                Tag::parse(["method", "POST"]).unwrap(),
                Tag::parse(["payload", &digest]).unwrap(),
            ])
            .sign_with_keys(keys)
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Nostr {}", STANDARD.encode(event.as_json()))).unwrap(),
        );
        headers
    }

    #[test]
    fn auth_is_exact_to_method_url_and_body() {
        let keys = Keys::generate();
        let url = "https://meeting.staging.internal.snowmanai.org/v1/tenants/20000000-0000-4000-8000-000000000001/meeting-commands";
        let body = br#"{"schema_version":"snowman.meeting.command.v1"}"#;
        let headers = auth_header(&keys, url, body);
        assert_eq!(
            verify_auth(&headers, url, body).unwrap().pubkey,
            keys.public_key().to_bytes()
        );
        assert!(verify_auth(&headers, url, b"changed").is_err());
        assert!(verify_auth(
            &headers,
            "https://other.internal.snowmanai.org/v1/tenants/x/meeting-commands",
            body
        )
        .is_err());
    }

    #[test]
    fn configuration_rejects_non_snowman_routes_and_non_kms_keys() {
        assert!(parse_private_origin("https://meeting.staging.internal.snowmanai.org/").is_ok());
        assert!(parse_private_origin("https://api.block.xyz/").is_err());
        assert!(parse_private_origin("http://meeting.internal.snowmanai.org/").is_err());
        assert!(valid_kms_key_arn(
            "arn:aws:kms:us-west-2:625242091862:key/00000000-0000-4000-8000-000000000001"
        ));
        assert!(!valid_kms_key_arn("arn:aws:iam::625242091862:role/key"));
    }

    #[test]
    fn canonical_receipt_bytes_sort_recursively() {
        let a = serde_json::json!({"z":{"b":2,"a":1},"a":true});
        assert_eq!(
            String::from_utf8(canonical_json(&a).unwrap()).unwrap(),
            r#"{"a":true,"z":{"a":1,"b":2}}"#
        );
    }
}
