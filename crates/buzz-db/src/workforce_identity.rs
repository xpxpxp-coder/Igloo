//! Tenant-scoped Snowman workforce identities layered above Nostr keys.
//!
//! A Nostr signature proves possession of a key. This resolver additionally
//! requires the key to be bound to an active Snowman human session or a live,
//! capability-bounded service identity. Provider tokens and raw subject values
//! are deliberately outside this database boundary.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use buzz_core::CommunityId;

use crate::{DbError, Result};

const MAX_ACTIVE_HUMAN_DEVICES: i64 = 5;

/// Active Snowman identity-authority binding for one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkforceIdentityBroker {
    /// Stable broker principal identifier.
    pub broker_id: String,
    /// Exact external identity provider accepted by this broker.
    pub provider: String,
    /// Exact Google Workspace hosted domain.
    pub hosted_domain: String,
    /// Exact external tenant binding asserted by the Snowman authority.
    pub tenant_id: String,
    /// Exact Analyst 360 client binding.
    pub client_id: String,
    /// Exact Analyst 360 project binding.
    pub project_id: String,
    /// Assurance established by reviewed Workspace policy evidence.
    pub assurance_level: String,
    /// Digest of the reviewed assurance-policy evidence.
    pub assurance_evidence_sha256: Vec<u8>,
    /// Time at which the assurance policy was evaluated.
    pub assurance_evaluated_at: DateTime<Utc>,
    /// Exact asymmetric AWS KMS key allowed to sign enrollment assertions.
    pub signing_kms_key_arn: String,
    /// Server-side maximum lifetime for a human session.
    pub max_session_seconds: i32,
}

/// Validated human enrollment inputs accepted from the relay boundary.
#[derive(Debug, Clone)]
pub struct NewHumanWorkforceSession {
    /// One-time identity-authority assertion identifier.
    pub assertion_id: Uuid,
    /// Bound identity-authority principal.
    pub broker_id: String,
    /// Stable tenant-local Snowman workforce identity.
    pub identity_id: Uuid,
    /// Relay-generated session identifier.
    pub session_id: Uuid,
    /// SHA-256 of the canonical provider issuer and subject.
    pub provider_subject_sha256: [u8; 32],
    /// User-facing name; never an email address by contract.
    pub display_name: String,
    /// Server-recognized Snowman role.
    pub role: String,
    /// MFA or phishing-resistant authentication assurance.
    pub assurance_level: String,
    /// Time at which Google Workspace authentication completed.
    pub authenticated_at: DateTime<Utc>,
    /// Bounded absolute session expiry.
    pub expires_at: DateTime<Utc>,
    /// Nostr public key proven by the enrolling device.
    pub device_pubkey: [u8; 32],
    /// Exact signed device-proof event identifier.
    pub device_proof_event_id: [u8; 32],
    /// SHA-256 of the complete enrollment request body.
    pub assertion_body_sha256: [u8; 32],
    /// Fixed deny-by-omission capabilities derived from the role.
    pub capabilities: Vec<String>,
    /// Relay-observed enrollment time.
    pub enrolled_at: DateTime<Utc>,
}

/// Durable result of a human device enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledHumanWorkforceSession {
    /// Stable workforce identity.
    pub identity_id: Uuid,
    /// New session identifier.
    pub session_id: Uuid,
    /// Session expiry after server-side capping.
    pub expires_at: DateTime<Utc>,
    /// Effective tenant role.
    pub role: String,
}

/// Validated, authority-signed revocation of a human identity or session set.
#[derive(Debug, Clone)]
pub struct NewHumanWorkforceRevocation {
    /// One-time authority assertion identifier.
    pub assertion_id: Uuid,
    /// Bound identity-authority principal.
    pub broker_id: String,
    /// Stable tenant-local human identity.
    pub identity_id: Uuid,
    /// Domain-separated provider-subject digest used to prove identity binding.
    pub provider_subject_sha256: [u8; 32],
    /// One session for `session`, otherwise `None`.
    pub session_id: Option<Uuid>,
    /// `session`, `all_sessions`, or permanent `identity` revocation.
    pub revocation_scope: String,
    /// Bounded receiver-approved lifecycle reason.
    pub reason: String,
    /// SHA-256 of the complete revocation request body.
    pub assertion_body_sha256: [u8; 32],
    /// Receiver-observed revocation time.
    pub revoked_at: DateTime<Utc>,
}

/// Counts returned from an atomic human workforce revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanWorkforceRevocationResult {
    /// Stable affected identity.
    pub identity_id: Uuid,
    /// Number of live sessions revoked.
    pub revoked_session_count: u64,
    /// Number of live device bindings revoked.
    pub revoked_device_count: u64,
    /// Number of live role grants revoked.
    pub revoked_grant_count: u64,
    /// Number of broker-owned relay memberships removed.
    pub revoked_member_count: u64,
    /// Whether the identity itself is now permanently revoked.
    pub identity_revoked: bool,
}

/// Load one active, tenant-scoped Snowman identity-authority binding.
pub async fn workforce_identity_broker(
    pool: &PgPool,
    community_id: CommunityId,
    broker_id: &str,
) -> Result<Option<WorkforceIdentityBroker>> {
    let row = sqlx::query(
        r#"
        SELECT broker_id, provider, hosted_domain, tenant_id, client_id,
               project_id, assurance_level, assurance_evidence_sha256,
               assurance_evaluated_at, signing_kms_key_arn, max_session_seconds
        FROM snowman_workforce_identity_brokers
        WHERE community_id=$1 AND broker_id=$2 AND status='active'
          AND revoked_at IS NULL
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(broker_id)
    .fetch_optional(pool)
    .await?;

    row.map(
        |row| -> std::result::Result<WorkforceIdentityBroker, sqlx::Error> {
            Ok(WorkforceIdentityBroker {
                broker_id: row.try_get("broker_id")?,
                provider: row.try_get("provider")?,
                hosted_domain: row.try_get("hosted_domain")?,
                tenant_id: row.try_get("tenant_id")?,
                client_id: row.try_get("client_id")?,
                project_id: row.try_get("project_id")?,
                assurance_level: row.try_get("assurance_level")?,
                assurance_evidence_sha256: row.try_get("assurance_evidence_sha256")?,
                assurance_evaluated_at: row.try_get("assurance_evaluated_at")?,
                signing_kms_key_arn: row.try_get("signing_kms_key_arn")?,
                max_session_seconds: row.try_get("max_session_seconds")?,
            })
        },
    )
    .transpose()
    .map_err(DbError::from)
}

/// Atomically consume an identity assertion and enroll or rotate one human device.
///
/// This is the only writer for identity-broker-owned human identities. The
/// transaction creates no access from a raw provider token: the caller has
/// already verified the bound KMS assertion and device signature.
pub async fn enroll_human_workforce_session(
    pool: &PgPool,
    community_id: CommunityId,
    enrollment: &NewHumanWorkforceSession,
) -> Result<EnrolledHumanWorkforceSession> {
    if enrollment.assertion_id.is_nil()
        || enrollment.identity_id.is_nil()
        || enrollment.session_id.is_nil()
        || enrollment.device_pubkey == [0; 32]
        || enrollment.capabilities.is_empty()
    {
        return Err(DbError::InvalidData(
            "Snowman human enrollment contains an invalid identifier".into(),
        ));
    }
    let mut tx = pool.begin().await?;

    let identity = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO snowman_workforce_identities
          (community_id, identity_id, identity_type, provider,
           provider_subject_sha256, display_name, role, status, created_at,
           updated_at, provisioning_authority)
        VALUES ($1,$2,'human','google_workspace',$3,$4,$5,'active',$6,$6,'identity_broker')
        ON CONFLICT (community_id, provider, provider_subject_sha256) DO UPDATE SET
          display_name=EXCLUDED.display_name,
          role=EXCLUDED.role,
          updated_at=EXCLUDED.updated_at
        WHERE snowman_workforce_identities.identity_id=EXCLUDED.identity_id
          AND snowman_workforce_identities.identity_type='human'
          AND snowman_workforce_identities.status='active'
          AND snowman_workforce_identities.revoked_at IS NULL
          AND (snowman_workforce_identities.provisioning_authority IS NULL
               OR snowman_workforce_identities.provisioning_authority='identity_broker')
        RETURNING identity_id
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(enrollment.identity_id)
    .bind(enrollment.provider_subject_sha256.as_slice())
    .bind(&enrollment.display_name)
    .bind(&enrollment.role)
    .bind(enrollment.enrolled_at)
    .fetch_optional(&mut *tx)
    .await?;
    if identity != Some(enrollment.identity_id) {
        return Err(DbError::InvalidData(
            "Snowman provider identity conflicts with an existing authority".into(),
        ));
    }

    let other_devices = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM snowman_workforce_sessions
        WHERE community_id=$1 AND identity_id=$2 AND revoked_at IS NULL
          AND expires_at > $3 AND device_pubkey <> $4
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(enrollment.identity_id)
    .bind(enrollment.enrolled_at)
    .bind(enrollment.device_pubkey.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    if other_devices >= MAX_ACTIVE_HUMAN_DEVICES {
        return Err(DbError::InvalidData(
            "Snowman human identity reached the active device limit".into(),
        ));
    }

    sqlx::query(
        r#"
        UPDATE snowman_workforce_sessions
        SET revoked_at=$3, revocation_reason='device_session_rotated'
        WHERE community_id=$1 AND identity_id=$2 AND device_pubkey=$4
          AND revoked_at IS NULL
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(enrollment.identity_id)
    .bind(enrollment.enrolled_at)
    .bind(enrollment.device_pubkey.as_slice())
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO snowman_workforce_sessions
          (community_id, session_id, identity_id, device_pubkey,
           assurance_level, authenticated_at, last_seen_at, expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(enrollment.session_id)
    .bind(enrollment.identity_id)
    .bind(enrollment.device_pubkey.as_slice())
    .bind(&enrollment.assurance_level)
    .bind(enrollment.authenticated_at)
    .bind(enrollment.enrolled_at)
    .bind(enrollment.expires_at)
    .execute(&mut *tx)
    .await?;

    let binding = sqlx::query(
        r#"
        INSERT INTO snowman_workforce_key_bindings
          (community_id, pubkey, identity_id, binding_type, session_id,
           bound_at, expires_at, revoked_at)
        VALUES ($1,$2,$3,'human_device',$4,$5,$6,NULL)
        ON CONFLICT (community_id, pubkey) DO UPDATE SET
          session_id=EXCLUDED.session_id,
          bound_at=EXCLUDED.bound_at,
          expires_at=EXCLUDED.expires_at,
          revoked_at=NULL
        WHERE snowman_workforce_key_bindings.identity_id=EXCLUDED.identity_id
          AND snowman_workforce_key_bindings.binding_type='human_device'
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(enrollment.device_pubkey.as_slice())
    .bind(enrollment.identity_id)
    .bind(enrollment.session_id)
    .bind(enrollment.enrolled_at)
    .bind(enrollment.expires_at)
    .execute(&mut *tx)
    .await?;
    if binding.rows_affected() != 1 {
        return Err(DbError::InvalidData(
            "Snowman relay key is already bound to another identity".into(),
        ));
    }

    sqlx::query(
        "UPDATE snowman_workforce_capability_grants SET revoked_at=$3 \
         WHERE community_id=$1 AND identity_id=$2 AND grant_source='role_policy' \
           AND revoked_at IS NULL",
    )
    .bind(community_id.as_uuid())
    .bind(enrollment.identity_id)
    .bind(enrollment.enrolled_at)
    .execute(&mut *tx)
    .await?;
    for capability in &enrollment.capabilities {
        sqlx::query(
            r#"
            INSERT INTO snowman_workforce_capability_grants
              (community_id, grant_id, identity_id, capability, grant_source,
               granted_at, expires_at)
            VALUES ($1,$2,$3,$4,'role_policy',$5,$6)
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(Uuid::new_v4())
        .bind(enrollment.identity_id)
        .bind(capability)
        .bind(enrollment.enrolled_at)
        .bind(enrollment.expires_at)
        .execute(&mut *tx)
        .await?;
    }

    let pubkey_hex = hex::encode(enrollment.device_pubkey);
    sqlx::query(
        r#"
        INSERT INTO users (community_id, pubkey, display_name)
        VALUES ($1,$2,$3)
        ON CONFLICT (community_id, pubkey) DO UPDATE SET
          display_name=EXCLUDED.display_name
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(enrollment.device_pubkey.as_slice())
    .bind(&enrollment.display_name)
    .execute(&mut *tx)
    .await?;
    let member = sqlx::query(
        r#"
        INSERT INTO relay_members (community_id, pubkey, role, added_by)
        VALUES ($1,$2,$3,'snowman_identity_broker')
        ON CONFLICT (community_id, pubkey) DO UPDATE SET
          role=EXCLUDED.role,
          updated_at=$4
        WHERE relay_members.role=EXCLUDED.role
           OR relay_members.added_by='snowman_identity_broker'
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(pubkey_hex)
    .bind(&enrollment.role)
    .bind(enrollment.enrolled_at)
    .execute(&mut *tx)
    .await?;
    if member.rows_affected() != 1 {
        return Err(DbError::InvalidData(
            "Snowman relay membership role conflicts with another authority".into(),
        ));
    }

    let receipt = sqlx::query(
        r#"
        INSERT INTO snowman_workforce_enrollment_receipts
          (community_id, assertion_id, broker_id, identity_id, session_id,
           provider_subject_sha256, device_pubkey, assertion_body_sha256,
           device_proof_event_id, role, assurance_level, authenticated_at,
           expires_at, enrolled_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        ON CONFLICT (community_id, assertion_id) DO NOTHING
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(enrollment.assertion_id)
    .bind(&enrollment.broker_id)
    .bind(enrollment.identity_id)
    .bind(enrollment.session_id)
    .bind(enrollment.provider_subject_sha256.as_slice())
    .bind(enrollment.device_pubkey.as_slice())
    .bind(enrollment.assertion_body_sha256.as_slice())
    .bind(enrollment.device_proof_event_id.as_slice())
    .bind(&enrollment.role)
    .bind(&enrollment.assurance_level)
    .bind(enrollment.authenticated_at)
    .bind(enrollment.expires_at)
    .bind(enrollment.enrolled_at)
    .execute(&mut *tx)
    .await?;
    if receipt.rows_affected() != 1 {
        return Err(DbError::InvalidData(
            "Snowman workforce enrollment assertion was already used".into(),
        ));
    }

    tx.commit().await?;
    Ok(EnrolledHumanWorkforceSession {
        identity_id: enrollment.identity_id,
        session_id: enrollment.session_id,
        expires_at: enrollment.expires_at,
        role: enrollment.role.clone(),
    })
}

/// Atomically revoke one device session, every session, or the human identity.
pub async fn revoke_human_workforce_session(
    pool: &PgPool,
    community_id: CommunityId,
    revocation: &NewHumanWorkforceRevocation,
) -> Result<HumanWorkforceRevocationResult> {
    if revocation.assertion_id.is_nil()
        || revocation.identity_id.is_nil()
        || revocation.broker_id.trim().is_empty()
        || !matches!(
            revocation.reason.as_str(),
            "user_logout"
                | "device_removed"
                | "global_logout"
                | "identity_inactive"
                | "assignment_changed"
                | "security_response"
        )
        || !matches!(
            revocation.revocation_scope.as_str(),
            "session" | "all_sessions" | "identity"
        )
        || (revocation.revocation_scope == "session") != revocation.session_id.is_some()
    {
        return Err(DbError::InvalidData(
            "Snowman human revocation contains an invalid target".into(),
        ));
    }
    let mut tx = pool.begin().await?;
    let identity = sqlx::query(
        r#"
        SELECT identity_id, identity_type, provisioning_authority
        FROM snowman_workforce_identities
        WHERE community_id=$1 AND provider='google_workspace'
          AND provider_subject_sha256=$2
        FOR UPDATE
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(revocation.provider_subject_sha256.as_slice())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(identity) = identity else {
        return Err(DbError::InvalidData(
            "Snowman human revocation identity is not enrolled".into(),
        ));
    };
    let stored_identity: Uuid = identity.try_get("identity_id")?;
    let identity_type: String = identity.try_get("identity_type")?;
    let authority: Option<String> = identity.try_get("provisioning_authority")?;
    if stored_identity != revocation.identity_id
        || identity_type != "human"
        || authority.as_deref() != Some("identity_broker")
    {
        return Err(DbError::InvalidData(
            "Snowman human revocation conflicts with identity authority".into(),
        ));
    }
    if let Some(session_id) = revocation.session_id {
        let belongs: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM snowman_workforce_sessions \
             WHERE community_id=$1 AND identity_id=$2 AND session_id=$3)",
        )
        .bind(community_id.as_uuid())
        .bind(revocation.identity_id)
        .bind(session_id)
        .fetch_one(&mut *tx)
        .await?;
        if !belongs {
            return Err(DbError::InvalidData(
                "Snowman human revocation session is not bound to the identity".into(),
            ));
        }
    }

    let receipt = sqlx::query(
        r#"
        INSERT INTO snowman_workforce_revocation_receipts
          (community_id, assertion_id, broker_id, identity_id, session_id,
           revocation_scope, reason, assertion_body_sha256,
           revoked_session_count, revoked_device_count, revoked_grant_count,
           revoked_member_count, revoked_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,0,0,0,$9)
        ON CONFLICT (community_id, assertion_id) DO NOTHING
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(revocation.assertion_id)
    .bind(&revocation.broker_id)
    .bind(revocation.identity_id)
    .bind(revocation.session_id)
    .bind(&revocation.revocation_scope)
    .bind(&revocation.reason)
    .bind(revocation.assertion_body_sha256.as_slice())
    .bind(revocation.revoked_at)
    .execute(&mut *tx)
    .await?;
    if receipt.rows_affected() != 1 {
        return Err(DbError::InvalidData(
            "Snowman workforce revocation assertion was already used".into(),
        ));
    }

    let device_rows = if let Some(session_id) = revocation.session_id {
        sqlx::query(
            "SELECT device_pubkey FROM snowman_workforce_sessions \
             WHERE community_id=$1 AND identity_id=$2 AND session_id=$3 \
               AND revoked_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(revocation.identity_id)
        .bind(session_id)
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query(
            "SELECT DISTINCT device_pubkey FROM snowman_workforce_sessions \
             WHERE community_id=$1 AND identity_id=$2 AND revoked_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(revocation.identity_id)
        .fetch_all(&mut *tx)
        .await?
    };
    let device_pubkeys = device_rows
        .iter()
        .map(|row| row.try_get::<Vec<u8>, _>("device_pubkey"))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let sessions = if let Some(session_id) = revocation.session_id {
        sqlx::query(
            "UPDATE snowman_workforce_sessions SET revoked_at=$4, revocation_reason=$5 \
             WHERE community_id=$1 AND identity_id=$2 AND session_id=$3 \
               AND revoked_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(revocation.identity_id)
        .bind(session_id)
        .bind(revocation.revoked_at)
        .bind(&revocation.reason)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    } else {
        sqlx::query(
            "UPDATE snowman_workforce_sessions SET revoked_at=$3, revocation_reason=$4 \
             WHERE community_id=$1 AND identity_id=$2 AND revoked_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(revocation.identity_id)
        .bind(revocation.revoked_at)
        .bind(&revocation.reason)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    };
    let bindings = if let Some(session_id) = revocation.session_id {
        sqlx::query(
            "UPDATE snowman_workforce_key_bindings SET revoked_at=$4 \
             WHERE community_id=$1 AND identity_id=$2 AND session_id=$3 \
               AND binding_type='human_device' AND revoked_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(revocation.identity_id)
        .bind(session_id)
        .bind(revocation.revoked_at)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    } else {
        sqlx::query(
            "UPDATE snowman_workforce_key_bindings SET revoked_at=$3 \
             WHERE community_id=$1 AND identity_id=$2 \
               AND binding_type='human_device' AND revoked_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(revocation.identity_id)
        .bind(revocation.revoked_at)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    };
    let remaining_sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM snowman_workforce_sessions \
         WHERE community_id=$1 AND identity_id=$2 AND revoked_at IS NULL \
           AND expires_at > $3",
    )
    .bind(community_id.as_uuid())
    .bind(revocation.identity_id)
    .bind(revocation.revoked_at)
    .fetch_one(&mut *tx)
    .await?;
    let grants = if remaining_sessions == 0 {
        sqlx::query(
            "UPDATE snowman_workforce_capability_grants SET revoked_at=$3 \
             WHERE community_id=$1 AND identity_id=$2 AND grant_source='role_policy' \
               AND revoked_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(revocation.identity_id)
        .bind(revocation.revoked_at)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    } else {
        0
    };
    let mut members = 0_u64;
    for pubkey in &device_pubkeys {
        members += sqlx::query(
            "DELETE FROM relay_members WHERE community_id=$1 AND pubkey=$2 \
             AND added_by='snowman_identity_broker'",
        )
        .bind(community_id.as_uuid())
        .bind(hex::encode(pubkey))
        .execute(&mut *tx)
        .await?
        .rows_affected();
    }
    let identity_revoked = revocation.revocation_scope == "identity";
    if identity_revoked {
        sqlx::query(
            "UPDATE snowman_workforce_identities \
             SET status='revoked', revoked_at=COALESCE(revoked_at,$3), updated_at=$3 \
             WHERE community_id=$1 AND identity_id=$2 AND identity_type='human'",
        )
        .bind(community_id.as_uuid())
        .bind(revocation.identity_id)
        .bind(revocation.revoked_at)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE snowman_workforce_revocation_receipts SET \
           revoked_session_count=$3, revoked_device_count=$4, \
           revoked_grant_count=$5, revoked_member_count=$6 \
         WHERE community_id=$1 AND assertion_id=$2",
    )
    .bind(community_id.as_uuid())
    .bind(revocation.assertion_id)
    .bind(i64::try_from(sessions).unwrap_or(i64::MAX))
    .bind(i64::try_from(bindings).unwrap_or(i64::MAX))
    .bind(i64::try_from(grants).unwrap_or(i64::MAX))
    .bind(i64::try_from(members).unwrap_or(i64::MAX))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(HumanWorkforceRevocationResult {
        identity_id: revocation.identity_id,
        revoked_session_count: sessions,
        revoked_device_count: bindings,
        revoked_grant_count: grants,
        revoked_member_count: members,
        identity_revoked,
    })
}

/// The governed principal resolved for a tenant and cryptographic relay key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkforcePrincipal {
    /// Stable tenant-scoped identity ID.
    pub identity_id: Uuid,
    /// `human` or `service`.
    pub identity_type: String,
    /// Snowman role used for relay scope derivation.
    pub role: String,
    /// Active fine-grained capabilities, deny-by-omission.
    pub capabilities: Vec<String>,
    /// Live human session ID; service identities have no interactive session.
    pub session_id: Option<Uuid>,
    /// Earliest applicable identity, binding, or session expiry.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Resolve one live Snowman workforce principal from its signed relay key.
///
/// Returns `None` for unknown, expired, suspended, or revoked identities. Human
/// device keys additionally require a live, non-revoked session bound to the
/// same identity and key. Service runtime keys never inherit a human session.
pub async fn resolve_workforce_principal(
    pool: &PgPool,
    community_id: CommunityId,
    pubkey: &[u8],
) -> Result<Option<WorkforcePrincipal>> {
    if pubkey.len() != 32 {
        return Err(DbError::InvalidData(
            "Snowman workforce relay pubkey must be exactly 32 bytes".into(),
        ));
    }
    let row = sqlx::query(
        r#"
        SELECT i.identity_id, i.identity_type, i.role, b.session_id,
               LEAST(i.expires_at, b.expires_at, s.expires_at) AS expires_at,
               COALESCE(array_agg(DISTINCT g.capability)
                 FILTER (WHERE g.capability IS NOT NULL), '{}') AS capabilities
        FROM snowman_workforce_key_bindings b
        JOIN snowman_workforce_identities i
          ON i.community_id=b.community_id AND i.identity_id=b.identity_id
        LEFT JOIN snowman_workforce_sessions s
          ON s.community_id=b.community_id AND s.identity_id=b.identity_id
         AND s.session_id=b.session_id
        LEFT JOIN snowman_workforce_capability_grants g
          ON g.community_id=i.community_id AND g.identity_id=i.identity_id
         AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > NOW())
        WHERE b.community_id=$1 AND b.pubkey=$2
          AND b.revoked_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > NOW())
          AND i.status='active' AND i.revoked_at IS NULL
          AND (i.expires_at IS NULL OR i.expires_at > NOW())
          AND (
            (i.identity_type='human' AND b.binding_type='human_device'
              AND s.session_id IS NOT NULL AND s.device_pubkey=b.pubkey
              AND s.revoked_at IS NULL AND s.expires_at > NOW())
            OR
            (i.identity_type='service' AND b.binding_type='service_runtime'
              AND b.session_id IS NULL AND s.session_id IS NULL)
          )
        GROUP BY i.identity_id, i.identity_type, i.role, b.session_id,
                 i.expires_at, b.expires_at, s.expires_at
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(pubkey)
    .fetch_optional(pool)
    .await?;

    row.map(
        |row| -> std::result::Result<WorkforcePrincipal, sqlx::Error> {
            Ok(WorkforcePrincipal {
                identity_id: row.try_get("identity_id")?,
                identity_type: row.try_get("identity_type")?,
                role: row.try_get("role")?,
                capabilities: row.try_get("capabilities")?,
                session_id: row.try_get("session_id")?,
                expires_at: row.try_get("expires_at")?,
            })
        },
    )
    .transpose()
    .map_err(DbError::from)
}

/// Verify that a tenant-local service identity is active, agent-scoped, and
/// holds one exact capability before a task is assigned to it.
pub async fn active_service_identity_has_capability(
    pool: &PgPool,
    community_id: CommunityId,
    identity_id: Uuid,
    capability: &str,
) -> Result<bool> {
    if identity_id.is_nil() || capability.trim().is_empty() {
        return Ok(false);
    }
    sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1
          FROM snowman_workforce_identities i
          JOIN snowman_workforce_capability_grants g
            ON g.community_id=i.community_id AND g.identity_id=i.identity_id
          WHERE i.community_id=$1 AND i.identity_id=$2
            AND i.identity_type='service' AND i.role='agent' AND i.status='active'
            AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
            AND g.capability=$3 AND g.revoked_at IS NULL
            AND (g.expires_at IS NULL OR g.expires_at > NOW())
        )
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(identity_id)
    .bind(capability)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_pubkey_fails_before_database_access() {
        let pool =
            PgPool::connect_lazy("postgres://unused:unused@localhost/unused").expect("lazy pool");
        let result =
            resolve_workforce_principal(&pool, CommunityId::from_uuid(Uuid::new_v4()), &[0_u8; 31])
                .await;
        assert!(matches!(result, Err(DbError::InvalidData(_))));
    }
}
