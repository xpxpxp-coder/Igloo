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
