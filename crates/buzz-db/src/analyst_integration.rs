//! Tenant-isolated Analyst 360 event ingress persistence.
//!
//! This module stores only minimized lifecycle events and receipt evidence. It
//! never reads Analyst 360 storage and never accepts a destination coordinate.

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};

use buzz_core::CommunityId;

use crate::{DbError, Result};

/// Active Analyst 360 service and asymmetric key binding for one community.
#[derive(Debug, Clone)]
pub struct AnalystIntegrationBinding {
    /// Authenticated service principal identifier.
    pub analyst_service_id: String,
    /// Analyst contract tenant identifier.
    pub tenant_id: String,
    /// Analyst contract client identifier.
    pub client_id: String,
    /// Analyst contract project identifier.
    pub project_id: String,
    /// KMS key used only to verify Analyst requests.
    pub request_kms_key_arn: String,
    /// KMS key used only to sign Command Center receipts.
    pub receipt_kms_key_arn: String,
    /// Receiver identity embedded in signed receipts.
    pub receiver_service_id: String,
}

/// Validated, minimized Analyst job event ready for idempotent persistence.
#[derive(Debug, Clone)]
pub struct NewAnalystEvent {
    /// Event identifier.
    pub event_id: String,
    /// Command identifier.
    pub command_id: String,
    /// Cross-service correlation identifier.
    pub correlation_id: String,
    /// Contract tenant identifier.
    pub tenant_id: String,
    /// Contract client identifier.
    pub client_id: String,
    /// Contract project identifier.
    pub project_id: String,
    /// Producer-observed event time.
    pub occurred_at: DateTime<Utc>,
    /// Command-local event sequence.
    pub sequence: i64,
    /// Allowlisted lifecycle status.
    pub status: String,
    /// Complete minimized event document.
    pub payload: Value,
    /// Digest claimed and validated by the event contract.
    pub event_sha256: [u8; 32],
    /// Digest of the complete canonical event document.
    pub payload_sha256: [u8; 32],
}

/// Request replay coordinates consumed with event acceptance.
#[derive(Debug, Clone)]
pub struct AnalystRequestNonce {
    /// Authenticated service principal.
    pub analyst_service_id: String,
    /// Cryptographically random request nonce.
    pub nonce: String,
    /// Digest of the complete request target.
    pub request_target_sha256: [u8; 32],
    /// Digest of the canonical body.
    pub body_sha256: [u8; 32],
    /// Assertion verification time.
    pub used_at: DateTime<Utc>,
}

/// Durable receipt evidence, when signing already completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAnalystReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Digest of the canonical unsigned receipt fields.
    pub receipt_sha256: [u8; 32],
    /// KMS signature bytes.
    pub receipt_signature: Vec<u8>,
    /// Receipt timestamp.
    pub receipt_signed_at: DateTime<Utc>,
}

/// Event acceptance state. A pending event still needs its KMS receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalystEventAcceptance {
    /// Event is durable and requires receipt signing.
    Pending,
    /// Exact event was already accepted and signed.
    Complete(StoredAnalystReceipt),
}

/// Resolve the active Analyst integration binding for one community.
pub async fn analyst_integration_binding(
    pool: &PgPool,
    community_id: CommunityId,
) -> Result<Option<AnalystIntegrationBinding>> {
    sqlx::query(
        r#"
        SELECT analyst_service_id, tenant_id, client_id, project_id,
               request_kms_key_arn, receipt_kms_key_arn, receiver_service_id
        FROM snowman_analyst_integrations
        WHERE community_id=$1 AND status='active'
        "#,
    )
    .bind(community_id.as_uuid())
    .fetch_optional(pool)
    .await?
    .map(|row| -> Result<AnalystIntegrationBinding> {
        Ok(AnalystIntegrationBinding {
            analyst_service_id: row.try_get("analyst_service_id")?,
            tenant_id: row.try_get("tenant_id")?,
            client_id: row.try_get("client_id")?,
            project_id: row.try_get("project_id")?,
            request_kms_key_arn: row.try_get("request_kms_key_arn")?,
            receipt_kms_key_arn: row.try_get("receipt_kms_key_arn")?,
            receiver_service_id: row.try_get("receiver_service_id")?,
        })
    })
    .transpose()
}

/// Consume one assertion nonce and idempotently persist its exact event.
pub async fn accept_analyst_event(
    pool: &PgPool,
    community_id: CommunityId,
    request: &AnalystRequestNonce,
    event: &NewAnalystEvent,
) -> Result<AnalystEventAcceptance> {
    let mut tx = pool.begin().await?;
    let nonce_inserted: Option<i32> = sqlx::query_scalar(
        r#"
        INSERT INTO snowman_analyst_request_nonces
          (community_id, analyst_service_id, nonce, operation,
           request_target_sha256, body_sha256, used_at, expires_at)
        VALUES ($1,$2,$3,'events.ingest',$4,$5,$6,$7)
        ON CONFLICT DO NOTHING
        RETURNING 1
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(&request.analyst_service_id)
    .bind(&request.nonce)
    .bind(request.request_target_sha256.as_slice())
    .bind(request.body_sha256.as_slice())
    .bind(request.used_at)
    .bind(request.used_at + Duration::days(1))
    .fetch_optional(&mut *tx)
    .await?;
    if nonce_inserted.is_none() {
        return Err(DbError::InvalidData(
            "Analyst service assertion nonce was already used".to_string(),
        ));
    }

    let existing = sqlx::query(
        r#"
        SELECT payload_sha256, event_sha256, receipt_id, receipt_sha256,
               receipt_signature, receipt_signed_at
        FROM snowman_analyst_events
        WHERE community_id=$1 AND event_id=$2
        FOR UPDATE
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(&event.event_id)
    .fetch_optional(&mut *tx)
    .await?;

    let outcome = if let Some(row) = existing {
        let payload_sha256: Vec<u8> = row.try_get("payload_sha256")?;
        let event_sha256: Vec<u8> = row.try_get("event_sha256")?;
        if payload_sha256.as_slice() != event.payload_sha256.as_slice()
            || event_sha256.as_slice() != event.event_sha256.as_slice()
        {
            return Err(DbError::InvalidData(
                "Analyst event identifier was reused with different content".to_string(),
            ));
        }
        receipt_from_row(&row)?.map_or(
            AnalystEventAcceptance::Pending,
            AnalystEventAcceptance::Complete,
        )
    } else {
        sqlx::query(
            r#"
            INSERT INTO snowman_analyst_events
              (community_id, event_id, command_id, correlation_id, tenant_id,
               client_id, project_id, occurred_at, sequence, status, payload,
               event_sha256, payload_sha256, received_from_service_id, received_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(&event.event_id)
        .bind(&event.command_id)
        .bind(&event.correlation_id)
        .bind(&event.tenant_id)
        .bind(&event.client_id)
        .bind(&event.project_id)
        .bind(event.occurred_at)
        .bind(event.sequence)
        .bind(&event.status)
        .bind(&event.payload)
        .bind(event.event_sha256.as_slice())
        .bind(event.payload_sha256.as_slice())
        .bind(&request.analyst_service_id)
        .bind(request.used_at)
        .execute(&mut *tx)
        .await?;
        AnalystEventAcceptance::Pending
    };
    tx.commit().await?;
    Ok(outcome)
}

/// Persist the first valid KMS receipt and return the durable winner.
pub async fn complete_analyst_receipt(
    pool: &PgPool,
    community_id: CommunityId,
    event_id: &str,
    receipt: &StoredAnalystReceipt,
) -> Result<StoredAnalystReceipt> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE snowman_analyst_events
        SET receipt_id=$3, receipt_sha256=$4, receipt_signature=$5,
            receipt_signed_at=$6
        WHERE community_id=$1 AND event_id=$2 AND receipt_id IS NULL
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(event_id)
    .bind(&receipt.receipt_id)
    .bind(receipt.receipt_sha256.as_slice())
    .bind(&receipt.receipt_signature)
    .bind(receipt.receipt_signed_at)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query(
        r#"
        SELECT payload_sha256, event_sha256, receipt_id, receipt_sha256,
               receipt_signature, receipt_signed_at
        FROM snowman_analyst_events
        WHERE community_id=$1 AND event_id=$2
        FOR UPDATE
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(event_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| DbError::InvalidData("Analyst event is missing".to_string()))?;
    let stored = receipt_from_row(&row)?
        .ok_or_else(|| DbError::InvalidData("Analyst receipt was not persisted".to_string()))?;
    tx.commit().await?;
    Ok(stored)
}

fn receipt_from_row(row: &sqlx::postgres::PgRow) -> Result<Option<StoredAnalystReceipt>> {
    let receipt_id: Option<String> = row.try_get("receipt_id")?;
    let receipt_sha256: Option<Vec<u8>> = row.try_get("receipt_sha256")?;
    let receipt_signature: Option<Vec<u8>> = row.try_get("receipt_signature")?;
    let receipt_signed_at: Option<DateTime<Utc>> = row.try_get("receipt_signed_at")?;
    match (
        receipt_id,
        receipt_sha256,
        receipt_signature,
        receipt_signed_at,
    ) {
        (None, None, None, None) => Ok(None),
        (Some(receipt_id), Some(digest), Some(receipt_signature), Some(receipt_signed_at)) => {
            let receipt_sha256: [u8; 32] = digest.try_into().map_err(|_| {
                DbError::InvalidData("Stored Analyst receipt digest is invalid".to_string())
            })?;
            Ok(Some(StoredAnalystReceipt {
                receipt_id,
                receipt_sha256,
                receipt_signature,
                receipt_signed_at,
            }))
        }
        _ => Err(DbError::InvalidData(
            "Stored Analyst receipt is incomplete".to_string(),
        )),
    }
}

impl crate::Db {
    /// Resolve the active tenant-bound Analyst integration.
    pub async fn analyst_integration_binding(
        &self,
        community_id: CommunityId,
    ) -> Result<Option<AnalystIntegrationBinding>> {
        analyst_integration_binding(&self.pool, community_id).await
    }

    /// Consume a service nonce and durably accept one minimized event.
    pub async fn accept_analyst_event(
        &self,
        community_id: CommunityId,
        request: &AnalystRequestNonce,
        event: &NewAnalystEvent,
    ) -> Result<AnalystEventAcceptance> {
        accept_analyst_event(&self.pool, community_id, request, event).await
    }

    /// Complete and return the first durable KMS receipt for an event.
    pub async fn complete_analyst_receipt(
        &self,
        community_id: CommunityId,
        event_id: &str,
        receipt: &StoredAnalystReceipt,
    ) -> Result<StoredAnalystReceipt> {
        complete_analyst_receipt(&self.pool, community_id, event_id, receipt).await
    }
}
