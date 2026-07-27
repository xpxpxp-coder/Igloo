use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use buzz_audit::AuditService;
use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::model::{CheckpointEnvelope, CheckpointPayload};

/// Audit-checkpoint errors intentionally omit payloads, tenant IDs and object bodies.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    /// A checkpoint failed strict schema, digest, sequence or coordinate validation.
    #[error("invalid audit checkpoint")]
    InvalidCheckpoint,
    /// Canonical serialization failed.
    #[error("audit checkpoint serialization failed")]
    Serialization,
    /// The externally retained history conflicts with itself or PostgreSQL.
    #[error("audit checkpoint integrity violation")]
    IntegrityViolation,
    /// The KMS signature is absent or invalid.
    #[error("audit checkpoint signature verification failed")]
    SignatureInvalid,
    /// An external provider operation failed; details stay in provider-safe logs.
    #[error("audit checkpoint provider operation failed")]
    Provider,
    /// A database operation failed.
    #[error("audit checkpoint database operation failed")]
    Database(#[from] sqlx::Error),
    /// The underlying audit chain failed validation.
    #[error("audit hash chain verification failed")]
    Audit(#[from] buzz_audit::AuditError),
}

/// Immutable object metadata returned without its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    /// Exact bucket-relative key.
    pub key: String,
    /// S3 version ID required for recovery evidence.
    pub version_id: String,
}

/// Result of publishing or reconciling a tenant checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// A new immutable version was successfully retained.
    Published(StoredObject),
    /// The exact object already existed, including ambiguous-write recovery.
    Recovered(StoredObject),
    /// No new audit sequence existed; the current anchor was reverified.
    Current(StoredObject),
    /// A tenant has no audit rows yet.
    Empty,
}

/// Asymmetric digest-signing boundary. Implementations must keep private keys non-exportable.
#[async_trait]
pub trait CheckpointSigner: Send + Sync {
    /// Sign exactly one SHA-256 digest using the exact configured key.
    async fn sign_digest(
        &self,
        key_arn: &str,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, CheckpointError>;
    /// Verify a digest/signature pair with the exact key named in the payload.
    async fn verify_digest(
        &self,
        key_arn: &str,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), CheckpointError>;
}

/// Append-only immutable object boundary used by publisher and recovery verifier.
#[async_trait]
pub trait ImmutableObjectStore: Send + Sync {
    /// List immutable object versions below a prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<StoredObject>, CheckpointError>;
    /// Read an exact object version.
    async fn get(&self, object: &StoredObject) -> Result<Vec<u8>, CheckpointError>;
    /// Create the key only if absent, returning `None` on a precondition conflict.
    async fn put_if_absent(
        &self,
        key: &str,
        body: &[u8],
        body_sha256: &[u8; 32],
    ) -> Result<Option<StoredObject>, CheckpointError>;
}

/// Minimal database boundary for tenant audit heads and append-only receipts.
#[async_trait]
pub trait CheckpointRepository: Send + Sync {
    /// List exact community identifiers without names or tenant content.
    async fn communities(&self) -> Result<Vec<Uuid>, CheckpointError>;
    /// Return `(sequence, root hash)` for one tenant, if any.
    async fn head(&self, community_id: Uuid) -> Result<Option<(i64, [u8; 32])>, CheckpointError>;
    /// Verify one segment against its externally anchored predecessor.
    async fn verify_segment(
        &self,
        community_id: Uuid,
        from_seq: i64,
        to_seq: i64,
        expected_previous: Option<[u8; 32]>,
    ) -> Result<[u8; 32], CheckpointError>;
    /// Freeze or return the one canonical payload for this tenant/sequence.
    async fn reserve_payload(
        &self,
        payload: &CheckpointPayload,
    ) -> Result<CheckpointPayload, CheckpointError>;
    /// Append a minimized publication receipt. Exact replay is idempotent.
    async fn record_publication(
        &self,
        envelope: &CheckpointEnvelope,
        object: &StoredObject,
    ) -> Result<(), CheckpointError>;
}

/// PostgreSQL implementation restricted to audit reads and checkpoint inserts.
pub struct PostgresCheckpointRepository {
    pool: PgPool,
    audit: AuditService,
}

impl PostgresCheckpointRepository {
    /// Build a repository over the dedicated least-privilege pool.
    pub fn new(pool: PgPool) -> Self {
        Self {
            audit: AuditService::new(pool.clone()),
            pool,
        }
    }
}

#[async_trait]
impl CheckpointRepository for PostgresCheckpointRepository {
    async fn communities(&self) -> Result<Vec<Uuid>, CheckpointError> {
        Ok(sqlx::query_scalar("SELECT id FROM communities ORDER BY id")
            .fetch_all(&self.pool)
            .await?)
    }

    async fn head(&self, community_id: Uuid) -> Result<Option<(i64, [u8; 32])>, CheckpointError> {
        let row = sqlx::query(
            "SELECT seq,hash FROM audit_log WHERE community_id=$1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(community_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let hash: Vec<u8> = row.get("hash");
        let root: [u8; 32] = hash
            .try_into()
            .map_err(|_| CheckpointError::IntegrityViolation)?;
        Ok(Some((row.get("seq"), root)))
    }

    async fn verify_segment(
        &self,
        community_id: Uuid,
        from_seq: i64,
        to_seq: i64,
        expected_previous: Option<[u8; 32]>,
    ) -> Result<[u8; 32], CheckpointError> {
        self.audit
            .verify_segment(
                CommunityId::from_uuid(community_id),
                from_seq,
                to_seq,
                expected_previous,
            )
            .await
            .map_err(CheckpointError::Audit)
    }

    async fn reserve_payload(
        &self,
        payload: &CheckpointPayload,
    ) -> Result<CheckpointPayload, CheckpointError> {
        payload.validate()?;
        sqlx::query(
            r#"INSERT INTO snowman_audit_checkpoint_requests
              (community_id,sequence,chain_root_sha256,previous_checkpoint_sha256,
               signed_at,build_sha256,database_schema_sha256,signing_key_arn)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT (community_id,sequence) DO NOTHING"#,
        )
        .bind(payload.community_id)
        .bind(payload.sequence)
        .bind(
            hex::decode(&payload.chain_root_sha256)
                .map_err(|_| CheckpointError::InvalidCheckpoint)?,
        )
        .bind(
            payload
                .previous_checkpoint_sha256
                .as_deref()
                .map(hex::decode)
                .transpose()
                .map_err(|_| CheckpointError::InvalidCheckpoint)?,
        )
        .bind(&payload.signed_at)
        .bind(hex::decode(&payload.build_sha256).map_err(|_| CheckpointError::InvalidCheckpoint)?)
        .bind(
            hex::decode(&payload.database_schema_sha256)
                .map_err(|_| CheckpointError::InvalidCheckpoint)?,
        )
        .bind(&payload.signing_key_arn)
        .execute(&self.pool)
        .await?;

        let row = sqlx::query(
            r#"SELECT chain_root_sha256,previous_checkpoint_sha256,signed_at,
                      build_sha256,database_schema_sha256,signing_key_arn
               FROM snowman_audit_checkpoint_requests
               WHERE community_id=$1 AND sequence=$2"#,
        )
        .bind(payload.community_id)
        .bind(payload.sequence)
        .fetch_one(&self.pool)
        .await?;
        let reserved = CheckpointPayload {
            schema_version: payload.schema_version.clone(),
            community_id: payload.community_id,
            sequence: payload.sequence,
            chain_root_sha256: hex::encode(row.get::<Vec<u8>, _>("chain_root_sha256")),
            previous_checkpoint_sha256: row
                .get::<Option<Vec<u8>>, _>("previous_checkpoint_sha256")
                .map(hex::encode),
            signed_at: row.get("signed_at"),
            build_sha256: hex::encode(row.get::<Vec<u8>, _>("build_sha256")),
            database_schema_sha256: hex::encode(row.get::<Vec<u8>, _>("database_schema_sha256")),
            signing_key_arn: row.get("signing_key_arn"),
        };
        reserved.validate()?;
        if reserved != *payload {
            return Err(CheckpointError::IntegrityViolation);
        }
        Ok(reserved)
    }

    async fn record_publication(
        &self,
        envelope: &CheckpointEnvelope,
        object: &StoredObject,
    ) -> Result<(), CheckpointError> {
        let object_sha = envelope.object_digest()?;
        let result = sqlx::query(
            r#"INSERT INTO snowman_audit_checkpoint_publications
              (community_id,sequence,checkpoint_sha256,previous_checkpoint_sha256,
               object_key,object_version_id,kms_key_arn,signed_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT (community_id,sequence,checkpoint_sha256) DO NOTHING"#,
        )
        .bind(envelope.payload.community_id)
        .bind(envelope.payload.sequence)
        .bind(object_sha.as_slice())
        .bind(
            envelope
                .payload
                .previous_checkpoint_sha256
                .as_deref()
                .map(hex::decode)
                .transpose()
                .map_err(|_| CheckpointError::InvalidCheckpoint)?,
        )
        .bind(&object.key)
        .bind(&object.version_id)
        .bind(&envelope.payload.signing_key_arn)
        .bind(&envelope.payload.signed_at)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            let exact: bool = sqlx::query_scalar(
                r#"SELECT EXISTS(
                   SELECT 1 FROM snowman_audit_checkpoint_publications
                    WHERE community_id=$1 AND sequence=$2 AND checkpoint_sha256=$3
                      AND object_key=$4 AND object_version_id=$5)"#,
            )
            .bind(envelope.payload.community_id)
            .bind(envelope.payload.sequence)
            .bind(object_sha.as_slice())
            .bind(&object.key)
            .bind(&object.version_id)
            .fetch_one(&self.pool)
            .await?;
            if !exact {
                return Err(CheckpointError::IntegrityViolation);
            }
        }
        Ok(())
    }
}

/// Publisher and recovery verifier over explicit database, KMS and object boundaries.
pub struct AuditCheckpointService<R, S, O> {
    repository: R,
    signer: S,
    store: O,
    signing_key_arn: String,
    build_sha256: String,
    database_schema_sha256: String,
}

impl<R, S, O> AuditCheckpointService<R, S, O>
where
    R: CheckpointRepository,
    S: CheckpointSigner,
    O: ImmutableObjectStore,
{
    /// Construct a service bound to exact build, schema and signing-key digests.
    pub fn new(
        repository: R,
        signer: S,
        store: O,
        signing_key_arn: String,
        build_sha256: String,
        database_schema_sha256: String,
    ) -> Result<Self, CheckpointError> {
        let probe = CheckpointPayload::new(
            Uuid::nil(),
            1,
            "00".repeat(32),
            None,
            Utc::now(),
            build_sha256.clone(),
            database_schema_sha256.clone(),
            signing_key_arn.clone(),
        )?;
        probe.validate()?;
        Ok(Self {
            repository,
            signer,
            store,
            signing_key_arn,
            build_sha256,
            database_schema_sha256,
        })
    }

    /// Verify all object-store tenants against PostgreSQL, then publish every new head.
    pub async fn publish_all(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<PublishOutcome>, CheckpointError> {
        self.verify_all().await?;
        let mut outcomes = Vec::new();
        for community in self.repository.communities().await? {
            outcomes.push(self.publish_community(community, now).await?);
        }
        Ok(outcomes)
    }

    /// Publish or reconcile one tenant without exposing its audit content.
    pub async fn publish_community(
        &self,
        community_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<PublishOutcome, CheckpointError> {
        let latest = self.latest_for_community(community_id).await?;
        let Some((sequence, root)) = self.repository.head(community_id).await? else {
            return if latest.is_none() {
                Ok(PublishOutcome::Empty)
            } else {
                Err(CheckpointError::IntegrityViolation)
            };
        };
        if let Some((envelope, object)) = &latest {
            if sequence < envelope.payload.sequence {
                return Err(CheckpointError::IntegrityViolation);
            }
            self.verify_anchor_against_database(envelope).await?;
            if sequence == envelope.payload.sequence {
                if hex::encode(root) != envelope.payload.chain_root_sha256 {
                    return Err(CheckpointError::IntegrityViolation);
                }
                return Ok(PublishOutcome::Current(object.clone()));
            }
        }
        let (from_seq, expected_previous, previous_checkpoint_sha256) = match &latest {
            Some((envelope, _)) => (
                envelope.payload.sequence + 1,
                Some(decode_digest(&envelope.payload.chain_root_sha256)?),
                Some(hex::encode(envelope.object_digest()?)),
            ),
            None => (1, None, None),
        };
        let verified_root = self
            .repository
            .verify_segment(community_id, from_seq, sequence, expected_previous)
            .await?;
        if verified_root != root {
            return Err(CheckpointError::IntegrityViolation);
        }
        let payload = CheckpointPayload::new(
            community_id,
            sequence,
            hex::encode(root),
            previous_checkpoint_sha256,
            now,
            self.build_sha256.clone(),
            self.database_schema_sha256.clone(),
            self.signing_key_arn.clone(),
        )?;
        let payload = self.repository.reserve_payload(&payload).await?;
        let digest = payload.digest()?;
        let signature = self
            .signer
            .sign_digest(&self.signing_key_arn, &digest)
            .await?;
        let envelope = CheckpointEnvelope::new(payload, &signature)?;
        self.verify_envelope(&envelope).await?;
        let key = envelope.object_key()?;
        let bytes = envelope.object_bytes()?;
        let body_sha256: [u8; 32] = Sha256::digest(&bytes).into();

        let (object, published) = match self.store.put_if_absent(&key, &bytes, &body_sha256).await {
            Ok(Some(object)) => (object, true),
            Ok(None) | Err(CheckpointError::Provider) => {
                // Conditional conflict or ambiguous provider response: recover only
                // by reading the deterministic key and proving byte equality.
                let recovered = self.exact_object(&key).await?;
                let recovered_bytes = self.store.get(&recovered).await?;
                if recovered_bytes != bytes {
                    return Err(CheckpointError::IntegrityViolation);
                }
                (recovered, false)
            }
            Err(error) => return Err(error),
        };
        if object.version_id.is_empty() {
            return Err(CheckpointError::IntegrityViolation);
        }
        self.repository
            .record_publication(&envelope, &object)
            .await?;
        if published {
            Ok(PublishOutcome::Published(object))
        } else {
            Ok(PublishOutcome::Recovered(object))
        }
    }

    /// Verify every retained checkpoint, its predecessor link, and its DB anchor.
    pub async fn verify_all(&self) -> Result<usize, CheckpointError> {
        let objects = self.store.list("checkpoints/").await?;
        let mut by_community: BTreeMap<Uuid, Vec<StoredObject>> = BTreeMap::new();
        for object in objects {
            let community = community_from_key(&object.key)?;
            by_community.entry(community).or_default().push(object);
        }
        let database_communities: BTreeSet<Uuid> =
            self.repository.communities().await?.into_iter().collect();
        if !by_community
            .keys()
            .all(|id| database_communities.contains(id))
        {
            return Err(CheckpointError::IntegrityViolation);
        }
        let mut verified = 0;
        for (community, mut tenant_objects) in by_community {
            tenant_objects.sort_by_key(|object| sequence_from_key(&object.key).unwrap_or(i64::MAX));
            let mut previous_object_digest: Option<String> = None;
            let mut previous_sequence = 0;
            let mut previous_root = None;
            for object in tenant_objects {
                let bytes = self.store.get(&object).await?;
                let envelope: CheckpointEnvelope = serde_json::from_slice(&bytes)
                    .map_err(|_| CheckpointError::InvalidCheckpoint)?;
                self.verify_envelope(&envelope).await?;
                if envelope.object_key()? != object.key
                    || envelope.payload.community_id != community
                    || envelope.payload.sequence <= previous_sequence
                    || envelope.payload.previous_checkpoint_sha256 != previous_object_digest
                {
                    return Err(CheckpointError::IntegrityViolation);
                }
                let root = self
                    .repository
                    .verify_segment(
                        envelope.payload.community_id,
                        previous_sequence + 1,
                        envelope.payload.sequence,
                        previous_root,
                    )
                    .await?;
                if hex::encode(root) != envelope.payload.chain_root_sha256 {
                    return Err(CheckpointError::IntegrityViolation);
                }
                previous_sequence = envelope.payload.sequence;
                previous_root = Some(decode_digest(&envelope.payload.chain_root_sha256)?);
                previous_object_digest = Some(hex::encode(envelope.object_digest()?));
                verified += 1;
            }
        }
        Ok(verified)
    }

    async fn verify_anchor_against_database(
        &self,
        envelope: &CheckpointEnvelope,
    ) -> Result<(), CheckpointError> {
        let row_root = self
            .repository
            .verify_segment(
                envelope.payload.community_id,
                envelope.payload.sequence,
                envelope.payload.sequence,
                None,
            )
            .await?;
        if hex::encode(row_root) != envelope.payload.chain_root_sha256 {
            return Err(CheckpointError::IntegrityViolation);
        }
        Ok(())
    }

    async fn verify_envelope(&self, envelope: &CheckpointEnvelope) -> Result<(), CheckpointError> {
        envelope.validate()?;
        if envelope.payload.signing_key_arn != self.signing_key_arn {
            return Err(CheckpointError::IntegrityViolation);
        }
        self.signer
            .verify_digest(
                &envelope.payload.signing_key_arn,
                &envelope.payload.digest()?,
                &envelope.signature()?,
            )
            .await
    }

    async fn latest_for_community(
        &self,
        community_id: Uuid,
    ) -> Result<Option<(CheckpointEnvelope, StoredObject)>, CheckpointError> {
        let prefix = format!("checkpoints/{community_id}/");
        let objects = self.store.list(&prefix).await?;
        let Some(max_seq) = objects
            .iter()
            .map(|object| sequence_from_key(&object.key))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
        else {
            return Ok(None);
        };
        let winners: Vec<_> = objects
            .into_iter()
            .filter(
                |object| matches!(sequence_from_key(&object.key), Ok(value) if value == max_seq),
            )
            .collect();
        if winners.len() != 1 {
            return Err(CheckpointError::IntegrityViolation);
        }
        let object = winners
            .into_iter()
            .next()
            .ok_or(CheckpointError::IntegrityViolation)?;
        let bytes = self.store.get(&object).await?;
        let envelope: CheckpointEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| CheckpointError::InvalidCheckpoint)?;
        self.verify_envelope(&envelope).await?;
        if envelope.object_key()? != object.key || envelope.payload.community_id != community_id {
            return Err(CheckpointError::IntegrityViolation);
        }
        Ok(Some((envelope, object)))
    }

    async fn exact_object(&self, key: &str) -> Result<StoredObject, CheckpointError> {
        let matches: Vec<_> = self
            .store
            .list(key)
            .await?
            .into_iter()
            .filter(|v| v.key == key)
            .collect();
        if matches.len() != 1 {
            return Err(CheckpointError::IntegrityViolation);
        }
        matches
            .into_iter()
            .next()
            .ok_or(CheckpointError::IntegrityViolation)
    }
}

fn decode_digest(value: &str) -> Result<[u8; 32], CheckpointError> {
    hex::decode(value)
        .map_err(|_| CheckpointError::InvalidCheckpoint)?
        .try_into()
        .map_err(|_| CheckpointError::InvalidCheckpoint)
}

fn community_from_key(key: &str) -> Result<Uuid, CheckpointError> {
    let mut parts = key.split('/');
    if parts.next() != Some("checkpoints") {
        return Err(CheckpointError::InvalidCheckpoint);
    }
    let id = parts.next().ok_or(CheckpointError::InvalidCheckpoint)?;
    Uuid::parse_str(id).map_err(|_| CheckpointError::InvalidCheckpoint)
}

fn sequence_from_key(key: &str) -> Result<i64, CheckpointError> {
    let filename = key
        .rsplit('/')
        .next()
        .ok_or(CheckpointError::InvalidCheckpoint)?;
    let sequence = filename
        .split('-')
        .next()
        .ok_or(CheckpointError::InvalidCheckpoint)?;
    if sequence.len() != 20 || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CheckpointError::InvalidCheckpoint);
    }
    sequence
        .parse()
        .map_err(|_| CheckpointError::InvalidCheckpoint)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    use super::*;

    const KEY: &str = "arn:aws:kms:us-west-2:111111111111:key/00000000-0000-4000-8000-000000000001";

    type RootMap = BTreeMap<(Uuid, i64), [u8; 32]>;

    #[derive(Clone, Default)]
    struct FakeRepository {
        roots: Arc<Mutex<RootMap>>,
        reservations: Arc<Mutex<BTreeMap<(Uuid, i64), CheckpointPayload>>>,
        publications: Arc<Mutex<Vec<(Uuid, i64, String)>>>,
    }

    impl FakeRepository {
        fn set_root(&self, community: Uuid, sequence: i64, root: [u8; 32]) {
            self.roots
                .lock()
                .unwrap()
                .insert((community, sequence), root);
        }
    }

    #[async_trait]
    impl CheckpointRepository for FakeRepository {
        async fn communities(&self) -> Result<Vec<Uuid>, CheckpointError> {
            Ok(self
                .roots
                .lock()
                .unwrap()
                .keys()
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect())
        }

        async fn head(
            &self,
            community_id: Uuid,
        ) -> Result<Option<(i64, [u8; 32])>, CheckpointError> {
            Ok(self
                .roots
                .lock()
                .unwrap()
                .iter()
                .filter(|((id, _), _)| *id == community_id)
                .max_by_key(|((_, sequence), _)| *sequence)
                .map(|((_, sequence), root)| (*sequence, *root)))
        }

        async fn verify_segment(
            &self,
            community_id: Uuid,
            from_seq: i64,
            to_seq: i64,
            expected_previous: Option<[u8; 32]>,
        ) -> Result<[u8; 32], CheckpointError> {
            let roots = self.roots.lock().unwrap();
            if let Some(expected) = expected_previous {
                if roots.get(&(community_id, from_seq - 1)) != Some(&expected) {
                    return Err(CheckpointError::IntegrityViolation);
                }
            }
            for sequence in from_seq..=to_seq {
                if !roots.contains_key(&(community_id, sequence)) {
                    return Err(CheckpointError::IntegrityViolation);
                }
            }
            roots
                .get(&(community_id, to_seq))
                .copied()
                .ok_or(CheckpointError::IntegrityViolation)
        }

        async fn reserve_payload(
            &self,
            payload: &CheckpointPayload,
        ) -> Result<CheckpointPayload, CheckpointError> {
            let mut values = self.reservations.lock().unwrap();
            let value = values
                .entry((payload.community_id, payload.sequence))
                .or_insert_with(|| payload.clone());
            if value != payload {
                return Err(CheckpointError::IntegrityViolation);
            }
            Ok(value.clone())
        }

        async fn record_publication(
            &self,
            envelope: &CheckpointEnvelope,
            object: &StoredObject,
        ) -> Result<(), CheckpointError> {
            let value = (
                envelope.payload.community_id,
                envelope.payload.sequence,
                object.version_id.clone(),
            );
            let mut values = self.publications.lock().unwrap();
            if !values.contains(&value) {
                values.push(value);
            }
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeSigner;

    #[async_trait]
    impl CheckpointSigner for FakeSigner {
        async fn sign_digest(
            &self,
            key_arn: &str,
            digest: &[u8; 32],
        ) -> Result<Vec<u8>, CheckpointError> {
            if key_arn != KEY {
                return Err(CheckpointError::SignatureInvalid);
            }
            Ok(digest.to_vec())
        }

        async fn verify_digest(
            &self,
            key_arn: &str,
            digest: &[u8; 32],
            signature: &[u8],
        ) -> Result<(), CheckpointError> {
            if key_arn == KEY && signature == digest {
                Ok(())
            } else {
                Err(CheckpointError::SignatureInvalid)
            }
        }
    }

    type ObjectMap = BTreeMap<String, (String, Vec<u8>)>;

    #[derive(Clone, Default)]
    struct FakeStore {
        objects: Arc<Mutex<ObjectMap>>,
        ambiguous_next_put: Arc<AtomicBool>,
    }

    #[async_trait]
    impl ImmutableObjectStore for FakeStore {
        async fn list(&self, prefix: &str) -> Result<Vec<StoredObject>, CheckpointError> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, (version, _))| StoredObject {
                    key: key.clone(),
                    version_id: version.clone(),
                })
                .collect())
        }

        async fn get(&self, object: &StoredObject) -> Result<Vec<u8>, CheckpointError> {
            self.objects
                .lock()
                .unwrap()
                .get(&object.key)
                .filter(|(version, _)| version == &object.version_id)
                .map(|(_, body)| body.clone())
                .ok_or(CheckpointError::Provider)
        }

        async fn put_if_absent(
            &self,
            key: &str,
            body: &[u8],
            body_sha256: &[u8; 32],
        ) -> Result<Option<StoredObject>, CheckpointError> {
            if Sha256::digest(body).as_slice() != body_sha256 {
                return Err(CheckpointError::IntegrityViolation);
            }
            let mut objects = self.objects.lock().unwrap();
            if objects.contains_key(key) {
                return Ok(None);
            }
            objects.insert(key.to_owned(), ("version-1".into(), body.to_vec()));
            if self.ambiguous_next_put.swap(false, Ordering::SeqCst) {
                return Err(CheckpointError::Provider);
            }
            Ok(Some(StoredObject {
                key: key.to_owned(),
                version_id: "version-1".into(),
            }))
        }
    }

    fn service(
        repository: FakeRepository,
        store: FakeStore,
    ) -> AuditCheckpointService<FakeRepository, FakeSigner, FakeStore> {
        AuditCheckpointService::new(
            repository,
            FakeSigner,
            store,
            KEY.into(),
            "aa".repeat(32),
            "bb".repeat(32),
        )
        .unwrap()
    }

    fn time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[tokio::test]
    async fn publication_is_idempotent_and_recovers_lost_response() {
        let community = Uuid::from_u128(1);
        let repository = FakeRepository::default();
        repository.set_root(community, 1, [1; 32]);
        let store = FakeStore::default();
        store.ambiguous_next_put.store(true, Ordering::SeqCst);
        let service = service(repository.clone(), store.clone());

        assert!(matches!(
            service.publish_community(community, time()).await.unwrap(),
            PublishOutcome::Recovered(_)
        ));
        assert!(matches!(
            service.publish_community(community, time()).await.unwrap(),
            PublishOutcome::Current(_)
        ));
        assert_eq!(store.objects.lock().unwrap().len(), 1);
        assert_eq!(repository.publications.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn later_anchor_links_prior_object_and_database_segment() {
        let community = Uuid::from_u128(2);
        let repository = FakeRepository::default();
        repository.set_root(community, 1, [1; 32]);
        let store = FakeStore::default();
        let service = service(repository.clone(), store.clone());
        service.publish_community(community, time()).await.unwrap();
        repository.set_root(community, 2, [2; 32]);
        service.publish_community(community, time()).await.unwrap();
        assert_eq!(service.verify_all().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn recomputed_database_history_cannot_match_retained_signature() {
        let community = Uuid::from_u128(3);
        let repository = FakeRepository::default();
        repository.set_root(community, 1, [1; 32]);
        let store = FakeStore::default();
        let service = service(repository.clone(), store);
        service.publish_community(community, time()).await.unwrap();

        repository.set_root(community, 1, [9; 32]);
        assert!(matches!(
            service.verify_all().await,
            Err(CheckpointError::IntegrityViolation)
        ));
    }

    #[tokio::test]
    async fn immutable_object_tamper_fails_signature_or_digest_validation() {
        let community = Uuid::from_u128(4);
        let repository = FakeRepository::default();
        repository.set_root(community, 1, [1; 32]);
        let store = FakeStore::default();
        let service = service(repository, store.clone());
        service.publish_community(community, time()).await.unwrap();
        let key = store.objects.lock().unwrap().keys().next().unwrap().clone();
        store.objects.lock().unwrap().get_mut(&key).unwrap().1[0] ^= 1;
        assert!(service.verify_all().await.is_err());
    }
}
