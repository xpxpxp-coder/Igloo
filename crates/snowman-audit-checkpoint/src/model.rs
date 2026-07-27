use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::service::CheckpointError;

/// Canonical checkpoint schema identifier.
pub const CHECKPOINT_SCHEMA: &str = "snowman.audit-checkpoint.v1";
/// Exact KMS algorithm used for deterministic, retry-safe signatures.
pub const SIGNING_ALGORITHM: &str = "RSASSA_PKCS1_V1_5_SHA_256";

/// Content-minimized payload signed by the dedicated asymmetric KMS key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointPayload {
    /// Versioned canonicalization contract.
    pub schema_version: String,
    /// Exact host-derived Snowman community/tenant identifier.
    pub community_id: Uuid,
    /// Inclusive audit sequence represented by `chain_root_sha256`.
    pub sequence: i64,
    /// Hash stored on the audit row at `sequence`.
    pub chain_root_sha256: String,
    /// SHA-256 of the preceding immutable checkpoint envelope, if any.
    pub previous_checkpoint_sha256: Option<String>,
    /// UTC time frozen before the signing attempt.
    pub signed_at: String,
    /// Digest of the exact deployed image/build provenance.
    pub build_sha256: String,
    /// Digest of the exact applied database schema/migration set.
    pub database_schema_sha256: String,
    /// Exact Snowman-account asymmetric KMS signing key ARN.
    pub signing_key_arn: String,
}

impl CheckpointPayload {
    /// Create a strictly formatted payload.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        community_id: Uuid,
        sequence: i64,
        chain_root_sha256: String,
        previous_checkpoint_sha256: Option<String>,
        signed_at: DateTime<Utc>,
        build_sha256: String,
        database_schema_sha256: String,
        signing_key_arn: String,
    ) -> Result<Self, CheckpointError> {
        let value = Self {
            schema_version: CHECKPOINT_SCHEMA.to_owned(),
            community_id,
            sequence,
            chain_root_sha256,
            previous_checkpoint_sha256,
            signed_at: signed_at.to_rfc3339_opts(SecondsFormat::Micros, true),
            build_sha256,
            database_schema_sha256,
            signing_key_arn,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate every bounded field before signing or accepting an envelope.
    pub fn validate(&self) -> Result<(), CheckpointError> {
        if self.schema_version != CHECKPOINT_SCHEMA || self.sequence <= 0 {
            return Err(CheckpointError::InvalidCheckpoint);
        }
        for digest in [
            Some(self.chain_root_sha256.as_str()),
            self.previous_checkpoint_sha256.as_deref(),
            Some(self.build_sha256.as_str()),
            Some(self.database_schema_sha256.as_str()),
        ]
        .into_iter()
        .flatten()
        {
            if !is_sha256(digest) {
                return Err(CheckpointError::InvalidCheckpoint);
            }
        }
        let parsed = DateTime::parse_from_rfc3339(&self.signed_at)
            .map_err(|_| CheckpointError::InvalidCheckpoint)?
            .with_timezone(&Utc);
        if parsed.to_rfc3339_opts(SecondsFormat::Micros, true) != self.signed_at {
            return Err(CheckpointError::InvalidCheckpoint);
        }
        if !is_snowman_kms_arn(&self.signing_key_arn) {
            return Err(CheckpointError::InvalidCheckpoint);
        }
        Ok(())
    }

    /// Deterministic bytes supplied to SHA-256 before KMS signs the digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| CheckpointError::Serialization)
    }

    /// SHA-256 of [`Self::canonical_bytes`].
    pub fn digest(&self) -> Result<[u8; 32], CheckpointError> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

/// Immutable signed checkpoint object stored in the compliance bucket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointEnvelope {
    /// Signed checkpoint data.
    pub payload: CheckpointPayload,
    /// Hex SHA-256 of the canonical payload.
    pub payload_sha256: String,
    /// Exact AWS KMS signing algorithm.
    pub signing_algorithm: String,
    /// Base64-encoded KMS signature; never private key material.
    pub signature_base64: String,
}

impl CheckpointEnvelope {
    /// Construct and validate a signed envelope.
    pub fn new(payload: CheckpointPayload, signature: &[u8]) -> Result<Self, CheckpointError> {
        use base64::Engine as _;
        let payload_sha256 = hex::encode(payload.digest()?);
        let value = Self {
            payload,
            payload_sha256,
            signing_algorithm: SIGNING_ALGORITHM.to_owned(),
            signature_base64: base64::engine::general_purpose::STANDARD.encode(signature),
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate structure and the payload digest before cryptographic verify.
    pub fn validate(&self) -> Result<(), CheckpointError> {
        use base64::Engine as _;
        self.payload.validate()?;
        if self.signing_algorithm != SIGNING_ALGORITHM
            || self.payload_sha256 != hex::encode(self.payload.digest()?)
        {
            return Err(CheckpointError::InvalidCheckpoint);
        }
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&self.signature_base64)
            .map_err(|_| CheckpointError::InvalidCheckpoint)?;
        if signature.is_empty() || signature.len() > 512 {
            return Err(CheckpointError::InvalidCheckpoint);
        }
        Ok(())
    }

    /// Stable JSON object bytes retained under S3 Object Lock.
    pub fn object_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| CheckpointError::Serialization)
    }

    /// Digest that links the next checkpoint to this entire signed object.
    pub fn object_digest(&self) -> Result<[u8; 32], CheckpointError> {
        Ok(Sha256::digest(self.object_bytes()?).into())
    }

    /// Decode the signature after structural validation.
    pub fn signature(&self) -> Result<Vec<u8>, CheckpointError> {
        use base64::Engine as _;
        self.validate()?;
        base64::engine::general_purpose::STANDARD
            .decode(&self.signature_base64)
            .map_err(|_| CheckpointError::InvalidCheckpoint)
    }

    /// Deterministic tenant-separated object key.
    pub fn object_key(&self) -> Result<String, CheckpointError> {
        self.validate()?;
        Ok(format!(
            "checkpoints/{}/{:020}-{}.json",
            self.payload.community_id, self.payload.sequence, self.payload_sha256
        ))
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_snowman_kms_arn(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    parts.len() == 6
        && parts[0] == "arn"
        && matches!(parts[1], "aws" | "aws-us-gov")
        && parts[2] == "kms"
        && !parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
        && parts[5].starts_with("key/")
        && parts[5].len() > 4
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> CheckpointPayload {
        CheckpointPayload::new(
            Uuid::from_u128(1),
            7,
            "11".repeat(32),
            Some("22".repeat(32)),
            DateTime::parse_from_rfc3339("2026-07-27T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            "33".repeat(32),
            "44".repeat(32),
            "arn:aws:kms:us-west-2:111111111111:key/00000000-0000-4000-8000-000000000001".into(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_payload_is_stable_and_minimized() {
        let value = payload();
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(bytes, value.canonical_bytes().unwrap());
        let text = String::from_utf8(bytes).unwrap();
        for forbidden in [
            "email",
            "transcript",
            "prompt",
            "message",
            "phone",
            "artifact",
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn envelope_binds_signature_and_deterministic_key() {
        let envelope = CheckpointEnvelope::new(payload(), &[7_u8; 384]).unwrap();
        assert!(envelope
            .object_key()
            .unwrap()
            .starts_with("checkpoints/00000000-0000-0000-0000-000000000001/00000000000000000007-"));
        let mut altered = envelope.clone();
        altered.payload.sequence = 8;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn rejects_noncanonical_time_and_unknown_kms_coordinate() {
        let mut value = payload();
        value.signed_at = "2026-07-27T12:00:00+00:00".into();
        assert!(value.validate().is_err());
        value = payload();
        value.signing_key_arn = "https://kms.example/key".into();
        assert!(value.validate().is_err());
    }
}
