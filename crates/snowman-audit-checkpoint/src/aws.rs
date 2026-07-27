use async_trait::async_trait;
use aws_sdk_kms::{
    primitives::Blob,
    types::{MessageType, SigningAlgorithmSpec},
};
use aws_sdk_s3::{
    error::ProvideErrorMetadata as _, primitives::ByteStream, types::ServerSideEncryption,
};

use crate::service::{CheckpointError, CheckpointSigner, ImmutableObjectStore, StoredObject};

/// AWS KMS signer/verifier bound by the caller to one exact asymmetric key ARN.
pub struct AwsKmsSigner {
    client: aws_sdk_kms::Client,
}

impl AwsKmsSigner {
    /// Create an AWS KMS boundary using the workload task identity.
    pub fn new(client: aws_sdk_kms::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CheckpointSigner for AwsKmsSigner {
    async fn sign_digest(
        &self,
        key_arn: &str,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, CheckpointError> {
        let output = self
            .client
            .sign()
            .key_id(key_arn)
            .message(Blob::new(digest))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
            .send()
            .await
            .map_err(|_| CheckpointError::Provider)?;
        output
            .signature
            .map(|value| value.into_inner())
            .filter(|value| !value.is_empty())
            .ok_or(CheckpointError::Provider)
    }

    async fn verify_digest(
        &self,
        key_arn: &str,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), CheckpointError> {
        let output = self
            .client
            .verify()
            .key_id(key_arn)
            .message(Blob::new(digest))
            .message_type(MessageType::Digest)
            .signature(Blob::new(signature))
            .signing_algorithm(SigningAlgorithmSpec::RsassaPkcs1V15Sha256)
            .send()
            .await
            .map_err(|_| CheckpointError::Provider)?;
        if output.signature_valid {
            Ok(())
        } else {
            Err(CheckpointError::SignatureInvalid)
        }
    }
}

/// S3 Object Lock store with exact SSE-KMS and immutable-key semantics.
pub struct AwsS3ObjectStore {
    client: aws_sdk_s3::Client,
    bucket: String,
    encryption_key_arn: String,
}

impl AwsS3ObjectStore {
    /// Create a bucket boundary. Bucket policy and task IAM must deny delete and
    /// require this exact encryption key.
    pub fn new(
        client: aws_sdk_s3::Client,
        bucket: String,
        encryption_key_arn: String,
    ) -> Result<Self, CheckpointError> {
        if bucket.is_empty() || encryption_key_arn.is_empty() {
            return Err(CheckpointError::InvalidCheckpoint);
        }
        Ok(Self {
            client,
            bucket,
            encryption_key_arn,
        })
    }
}

#[async_trait]
impl ImmutableObjectStore for AwsS3ObjectStore {
    async fn list(&self, prefix: &str) -> Result<Vec<StoredObject>, CheckpointError> {
        let mut token = None;
        let mut objects = Vec::new();
        loop {
            let output = self
                .client
                .list_object_versions()
                .bucket(&self.bucket)
                .prefix(prefix)
                .set_key_marker(token.clone())
                .send()
                .await
                .map_err(|_| CheckpointError::Provider)?;
            for version in output.versions() {
                if !version.is_latest.unwrap_or(false) {
                    // More than one retained version for a deterministic key is
                    // a publication integrity failure, not something to hide.
                    return Err(CheckpointError::IntegrityViolation);
                }
                let key = version.key().ok_or(CheckpointError::IntegrityViolation)?;
                let version_id = version
                    .version_id()
                    .ok_or(CheckpointError::IntegrityViolation)?;
                objects.push(StoredObject {
                    key: key.to_owned(),
                    version_id: version_id.to_owned(),
                });
            }
            if !output.is_truncated.unwrap_or(false) {
                break;
            }
            token = output.next_key_marker;
            if token.is_none() {
                return Err(CheckpointError::IntegrityViolation);
            }
        }
        Ok(objects)
    }

    async fn get(&self, object: &StoredObject) -> Result<Vec<u8>, CheckpointError> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&object.key)
            .version_id(&object.version_id)
            .send()
            .await
            .map_err(|_| CheckpointError::Provider)?;
        if output.version_id.as_deref() != Some(object.version_id.as_str())
            || output.server_side_encryption != Some(ServerSideEncryption::AwsKms)
            || output.ssekms_key_id.as_deref() != Some(self.encryption_key_arn.as_str())
            || output.object_lock_mode.is_none()
            || output.object_lock_retain_until_date.is_none()
        {
            return Err(CheckpointError::IntegrityViolation);
        }
        let bytes = output
            .body
            .collect()
            .await
            .map_err(|_| CheckpointError::Provider)?
            .into_bytes();
        Ok(bytes.to_vec())
    }

    async fn put_if_absent(
        &self,
        key: &str,
        body: &[u8],
        body_sha256: &[u8; 32],
    ) -> Result<Option<StoredObject>, CheckpointError> {
        use base64::Engine as _;
        let checksum = base64::engine::general_purpose::STANDARD.encode(body_sha256);
        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(ByteStream::from(body.to_vec()))
            .content_type("application/vnd.snowman.audit-checkpoint+json")
            .checksum_sha256(checksum)
            .server_side_encryption(ServerSideEncryption::AwsKms)
            .ssekms_key_id(&self.encryption_key_arn)
            .if_none_match("*")
            .send()
            .await;
        match result {
            Ok(output) => {
                let version_id = output
                    .version_id
                    .filter(|value| !value.is_empty())
                    .ok_or(CheckpointError::IntegrityViolation)?;
                Ok(Some(StoredObject {
                    key: key.to_owned(),
                    version_id,
                }))
            }
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|value| value.code() == Some("PreconditionFailed")) =>
            {
                Ok(None)
            }
            Err(_) => Err(CheckpointError::Provider),
        }
    }
}
