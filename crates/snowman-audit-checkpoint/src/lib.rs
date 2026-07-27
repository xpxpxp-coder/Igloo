#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Periodic external anchors for the per-community Snowman audit chain.
//!
//! Checkpoints contain digests and opaque tenant identifiers only. AWS KMS
//! signs the canonical payload and S3 Object Lock retains the signed envelope.
//! The object history, not a mutable PostgreSQL receipt, is authoritative.

mod aws;
mod model;
mod service;

pub use aws::{AwsKmsSigner, AwsS3ObjectStore};
pub use model::{CheckpointEnvelope, CheckpointPayload, CHECKPOINT_SCHEMA};
pub use service::{
    AuditCheckpointService, CheckpointError, CheckpointRepository, CheckpointSigner,
    ImmutableObjectStore, PostgresCheckpointRepository, PublishOutcome, StoredObject,
};
