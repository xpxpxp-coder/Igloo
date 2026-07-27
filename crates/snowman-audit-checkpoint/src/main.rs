use anyhow::{bail, Context};
use chrono::Utc;
use snowman_audit_checkpoint::{
    AuditCheckpointService, AwsKmsSigner, AwsS3ObjectStore, PostgresCheckpointRepository,
};
use sqlx::postgres::PgPoolOptions;

fn required(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

async fn run() -> anyhow::Result<()> {
    let mode = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "verify".to_owned());
    if !matches!(mode.as_str(), "publish" | "verify") {
        bail!("usage: snowman-audit-checkpoint [publish|verify]");
    }
    let database_url = required("DATABASE_URL")?;
    let bucket = required("SNOWMAN_AUDIT_CHECKPOINT_BUCKET")?;
    let signing_key = required("SNOWMAN_AUDIT_CHECKPOINT_SIGNING_KEY_ARN")?;
    let encryption_key = required("SNOWMAN_AUDIT_CHECKPOINT_ENCRYPTION_KEY_ARN")?;
    let build_sha256 = required("SNOWMAN_BUILD_SHA256")?;
    let schema_sha256 = required("SNOWMAN_DATABASE_SCHEMA_SHA256")?;
    let expected_role = required("SNOWMAN_AUDIT_CHECKPOINT_DB_ROLE")?;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .context("audit checkpoint database connection failed")?;
    buzz_db::runtime_security::verify_audit_checkpoint_role(&pool, &expected_role)
        .await
        .context("audit checkpoint database role failed closed")?;
    let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let repository = PostgresCheckpointRepository::new(pool);
    let signer = AwsKmsSigner::new(aws_sdk_kms::Client::new(&sdk));
    let store = AwsS3ObjectStore::new(aws_sdk_s3::Client::new(&sdk), bucket, encryption_key)?;
    let service = AuditCheckpointService::new(
        repository,
        signer,
        store,
        signing_key,
        build_sha256,
        schema_sha256,
    )?;
    if mode == "publish" {
        let outcomes = service.publish_all(Utc::now()).await?;
        tracing::info!(
            event = "audit_checkpoint_complete",
            tenants = outcomes.len()
        );
    } else {
        let verified = service.verify_all().await?;
        tracing::info!(
            event = "audit_checkpoint_verify_complete",
            checkpoints = verified
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().with_target(false).init();
    if let Err(error) = run().await {
        tracing::error!(event = "audit_checkpoint_failure", error = %error);
        return Err(error);
    }
    Ok(())
}
