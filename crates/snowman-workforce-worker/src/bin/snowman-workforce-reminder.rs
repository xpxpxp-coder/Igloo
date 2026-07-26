#![forbid(unsafe_code)]

use snowman_workforce_worker::{ReminderConfig, ReminderWorker};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "snowman_workforce_reminder=info".into()),
        )
        .init();
    let config = ReminderConfig::from_env()?;
    ReminderWorker::new(config)?.run().await?;
    Ok(())
}
