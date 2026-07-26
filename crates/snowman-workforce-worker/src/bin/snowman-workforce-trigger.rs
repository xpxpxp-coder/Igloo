#![forbid(unsafe_code)]

use snowman_workforce_worker::{Trigger, TriggerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "snowman_workforce_trigger=info".into()),
        )
        .init();
    let config = TriggerConfig::from_env()?;
    Trigger::new(config)?.run().await?;
    Ok(())
}
