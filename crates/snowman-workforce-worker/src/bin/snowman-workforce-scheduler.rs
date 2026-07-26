#![forbid(unsafe_code)]

use snowman_workforce_worker::{Scheduler, SchedulerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "snowman_workforce_scheduler=info".into()),
        )
        .init();
    let config = SchedulerConfig::from_env()?;
    Scheduler::new(config)?.run().await?;
    Ok(())
}
