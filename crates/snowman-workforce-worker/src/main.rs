#![forbid(unsafe_code)]

use snowman_workforce_worker::{Config, Worker};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "snowman_workforce_worker=info".into()),
        )
        .init();
    let config = Config::from_env()?;
    Worker::new(config).await?.run().await?;
    Ok(())
}
