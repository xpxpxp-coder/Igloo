#![forbid(unsafe_code)]

use snowman_provider_egress_proxy::server::{router, AppState, Config};
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("snowman_provider_egress_proxy=info")),
        )
        .with_current_span(false)
        .with_span_list(false)
        .init();
    let state = AppState::new(Config::from_env()?).await?;
    let listener = tokio::net::TcpListener::bind(state.bind_addr()).await?;
    tracing::info!(
        service = "snowman-provider-egress",
        "private listener ready"
    );
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown())
        .await?;
    tracing::info!(
        service = "snowman-provider-egress",
        "graceful shutdown complete"
    );
    Ok(())
}

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            tokio::select! {
                result = signal::ctrl_c() => { let _ = result; }
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = signal::ctrl_c().await;
}
