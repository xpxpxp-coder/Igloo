#![forbid(unsafe_code)]

use snowman_meeting_media_gateway::server::{control_router, AppState, Config};
use tokio::signal;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("snowman_meeting_media_gateway=info")),
        )
        .with_current_span(false)
        .with_span_list(false)
        .init();
    let state = AppState::new(Config::from_env()?).await?;
    let listener = tokio::net::TcpListener::bind(state.control_bind_addr()).await?;
    tracing::info!(
        service = "snowman-meeting-media",
        "private control listener ready"
    );
    axum::serve(listener, control_router(state))
        .with_graceful_shutdown(shutdown())
        .await?;
    tracing::info!(
        service = "snowman-meeting-media",
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
