#![forbid(unsafe_code)]

use snowman_agent_broker::{router, AppState, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        // The broker never permits ambient directives that could enable SQL,
        // HTTP-body, or dependency debug logging.
        .with_env_filter("snowman_agent_broker=info")
        .init();
    let state = AppState::new(Config::from_env()?).await?;
    let listener = tokio::net::TcpListener::bind(state.bind_addr()).await?;
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
