// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use context_forge_rs::{
    config::Settings,
    database::Database,
    probes::{self, RedisProbe},
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let settings = Settings::from_env()?;
    let database = Database::from_settings(&settings)?;
    let redis = settings.redis.as_ref().map(RedisProbe::new).transpose()?;
    let listener = TcpListener::bind((settings.host.as_str(), settings.port)).await?;
    tracing::info!(address = %listener.local_addr()?, "gateway listening");
    axum::serve(listener, probes::router(database, redis))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
