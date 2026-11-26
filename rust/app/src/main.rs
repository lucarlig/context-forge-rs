// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, net::SocketAddr, sync::Arc};

use context_forge_rs::{
    access::Authorizer,
    config::Settings,
    database::Database,
    gateway::GatewayService,
    probes::{self, RedisProbe},
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    let settings = Settings::from_env()?;
    let database = Database::from_settings(&settings)?;
    let redis = settings.redis.as_ref().map(RedisProbe::new).transpose()?;
    let verifier = Settings::jwt_verifier()?;
    let require_mcp_auth = Settings::mcp_requires_auth()?;
    if verifier.is_some() || !require_mcp_auth {
        database.migrate_identity().await?;
        database.migrate_catalog().await?;
    }
    let access = Arc::new(Authorizer::new(
        database.clone(),
        verifier,
        Settings::invalidate_sessions_on_password_change()?,
    ));
    let service = Arc::new(GatewayService::new(
        database.clone(),
        access,
        Settings::upstream_client()?,
        Settings::mcp_pagination()?,
        Settings::catalog_refresh()?,
    ));
    let shutdown = CancellationToken::new();
    let mut http_options = Settings::mcp_http_options()?;
    if let Some(settings) = &mut http_options.sessions {
        settings.shutdown = shutdown.clone();
    }
    let mcp = service.mcp_router_with_options(
        require_mcp_auth,
        Settings::mcp_inbound_protocol_mode()?,
        http_options,
    );
    let app = probes::router(database, redis)
        .merge(Settings::mcp_ingress_policy()?.apply(mcp))
        .merge(service.registration_router());
    let listener = TcpListener::bind((settings.host.as_str(), settings.port)).await?;
    tracing::info!(address = %listener.local_addr()?, "gateway listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        shutdown.cancel();
    })
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
