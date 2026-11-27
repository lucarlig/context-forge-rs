// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, net::SocketAddr, sync::Arc};

use context_forge_rs::{
    access::Authorizer,
    config::Settings,
    database::Database,
    gateway::GatewayService,
    mcp::SseBackend,
    probes::{self, RedisProbe},
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt, reload, util::SubscriberInitExt,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (filter, handle) = reload::Layer::new(LevelFilter::INFO);
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let settings = Settings::from_env()?;
    let database = Database::from_settings(&settings)?;
    let redis = settings.redis.as_ref().map(RedisProbe::new).transpose()?;
    let verifier = Settings::jwt_verifier()?;
    let require_mcp_auth = Settings::mcp_requires_auth()?;
    let require_api_auth = Settings::api_requires_auth()?;
    let shutdown = CancellationToken::new();
    let sse = settings.gateway_sse_settings(shutdown.clone())?;
    let catalog_available = verifier.is_some() || !require_mcp_auth;
    if catalog_available {
        database.migrate_identity().await?;
        database.migrate_catalog().await?;
        if matches!(sse.backend, SseBackend::Database) {
            database.migrate_legacy_sse().await?;
        }
    }
    let access = Arc::new(Authorizer::new(
        database.clone(),
        verifier,
        Settings::invalidate_sessions_on_password_change()?,
    ));
    let (management_page_size, management_max_page_size) = Settings::management_page_sizes()?;
    let catalog_refresh = Settings::catalog_refresh()?;
    let health_settings = Settings::gateway_health(&catalog_refresh)?;
    let service = Arc::new(
        GatewayService::new(
            database.clone(),
            access,
            Settings::upstream_client()?,
            Settings::mcp_pagination()?,
            catalog_refresh,
        )
        .with_gateway_lifecycle(Settings::gateway_lifecycle()?)
        .with_root_settings(Settings::root_settings()?, shutdown.clone())?
        .with_resource_limits(Settings::resource_limits()?)
        .with_max_prompt_bytes(Settings::max_prompt_bytes()?)
        .with_logging_filter(handle)
        .with_management_page_sizes(management_page_size, management_max_page_size)
        .with_credential_secret(Settings::auth_encryption_secret()?.as_deref())
        .with_secret_kdf(Settings::secret_kdf()?)
        .with_query_auth_hosts(Settings::query_auth_hosts()?)
        .with_header_forwarding(Settings::header_forwarding()?)
        .with_identity_forwarding(Settings::identity_forwarding()?)
        .with_direct_proxy(Settings::direct_proxy_timeout()?)
        .with_proxy_catalog(settings.proxy_catalog()?)
        .with_listen_settings(Settings::mcp_listen_settings(shutdown.clone())?),
    );
    let mut http_options = settings.mcp_http_options()?;
    if let Some(settings) = &mut http_options.sessions {
        settings.shutdown = shutdown.clone();
    }
    let mcp = service.mcp_router_with_options(
        require_mcp_auth,
        Settings::mcp_inbound_protocol_mode()?,
        http_options,
    );
    let legacy_sse = service.legacy_sse_router(require_api_auth, sse);
    let websocket = service.websocket_router(Settings::websocket_settings(shutdown.clone())?);
    let app = probes::router(database, redis)
        .merge(Settings::mcp_ingress_policy()?.apply(mcp.merge(legacy_sse).merge(websocket)))
        .merge(service.registration_router());
    let listener = TcpListener::bind((settings.host.as_str(), settings.port)).await?;
    let background = catalog_available.then(|| {
        [
            tokio::spawn(
                service
                    .clone()
                    .run_gateway_health(health_settings, shutdown.clone()),
            ),
            tokio::spawn(service.run_gateway_lifecycle(shutdown.clone())),
        ]
    });
    tracing::info!(address = %listener.local_addr()?, "gateway listening");
    let stop = shutdown.clone();
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        stop.cancel();
    })
    .await;
    shutdown.cancel();
    if let Some(tasks) = background {
        for task in tasks {
            task.await?;
        }
    }
    result?;
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
