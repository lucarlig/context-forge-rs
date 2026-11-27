// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, net::SocketAddr, sync::Arc};

use context_forge_rs::{
    access::Authorizer,
    config::Settings,
    database::Database,
    gateway::GatewayService,
    local_auth,
    probes::{self, RedisProbe},
    schema,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{
    filter::LevelFilter, layer::SubscriberExt, reload, util::SubscriberInitExt,
};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    if std::env::args().nth(1).as_deref() == Some(context_forge_rs::response_filter::WORKER_ARG) {
        return context_forge_rs::response_filter::worker().map_err(Into::into);
    }
    run()
}

#[tokio::main]
async fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("rotate-credentials") => {
            return context_forge_rs::credential_rotation::cli(args).await;
        }
        Some("migrate") => return schema::cli(args).await,
        Some(command @ ("export" | "import")) => {
            return context_forge_rs::configuration_cli::run(command, args).await;
        }
        _ => {}
    }
    let (filter, handle) = reload::Layer::new(LevelFilter::INFO);
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let settings = Settings::from_env()?;
    let database = Database::from_settings(&settings)?;
    let redis = settings.redis.as_ref().map(RedisProbe::new).transpose()?;
    let verifier = Settings::jwt_verifier()?;
    let external_identity = Settings::sso_external_identity()?;
    let require_mcp_auth = Settings::mcp_requires_auth()?;
    let require_api_auth = Settings::api_requires_auth()?;
    let shutdown = CancellationToken::new();
    let sse = settings.gateway_sse_settings(shutdown.clone())?;
    let catalog_available = verifier.is_some() || external_identity.is_some() || !require_mcp_auth;
    if schema::skip_migrations()? {
        database
            .require_current_schema()
            .await
            .map_err(|error| error.to_string())?;
    } else if catalog_available {
        database.migrate_schema().await?;
    }
    let access = Arc::new(
        Authorizer::new(
            database.clone(),
            verifier,
            Settings::invalidate_sessions_on_password_change()?,
        )
        .with_internal_jwt_issuer(Settings::jwt_issuer_name()?)
        .with_external_identity(external_identity)
        .with_token_usage_logging(Settings::token_usage_logging()?),
    );
    let email_auth_enabled = Settings::email_auth_enabled()?;
    let issuer = Settings::jwt_issuer()?;
    let accounts = match issuer
        .as_ref()
        .filter(|_| email_auth_enabled && catalog_available)
    {
        Some(issuer) => {
            local_auth::router(
                database.clone(),
                access.clone(),
                issuer.clone(),
                Settings::local_accounts()?,
            )
            .await?
        }
        None => axum::Router::new(),
    };
    let (management_page_size, management_max_page_size) = Settings::management_page_sizes()?;
    let catalog_refresh = Settings::catalog_refresh()?;
    let health_settings = Settings::gateway_health(&catalog_refresh)?;
    let gateway_listeners = settings.gateway_listeners()?;
    let (well_known, cache_max_age, allow_oauth_loopback) = Settings::server_oauth_metadata()?;
    let (rest_timeout, rest_response_text_limit) = Settings::rest_tool_limits()?;
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
        .with_tool_preview(Settings::tool_preview_enabled()?)
        .with_response_filters(Settings::response_filters()?)
        .with_rest_tool_limits(rest_timeout, rest_response_text_limit)
        .with_token_issuer(email_auth_enabled, issuer)
        .with_gateway_oauth(Settings::gateway_oauth()?)
        .with_virtual_server_base(Settings::virtual_server_base()?)
        .with_export_settings(settings.export_settings()?)
        .with_server_oauth_metadata(well_known, cache_max_age, allow_oauth_loopback)
        .with_logging_filter(handle)
        .with_management_page_sizes(management_page_size, management_max_page_size)
        .with_credential_secret(Settings::auth_encryption_secret()?.as_deref())
        .with_redis_oauth_cache(Settings::redis_connection()?.as_ref())
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
    let transport = Settings::mcp_ingress_policy()?.apply(mcp.merge(legacy_sse).merge(websocket));
    let management =
        service.registration_router_with_probe(transport.clone(), health_settings.timeout);
    let app = probes::router(database, redis)
        .merge(transport)
        .merge(management)
        .merge(accounts)
        .merge(service.gateway_oauth_callback())
        .merge(service.server_oauth_router());
    let listener = TcpListener::bind((settings.host.as_str(), settings.port)).await?;
    let background = catalog_available.then(|| {
        [
            tokio::spawn(
                service
                    .clone()
                    .run_gateway_health(health_settings, shutdown.clone()),
            ),
            tokio::spawn(service.clone().run_gateway_lifecycle(shutdown.clone())),
            tokio::spawn(service.run_gateway_listeners(gateway_listeners, shutdown.clone())),
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
