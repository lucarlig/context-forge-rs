// SPDX-License-Identifier: Apache-2.0

mod environment;
mod http;
mod remote;
mod stdio;

use std::{error::Error, sync::Arc, time::Duration};

use clap::{ArgGroup, Parser};
use context_forge_rs::{config::Settings, grpc::GrpcTarget};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::filter::LevelFilter;

#[derive(Parser)]
#[command(
    about = "Translate MCP transports or discover a gRPC service",
    group(ArgGroup::new("source").required(true).args(["stdio", "connect_sse", "connect_streamable_http", "grpc", "connect_grpc"]))
)]
struct Arguments {
    #[arg(long, value_name = "COMMAND")]
    stdio: Option<String>,
    #[arg(long, value_name = "URL")]
    connect_sse: Option<String>,
    #[arg(long, value_name = "URL")]
    connect_streamable_http: Option<String>,
    #[arg(
        long,
        value_name = "HOST:PORT",
        help = "Discover methods on a gRPC service"
    )]
    grpc: Option<String>,
    #[arg(long, value_name = "HOST:PORT")]
    connect_grpc: Option<String>,
    #[arg(long, requires = "grpc")]
    grpc_tls: bool,
    #[arg(long, requires = "grpc", value_name = "PATH")]
    grpc_cert: Option<String>,
    #[arg(long, requires = "grpc", value_name = "PATH")]
    grpc_key: Option<String>,
    #[arg(long = "grpc-metadata", requires = "grpc", value_name = "KEY=VALUE")]
    _grpc_metadata: Vec<String>,
    #[arg(long = "stdioCommand", value_name = "COMMAND")]
    stdio_command: Option<String>,
    #[arg(long = "oauth2Bearer", value_name = "TOKEN")]
    bearer: Option<String>,
    #[arg(long)]
    expose_sse: bool,
    #[arg(long)]
    expose_streamable_http: bool,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 8000)]
    port: u16,
    #[arg(long, num_args = 0..)]
    cors: Vec<String>,
    #[arg(long = "ssePath", default_value = "/sse")]
    sse_path: String,
    #[arg(long = "messagePath", default_value = "/message")]
    message_path: String,
    #[arg(long = "keepAlive")]
    keepalive: Option<u64>,
    #[arg(long = "logLevel", default_value = "info", value_parser = ["debug", "info", "warning", "error", "critical"])]
    log_level: String,
    #[arg(long = "stateless")]
    _stateless: bool,
    #[arg(long = "jsonResponse")]
    _json_response: bool,
    #[arg(long)]
    enable_dynamic_env: bool,
    #[arg(long, value_name = "HEADER=ENV_VAR")]
    header_to_env: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Arguments::parse();
    let level = match args.log_level.as_str() {
        "debug" => LevelFilter::DEBUG,
        "warning" => LevelFilter::WARN,
        "error" | "critical" => LevelFilter::ERROR,
        _ => LevelFilter::INFO,
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .init();

    if args.connect_grpc.is_some() {
        eprintln!(
            "Error: --connect-grpc mode not yet implemented. Use --grpc to expose a gRPC server."
        );
        std::process::exit(1);
    }
    if let Some(address) = args.grpc.as_deref() {
        let target = GrpcTarget {
            address,
            tls: args.grpc_tls,
            certificate: args.grpc_cert.as_deref(),
            key: args.grpc_key.as_deref(),
        };
        let upstream = Settings::upstream_client()?;
        let deadline = Settings::grpc_federation()?.timeout;
        let shutdown = shutdown_signal();
        tokio::pin!(shutdown);
        let probe = tokio::select! {
            () = &mut shutdown => return Ok(()),
            result = target.probe(&upstream, deadline) => result?,
        };
        tracing::info!("Discovered: {} services", probe.service_count);
        tracing::info!("Register the service through /admin/grpc to expose its methods in MCP");
        shutdown.await;
        return Ok(());
    }

    let remote = args
        .connect_sse
        .as_deref()
        .map(|url| (url, remote::Transport::Sse))
        .or_else(|| {
            args.connect_streamable_http
                .as_deref()
                .map(|url| (url, remote::Transport::StreamableHttp))
        });
    if let Some((url, transport)) = remote {
        return remote::run(
            url,
            transport,
            args.bearer.as_deref(),
            args.stdio_command.as_deref(),
        )
        .await;
    }

    let shutdown = CancellationToken::new();
    let mut settings = Settings::sse_settings(shutdown.clone())?;
    if let (Some(_), Some(seconds)) = (settings.keepalive, args.keepalive) {
        settings.keepalive = (seconds > 0).then(|| Duration::from_secs(seconds));
    }
    let command = args.stdio.as_deref().expect("stdio source selected");
    let environment = (args.enable_dynamic_env && !args.header_to_env.is_empty())
        .then(|| environment::DynamicEnvironment::parse(command.to_owned(), &args.header_to_env))
        .transpose()?
        .map(Arc::new);
    let empty = environment::EnvironmentValues::new();
    let routes = http::Expose {
        sse: args.expose_sse || !args.expose_streamable_http,
        streamable_http: args.expose_streamable_http,
        sse_path: args.sse_path,
        message_path: args.message_path,
        cors: args.cors,
        settings,
        environment: environment.clone(),
    };
    let listener = TcpListener::bind((args.host.as_str(), args.port)).await?;
    let (process, bridge) = stdio::StdioProcess::start(
        command,
        &shutdown,
        environment
            .as_deref()
            .map(|environment| (environment, &empty)),
    )?;
    let app = routes.router(bridge)?;
    tracing::info!(address = %listener.local_addr()?, "stdio translation server listening");
    let stopped = shutdown.clone();
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            stopped.cancel();
        })
        .await;
    shutdown.cancel();
    process.stop().await;
    result?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
