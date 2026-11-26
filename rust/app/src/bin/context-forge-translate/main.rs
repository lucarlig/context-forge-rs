// SPDX-License-Identifier: Apache-2.0

mod http;
mod remote;
mod stdio;

use std::{error::Error, time::Duration};

use clap::{ArgGroup, Parser};
use context_forge_rs::config::Settings;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::filter::LevelFilter;

#[derive(Parser)]
#[command(
    about = "Translate MCP between stdio, SSE, and Streamable HTTP",
    group(ArgGroup::new("source").required(true).args(["stdio", "connect_sse", "connect_streamable_http"]))
)]
struct Arguments {
    #[arg(long, value_name = "COMMAND")]
    stdio: Option<String>,
    #[arg(long, value_name = "URL")]
    connect_sse: Option<String>,
    #[arg(long, value_name = "URL")]
    connect_streamable_http: Option<String>,
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
    let routes = http::Expose {
        sse: args.expose_sse || !args.expose_streamable_http,
        streamable_http: args.expose_streamable_http,
        sse_path: args.sse_path,
        message_path: args.message_path,
        cors: args.cors,
        settings,
    };
    let listener = TcpListener::bind((args.host.as_str(), args.port)).await?;
    let command = args.stdio.as_deref().expect("stdio source selected");
    let (process, bridge) = stdio::StdioProcess::start(command, &shutdown)?;
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
