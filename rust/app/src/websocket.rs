// SPDX-License-Identifier: Apache-2.0

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{
        ConnectInfo, Request, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket, close_code, rejection::WebSocketUpgradeRejection},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    access,
    gateway::GatewayService,
    mcp::{MAX_REQUEST_BODY_BYTES, legacy_transport_reply},
};

pub struct WebSocketSettings {
    pub enabled: bool,
    pub require_auth: bool,
    pub shutdown: CancellationToken,
}

struct WebSocketState {
    gateway: Arc<GatewayService>,
    settings: WebSocketSettings,
}

pub(crate) fn router(gateway: Arc<GatewayService>, settings: WebSocketSettings) -> Router {
    Router::new()
        .route("/ws", get(open))
        .with_state(Arc::new(WebSocketState { gateway, settings }))
}

async fn open(
    State(state): State<Arc<WebSocketState>>,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    request: Request,
) -> Response {
    let Ok(upgrade) = upgrade else {
        return (
            StatusCode::NOT_FOUND,
            [(header::VARY, "Origin")],
            Json(json!({"detail":"Not Found"})),
        )
            .into_response();
    };
    if !state.settings.enabled {
        return StatusCode::FORBIDDEN.into_response();
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0.ip());
    if state
        .gateway
        .access
        .websocket_principal(request.headers(), peer, state.settings.require_auth)
        .await
        .is_err()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let headers = request.headers().clone();
    upgrade
        .max_message_size(MAX_REQUEST_BODY_BYTES)
        .on_upgrade(move |socket| relay(socket, state, headers, peer))
}

async fn relay(
    mut socket: WebSocket,
    state: Arc<WebSocketState>,
    headers: HeaderMap,
    peer: Option<IpAddr>,
) {
    let run = async {
        while let Some(Ok(message)) = socket.recv().await {
            let text = match message {
                Message::Text(text) => text,
                Message::Close(_) => break,
                Message::Binary(_) => {
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: close_code::ERROR,
                            reason: "".into(),
                        })))
                        .await;
                    break;
                }
                Message::Ping(_) | Message::Pong(_) => continue,
            };
            let Some(reply) = respond(&state, &headers, peer, &text).await else {
                break;
            };
            if socket.send(Message::Text(reply.into())).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        biased;
        () = state.settings.shutdown.cancelled() => {},
        () = run => {},
    }
}

async fn respond(
    state: &WebSocketState,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    text: &str,
) -> Option<String> {
    let Ok(mut request) = serde_json::from_str::<Value>(text) else {
        return Some(
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})
                .to_string(),
        );
    };
    let principal = match state
        .gateway
        .access
        .websocket_principal(headers, peer, state.settings.require_auth)
        .await
    {
        Ok(principal) => principal,
        Err(error) => {
            let body = to_bytes(error.into_response().into_body(), MAX_REQUEST_BODY_BYTES)
                .await
                .ok()?;
            return String::from_utf8(body.to_vec()).ok();
        }
    };
    let Some(method) = request["method"]
        .as_str()
        .filter(|_| request["jsonrpc"] == "2.0")
        .map(str::to_owned)
    else {
        return Some(invalid_request(Value::Null).to_string());
    };
    let id = request
        .as_object_mut()
        .expect("request is an object")
        .entry("id")
        .or_insert_with(|| json!(Uuid::new_v4().to_string()))
        .clone();
    if method.starts_with("notifications/") {
        return Some(json!({"jsonrpc":"2.0","id":id,"result":{}}).to_string());
    }
    let permission = rpc_permission(&method);
    let server_id = request["params"]["server_id"]
        .as_str()
        .filter(|id| !id.is_empty());
    let server = match server_id {
        Some(server_id) => match state
            .gateway
            .visible_server(server_id, principal.as_ref())
            .await
        {
            Ok(Some(server)) => Some(server),
            Ok(None) => return Some(rpc_denied(&id, &method)),
            Err(error) => return Some(database_error(error, &id)),
        },
        None => None,
    };
    if let Some(permission) = permission {
        let Some(principal) = principal.as_ref() else {
            return Some(rpc_denied(&id, &method));
        };
        match state
            .gateway
            .access
            .allows(
                principal,
                permission,
                access::role_context(server.as_ref()),
                true,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => return Some(rpc_denied(&id, &method)),
            Err(error) => return Some(database_error(error, &id)),
        }
    }
    let mut reply =
        legacy_transport_reply(&state.gateway, principal.as_ref(), server.as_ref(), request)
            .await
            .unwrap_or_else(|| invalid_request(id));
    if reply["error"]["code"] == -32601 {
        reply["error"] =
            json!({"code":-32601,"message":format!("Method not found: {method}"),"data":{}});
    }
    Some(reply.to_string())
}

fn rpc_permission(method: &str) -> Option<&'static str> {
    match method {
        "initialize" | "ping" | "subscriptions/listen" => None,
        "tools/list" | "list_tools" | "completion/complete" => Some("tools.read"),
        "resources/list"
        | "resources/templates/list"
        | "resources/read"
        | "resources/subscribe"
        | "resources/unsubscribe" => Some("resources.read"),
        "prompts/list" | "prompts/get" => Some("prompts.read"),
        "list_gateways" => Some("gateways.read"),
        "roots/list" | "list_roots" | "logging/setLevel" => Some("admin.system_config"),
        _ => Some("tools.execute"),
    }
}

fn rpc_denied(id: &Value, method: &str) -> String {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32003,"message":"Access denied","data":{"method":method}}}).to_string()
}

fn database_error(error: sqlx::Error, id: &Value) -> String {
    tracing::error!(%error, "WebSocket RPC authorization failed");
    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"Internal error"}}).to_string()
}

fn invalid_request(id: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32600,"message":"Invalid Request"}})
}
