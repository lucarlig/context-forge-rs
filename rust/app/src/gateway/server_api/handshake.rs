// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, time::Instant};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request},
};
use tower::ServiceExt;

use super::*;

const LEGACY_PROTOCOL: &str = "2025-11-25";
const MODERN_PROTOCOL: &str = "2026-07-28";
const PROTOCOL_ERROR: &str = "The server responded but MCP negotiation failed. Confirm the URL points at an MCP endpoint (for example /mcp or /sse) and supports an MCP protocol this gateway understands.";

#[derive(Clone)]
pub(in crate::gateway) struct HandshakeProbe {
    pub(in crate::gateway) router: Router,
    pub(in crate::gateway) timeout: Duration,
}

#[derive(Deserialize)]
pub(super) struct HandshakeInput {
    headers: Option<BTreeMap<String, String>>,
}

pub(super) async fn test(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    probe: Option<Extension<HandshakeProbe>>,
    headers: HeaderMap,
    body: Option<Json<HandshakeInput>>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "servers.read", false).await?;
    let server = find_visible(&service, &principal, &id).await?;
    let start = Instant::now();
    let mut result = json!({
        "success":false,"latencyMs":0,"negotiationPath":null,"protocolVersion":null,"serverName":null,
        "serverVersion":null,"capabilities":null,"componentCounts":null,"countsPartial":false,
        "credentialSource":"none","failureClass":null,"error":null,"rawPreview":null,
        "stages":null,"failedStage":null,"errorCode":null,"reauthorizationRequired":false,
    });
    if !server.enabled {
        result["failureClass"] = "transport".into();
        result["error"] = format!(
            "Virtual server '{}' is disabled. Enable it before testing the connection.",
            server.name,
        )
        .into();
        return Ok(Json(result));
    }

    let Extension(probe) = probe.unwrap_or_else(|| {
        Extension(HandshakeProbe {
            router: service.mcp_router(true, ProtocolMode::Auto),
            timeout: Duration::from_secs(5),
        })
    });
    let mut incoming = HeaderMap::new();
    if let Some(host) = headers.get(header::HOST) {
        incoming.insert(header::HOST, host.clone());
    }
    if let Some(authorization) = headers.get(header::AUTHORIZATION) {
        incoming.insert(header::AUTHORIZATION, authorization.clone());
        result["credentialSource"] = "session".into();
    }
    if let Some(override_value) = body
        .and_then(|Json(input)| input.headers)
        .and_then(|headers| {
            headers
                .into_iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("authorization"))
        })
    {
        let mut value = HeaderValue::from_str(&override_value.1).map_err(|_| {
            CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid handshake Authorization header",
            )
        })?;
        value.set_sensitive(true);
        incoming.insert(header::AUTHORIZATION, value);
        result["credentialSource"] = "form".into();
    }
    let target = format!("/servers/{}/mcp", server.id);
    let mut client = LocalMcp {
        router: &probe.router,
        target: &target,
        headers: incoming,
        next_id: 1,
    };
    match tokio::time::timeout(probe.timeout, client.handshake()).await {
        Ok(Ok(fields)) => {
            for (key, value) in fields {
                result[key] = value;
            }
            result["success"] = true.into();
        }
        Ok(Err(())) => {
            result["failureClass"] = "protocol".into();
            result["error"] = PROTOCOL_ERROR.into();
        }
        Err(_) => {
            result["failureClass"] = "transport".into();
            result["error"] =
                "The virtual server did not respond before the handshake timed out.".into();
        }
    }
    if client.headers.contains_key("mcp-session-id") {
        let _ =
            tokio::time::timeout(Duration::from_secs(1), client.send(Method::DELETE, None)).await;
    }
    result["latencyMs"] = (start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64).into();
    Ok(Json(result))
}

struct LocalMcp<'a> {
    router: &'a Router,
    target: &'a str,
    headers: HeaderMap,
    next_id: u32,
}

impl LocalMcp<'_> {
    async fn handshake(&mut self) -> Result<serde_json::Map<String, Value>, ()> {
        let legacy = self.call("initialize", json!({
            "protocolVersion":LEGACY_PROTOCOL,"capabilities":{},"clientInfo":{"name":"context-forge-probe","version":"1"},
        })).await;
        let (path, version, initialization) = match legacy {
            Ok(reply) => {
                let version = reply["protocolVersion"].as_str().ok_or(())?.to_owned();
                let header = HeaderValue::from_str(&version).map_err(|_| ())?;
                self.headers.insert("mcp-protocol-version", header);
                let _ = self
                    .send(
                        Method::POST,
                        Some(json!({
                            "jsonrpc":"2.0","method":"notifications/initialized"
                        })),
                    )
                    .await;
                ("initialize", version, reply)
            }
            Err(ProbeReply::MethodUnavailable) => {
                self.headers.insert(
                    "mcp-protocol-version",
                    HeaderValue::from_static(MODERN_PROTOCOL),
                );
                let reply = self
                    .call("server/discover", modern_meta())
                    .await
                    .map_err(|_| ())?;
                let versions = reply["supportedVersions"].as_array().ok_or(())?;
                if !versions
                    .iter()
                    .any(|value| value.as_str() == Some(MODERN_PROTOCOL))
                {
                    return Err(());
                }
                ("server_discover", MODERN_PROTOCOL.to_owned(), reply)
            }
            Err(ProbeReply::Invalid) => return Err(()),
        };
        let caps = initialization["capabilities"].as_object().ok_or(())?;
        let info = if path == "initialize" {
            &initialization["serverInfo"]
        } else {
            &initialization["_meta"]["io.modelcontextprotocol/serverInfo"]
        };
        if !info["name"].is_string() || !info["version"].is_string() {
            return Err(());
        }
        let mut counts = serde_json::Map::new();
        let mut partial = false;
        for (entity, method) in [
            ("tools", "tools/list"),
            ("resources", "resources/list"),
            ("prompts", "prompts/list"),
        ] {
            if !caps.contains_key(entity) {
                continue;
            }
            let params = if path == "server_discover" {
                modern_meta()
            } else {
                json!({})
            };
            if let Ok(reply) = self.call(method, params).await {
                if let Some(items) = reply[entity].as_array() {
                    counts.insert(entity.into(), items.len().into());
                }
                partial |= reply["nextCursor"].is_string();
            }
        }
        let raw = initialization.to_string();
        let output = json!({
            "negotiationPath":path,"protocolVersion":version,"serverName":info["name"],
            "serverVersion":info["version"],"capabilities":caps,"componentCounts":counts,
            "countsPartial":partial,"rawPreview":raw.chars().take(4096).collect::<String>(),
        });
        Ok(output.as_object().expect("handshake fields").clone())
    }

    async fn call(&mut self, method: &str, params: Value) -> Result<Value, ProbeReply> {
        let id = self.next_id;
        self.next_id += 1;
        let response = self
            .send(
                Method::POST,
                Some(json!({
                    "jsonrpc":"2.0","id":id,"method":method,"params":params,
                })),
            )
            .await
            .map_err(|_| ProbeReply::Invalid)?;
        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            return Err(ProbeReply::MethodUnavailable);
        }
        if !response.status().is_success() {
            return Err(ProbeReply::Invalid);
        }
        if let Some(session) = response.headers().get("mcp-session-id") {
            self.headers.insert("mcp-session-id", session.clone());
        }
        let event_stream = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"));
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .map_err(|_| ProbeReply::Invalid)?;
        let data: Value = if event_stream {
            let text = std::str::from_utf8(&bytes).map_err(|_| ProbeReply::Invalid)?;
            text.lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
                .find(|reply| reply["id"].as_u64() == Some(u64::from(id)))
                .ok_or(ProbeReply::Invalid)?
        } else {
            serde_json::from_slice(&bytes).map_err(|_| ProbeReply::Invalid)?
        };
        if data["id"].as_u64() != Some(u64::from(id)) {
            return Err(ProbeReply::Invalid);
        }
        if let Some(result) = data.get("result") {
            return Ok(result.clone());
        }
        if data["error"]["code"].as_i64() == Some(-32601) {
            Err(ProbeReply::MethodUnavailable)
        } else {
            Err(ProbeReply::Invalid)
        }
    }

    async fn send(&self, method: Method, payload: Option<Value>) -> Result<Response, ()> {
        let mut request = Request::builder().uri(self.target).method(method);
        let headers = request.headers_mut().ok_or(())?;
        headers.extend(self.headers.clone());
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        let body = if let Some(payload) = payload {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            if let Some(method) = payload["method"].as_str() {
                headers.insert("mcp-method", HeaderValue::from_str(method).map_err(|_| ())?);
            }
            Body::from(payload.to_string())
        } else {
            Body::empty()
        };
        let mut request = request.body(body).map_err(|_| ())?;
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
        self.router
            .clone()
            .oneshot(request)
            .await
            .map_err(|never| match never {})
    }
}

enum ProbeReply {
    Invalid,
    MethodUnavailable,
}

fn modern_meta() -> Value {
    json!({"_meta":{"io.modelcontextprotocol/protocolVersion":MODERN_PROTOCOL,
                    "io.modelcontextprotocol/clientCapabilities":{}}})
}
