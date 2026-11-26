// SPDX-License-Identifier: Apache-2.0

use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use rmcp::model::{ClientCapabilities, Implementation};
use serde::Deserialize;
use serde_json::Value;

use crate::mcp::rpc_error;

const VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";

pub(crate) fn reject_invalid_request(headers: &HeaderMap, body: &Value) -> Option<Response> {
    let method = body.get("method")?.as_str()?;
    let id = body.get("id")?;
    if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || !(id.is_string() || id.is_i64() || id.is_u64())
    {
        return None;
    }

    let mismatch =
        |message: &str| rpc_error(StatusCode::BAD_REQUEST, id, -32020, message, None::<()>);
    for name in ["mcp-protocol-version", "mcp-method", "mcp-name"] {
        if headers.get_all(name).iter().nth(1).is_some() {
            return Some(mismatch(&format!("{name} header appears more than once")));
        }
    }

    let invalid =
        |message: &str| rpc_error(StatusCode::BAD_REQUEST, id, -32602, message, None::<()>);
    let Some(meta) = body["params"]["_meta"].as_object() else {
        return Some(invalid(&format!(
            "params._meta must be an object carrying the required '{VERSION}' and '{CAPABILITIES}' envelope keys"
        )));
    };
    let missing: Vec<_> = [VERSION, CAPABILITIES]
        .into_iter()
        .filter(|name| !meta.contains_key(*name))
        .collect();
    if !missing.is_empty() {
        return Some(invalid(&format!(
            "params._meta is missing the required envelope key(s): {}",
            missing.join(", ")
        )));
    }

    let header = |name: &str| headers.get(name).and_then(|header| header.to_str().ok());
    if header("mcp-protocol-version") != meta[VERSION].as_str() {
        return Some(mismatch(
            "mcp-protocol-version header does not match the request envelope's protocol version",
        ));
    }
    if header("mcp-method") != Some(method) {
        return Some(mismatch(
            "mcp-method header does not match the request body's method",
        ));
    }
    if let Some(name_key) = name_parameter(method)
        && let Some(name) = body["params"].get(name_key).filter(|name| !name.is_null())
        && (name.as_str().is_none() || decode_name(header("mcp-name")).as_deref() != name.as_str())
    {
        return Some(mismatch(&format!(
            "mcp-name header does not match the request body's '{name_key}' parameter"
        )));
    }

    if !meta[CAPABILITIES].is_object()
        || ClientCapabilities::deserialize(&meta[CAPABILITIES]).is_err()
        || meta.get(CLIENT_INFO).is_some_and(|info| {
            !info.is_null() && (!info.is_object() || Implementation::deserialize(info).is_err())
        })
    {
        return Some(rpc_error(
            StatusCode::BAD_REQUEST,
            id,
            -32602,
            "Invalid request parameters",
            Some(""),
        ));
    }
    if matches!(method, "initialize" | "logging/setLevel") {
        return Some(rpc_error(
            StatusCode::NOT_FOUND,
            id,
            -32601,
            "Method not found",
            Some(method),
        ));
    }
    None
}

fn name_parameter(method: &str) -> Option<&'static str> {
    match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => Some("uri"),
        "tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId"),
        _ => None,
    }
}

fn decode_name(value: Option<&str>) -> Option<String> {
    let value = value?;
    match value
        .strip_prefix("=?base64?")
        .and_then(|value| value.strip_suffix("?="))
    {
        Some(value) => {
            let decoded = BASE64_STANDARD.decode(value).ok()?;
            if BASE64_STANDARD.encode(&decoded) != value {
                return None;
            }
            String::from_utf8(decoded).ok()
        }
        None => Some(value.to_owned()),
    }
}
