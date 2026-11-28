// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use jiff::{fmt::rfc2822, tz::Offset};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde_json::json;

use crate::config::{legacy_api_enabled, value};

const DEFAULT_SUNSET: &str = "Sat, 26 Sep 2026 00:00:00 GMT";
const LINK_ENCODING: &AsciiSet = &CONTROLS.add(b' ').add(b'<').add(b'>').add(b'"').add(b'\\');

const SHIM_PREFIXES: &[&str] = &[
    "protocol",
    "tools",
    "resources",
    "prompts",
    "gateways",
    "roots",
    "servers",
    "metrics",
    "tags",
    "export",
    "import",
    "search",
    "a2a",
    "observability",
    "reverse-proxy",
    "cancellation",
    "toolops",
    "auth",
    "teams",
    "users",
    "tokens",
    "rbac",
    "compliance",
    "admin",
    "llmchat",
    "llm",
];

pub(super) enum LegacyApi {
    Disabled,
    Enabled(Option<HeaderValue>),
}

impl LegacyApi {
    pub(super) fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        if !legacy_api_enabled()? {
            return Ok(Self::Disabled);
        }

        let configured = value("LEGACY_API_SUNSET_DATE", DEFAULT_SUNSET)?;
        let sunset = rfc2822::parse(configured.trim())
            .ok()
            .filter(|date| date.offset() == Offset::UTC)
            .map(|date| {
                let formatted = date.strftime("%a, %d %b %Y %T GMT").to_string();
                HeaderValue::from_str(&formatted).expect("formatted HTTP date")
            });
        if sunset.is_none() {
            tracing::warn!(
                "invalid LEGACY_API_SUNSET_DATE, omitting legacy API deprecation headers"
            );
        }
        Ok(Self::Enabled(sunset))
    }

    pub(super) fn filter_routes(&self, router: Router) -> Router {
        if matches!(self, Self::Disabled) {
            router.layer(middleware::from_fn(reject_legacy))
        } else {
            router
        }
    }

    pub(super) fn decorate(self, router: Router) -> Router {
        if let Self::Enabled(Some(sunset)) = self {
            router.layer(middleware::from_fn_with_state(sunset, deprecate))
        } else {
            router
        }
    }
}

fn is_shim(path: &str) -> bool {
    path.strip_prefix('/')
        .and_then(|path| path.split('/').next())
        .is_some_and(|prefix| SHIM_PREFIXES.contains(&prefix))
}

fn is_unversioned_server_route(path: &str) -> bool {
    path.strip_prefix("/servers/")
        .and_then(|path| path.split_once('/'))
        .is_some_and(|(id, suffix)| {
            !id.is_empty()
                && matches!(
                    suffix,
                    "mcp" | "mcp/" | ".well-known/oauth-protected-resource"
                )
        })
}

async fn reject_legacy(request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if (is_shim(path) && !is_unversioned_server_route(path)) || path == "/version" {
        return (StatusCode::NOT_FOUND, Json(json!({"detail":"Not Found"}))).into_response();
    }
    next.run(request).await
}

async fn deprecate(State(sunset): State<HeaderValue>, request: Request, next: Next) -> Response {
    let raw_path = request.uri().path();
    let path = percent_decode_str(raw_path).decode_utf8_lossy();
    if !is_shim(&path)
        || path.contains("/.well-known")
        || path.bytes().any(|byte| byte.is_ascii_control())
    {
        return next.run(request).await;
    }

    let canonical = format!("/v1{}", utf8_percent_encode(raw_path, LINK_ENCODING));
    let mut response = next.run(request).await;
    if response.status().is_success() || response.status().is_redirection() {
        let headers = response.headers_mut();
        let append = |headers: &mut axum::http::HeaderMap, name: &'static str, value: String| {
            headers.append(
                name,
                HeaderValue::from_str(&value).expect("valid legacy API header"),
            );
        };
        headers.append("deprecation", HeaderValue::from_static("true"));
        append(
            headers,
            "link",
            format!("<{canonical}>; rel=\"successor-version\""),
        );
        append(
            headers,
            "x-deprecated-endpoint",
            format!(
                "This endpoint is deprecated. Use {canonical} instead. It will be removed after {}.",
                sunset.to_str().expect("formatted HTTP date"),
            ),
        );
        headers.append("sunset", sunset);
    }
    response
}
