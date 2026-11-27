// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, error::Error, sync::Arc};

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};

use super::compression::{Coding, Compression};
use crate::config::{allowlist, flag, parse, value};

const EXPOSE_HEADERS: &str = "Content-Length, X-Request-ID, X-Password-Change-Required";
const PREFLIGHT_METHODS: &str = "GET, POST, PUT, DELETE, OPTIONS";
const PREFLIGHT_VARY: &str = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Access-Control-Request-Private-Network";

pub(super) struct ResponsePolicy {
    cors: Cors,
    security: Option<SecurityHeaders>,
    compression: Option<Compression>,
}

impl ResponsePolicy {
    pub(super) fn from_env(port: u16) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Ok(Self {
            cors: Cors {
                origins: allowed_origins(port)?,
                credentials: flag("CORS_ALLOW_CREDENTIALS")?.unwrap_or(true),
            },
            security: flag("SECURITY_HEADERS_ENABLED")?
                .unwrap_or(true)
                .then(SecurityHeaders::from_env)
                .transpose()?,
            compression: Compression::from_env()?,
        })
    }

    pub(super) fn apply(self, router: Router) -> Router {
        router.layer(middleware::from_fn_with_state(Arc::new(self), respond))
    }
}

pub(crate) fn allowed_origins(port: u16) -> Result<HashSet<String>, Box<dyn Error + Send + Sync>> {
    if std::env::var_os("ALLOWED_ORIGINS").is_some() {
        return allowlist("ALLOWED_ORIGINS");
    }
    if value("ENVIRONMENT", "development")? == "development" {
        return Ok([
            "http://localhost".to_owned(),
            "http://localhost:3000".to_owned(),
            "http://localhost:8080".to_owned(),
            "http://127.0.0.1:3000".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
            format!("http://localhost:{port}"),
            format!("http://127.0.0.1:{port}"),
        ]
        .into());
    }
    let domain = reqwest::Url::parse(&value("APP_DOMAIN", "http://localhost:4444")?)?;
    let host = domain.host_str().ok_or("invalid APP_DOMAIN")?;
    Ok([
        format!("https://{host}"),
        format!("https://app.{host}"),
        format!("https://admin.{host}"),
    ]
    .into())
}

async fn respond(
    State(policy): State<Arc<ResponsePolicy>>,
    request: Request,
    next: Next,
) -> Response {
    let origin = request.headers().get(header::ORIGIN).cloned();
    let https = request.uri().scheme_str() == Some("https")
        || request
            .headers()
            .get("x-forwarded-proto")
            .is_some_and(|value| value == "https");
    let path = request.uri().path().to_owned();
    let compressor = policy
        .compression
        .as_ref()
        .filter(|compression| compression.supports_path(&path));
    let coding = compressor.and_then(|_| Coding::select(request.headers()));
    let mut response = match policy.cors.preflight(&request, origin.as_ref()) {
        Some(preflight) => preflight,
        None => {
            let mut response = next.run(request).await;
            if response.status() == StatusCode::SWITCHING_PROTOCOLS {
                return response;
            }
            policy.cors.simple(response.headers_mut(), origin.as_ref());
            response
        }
    };
    if let Some(compressor) = compressor {
        response = compressor.apply(response, coding).await;
    }
    if let Some(security) = &policy.security {
        security.apply(
            response.headers_mut(),
            &policy.cors,
            origin.as_ref(),
            &path,
            https,
        );
    }
    response
}

struct Cors {
    origins: HashSet<String>,
    credentials: bool,
}

impl Cors {
    fn exact(&self, origin: &HeaderValue) -> bool {
        origin
            .to_str()
            .is_ok_and(|origin| self.origins.contains(origin))
    }

    fn preflight(&self, request: &Request, origin: Option<&HeaderValue>) -> Option<Response> {
        if request.method() != Method::OPTIONS {
            return None;
        }
        let origin = origin?;
        let request_headers = request.headers();
        let method = request_headers.get(header::ACCESS_CONTROL_REQUEST_METHOD)?;
        let wildcard = self.origins.contains("*");
        let mut headers = HeaderMap::new();
        let mut failures = Vec::new();
        if wildcard || self.exact(origin) {
            let value = if wildcard && !self.credentials {
                HeaderValue::from_static("*")
            } else {
                origin.clone()
            };
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
        } else {
            failures.push("origin");
        }
        if !matches!(
            method.as_bytes(),
            b"GET" | b"POST" | b"PUT" | b"DELETE" | b"OPTIONS"
        ) {
            failures.push("method");
        }
        if let Some(requested) = request_headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
        }
        if request_headers.contains_key("access-control-request-private-network") {
            failures.push("private-network");
        }
        self.add_credentials(&mut headers);
        headers.insert(header::VARY, HeaderValue::from_static(PREFLIGHT_VARY));
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(PREFLIGHT_METHODS),
        );
        Some(if failures.is_empty() {
            (headers, "OK").into_response()
        } else {
            (
                StatusCode::BAD_REQUEST,
                headers,
                format!("Disallowed CORS {}", failures.join(", ")),
            )
                .into_response()
        })
    }

    fn simple(&self, headers: &mut HeaderMap, origin: Option<&HeaderValue>) {
        if let Some(origin) = origin {
            self.add_credentials(headers);
            headers.insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                HeaderValue::from_static(EXPOSE_HEADERS),
            );
            if self.origins.contains("*") {
                let value = if self.credentials {
                    origin.clone()
                } else {
                    HeaderValue::from_static("*")
                };
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            } else if self.exact(origin) {
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
            }
        }
        add_vary(headers, "Origin");
    }

    fn add_credentials(&self, headers: &mut HeaderMap) {
        if self.credentials {
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
    }
}

struct SecurityHeaders {
    no_sniff: bool,
    frame: Option<HeaderValue>,
    xss_protection: bool,
    prevent_download_execution: bool,
    hsts: Option<HeaderValue>,
    remove_server_headers: bool,
    root: String,
    random: SystemRandom,
}

impl SecurityHeaders {
    fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let frame = value("X_FRAME_OPTIONS", "DENY")?;
        let frame = frame.trim();
        let frame = (!matches!(frame.to_ascii_lowercase().as_str(), "" | "none" | "null"))
            .then(|| HeaderValue::from_str(frame))
            .transpose()
            .map_err(|_| "invalid X_FRAME_OPTIONS")?;
        let hsts = if flag("HSTS_ENABLED")?.unwrap_or(true) {
            let age = parse("HSTS_MAX_AGE", 31_536_000_u64)?;
            let subdomains = if flag("HSTS_INCLUDE_SUBDOMAINS")?.unwrap_or(true) {
                "; includeSubDomains"
            } else {
                ""
            };
            Some(HeaderValue::from_str(&format!(
                "max-age={age}{subdomains}"
            ))?)
        } else {
            None
        };
        Ok(Self {
            no_sniff: flag("X_CONTENT_TYPE_OPTIONS_ENABLED")?.unwrap_or(true),
            frame,
            xss_protection: flag("X_XSS_PROTECTION_ENABLED")?.unwrap_or(true),
            prevent_download_execution: flag("X_DOWNLOAD_OPTIONS_ENABLED")?.unwrap_or(true),
            hsts,
            remove_server_headers: flag("REMOVE_SERVER_HEADERS")?.unwrap_or(true),
            root: value("APP_ROOT_PATH", "")?.trim_end_matches('/').to_owned(),
            random: SystemRandom::new(),
        })
    }

    fn apply(
        &self,
        headers: &mut HeaderMap,
        cors: &Cors,
        origin: Option<&HeaderValue>,
        path: &str,
        https: bool,
    ) {
        if self.no_sniff {
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
        }
        if let Some(frame) = &self.frame {
            headers.insert(header::X_FRAME_OPTIONS, frame.clone());
        }
        if self.xss_protection {
            headers.insert(header::X_XSS_PROTECTION, HeaderValue::from_static("0"));
        }
        if self.prevent_download_execution {
            headers.insert("x-download-options", HeaderValue::from_static("noopen"));
        }
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );

        let path = path
            .strip_prefix(&self.root)
            .filter(|suffix| suffix.starts_with('/'))
            .unwrap_or(path);
        if !matches!(path, "/docs" | "/redoc" | "/openapi.json") {
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                self.content_security_policy(),
            );
        }
        if https && let Some(hsts) = &self.hsts {
            headers.insert(header::STRICT_TRANSPORT_SECURITY, hsts.clone());
        }
        if self.remove_server_headers {
            headers.remove(header::SERVER);
            headers.remove("x-powered-by");
        }
        if let Some(origin) = origin.filter(|value| cors.exact(value)) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
            cors.add_credentials(headers);
            headers.insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                HeaderValue::from_static("Content-Length, X-Request-ID"),
            );
            add_vary(headers, "Origin");
        }
        if !cacheable(path) {
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store, private"),
            );
            headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
            add_vary(headers, "Authorization");
        }
    }

    fn content_security_policy(&self) -> HeaderValue {
        let mut bytes = [0; 16];
        let script = if self.random.fill(&mut bytes).is_ok() {
            format!(
                "script-src-elem 'self' 'nonce-{}'",
                URL_SAFE_NO_PAD.encode(bytes)
            )
        } else {
            tracing::error!("could not generate Content Security Policy nonce");
            "script-src-elem 'self'".to_owned()
        };
        let mut policy = format!(
            "default-src 'self'; {script}; script-src-attr 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' ws: wss: https:;"
        );
        if let Some(frame) = self.frame.as_ref().and_then(|value| value.to_str().ok()) {
            let upper = frame.to_ascii_uppercase();
            let ancestors = match upper.as_str() {
                "SAMEORIGIN" => "'self'",
                "ALLOW-ALL" => "* file: http: https:",
                _ if upper.starts_with("ALLOW-FROM") => {
                    frame.split_once(' ').map_or("'none'", |(_, uri)| uri)
                }
                _ => "'none'",
            };
            policy.push_str(" frame-ancestors ");
            policy.push_str(ancestors);
            policy.push(';');
        }
        HeaderValue::from_str(&policy).expect("validated frame policy and ASCII directives")
    }
}

fn cacheable(path: &str) -> bool {
    matches!(path, "/health" | "/ready")
        || path.starts_with("/static/")
        || path.starts_with("/.well-known/")
        || path
            .strip_prefix("/servers/")
            .or_else(|| path.strip_prefix("/v1/virtual-servers/"))
            .and_then(|suffix| suffix.split_once('/'))
            .is_some_and(|(server, resource)| {
                !server.is_empty() && resource.starts_with(".well-known/")
            })
}

pub(super) fn add_vary(headers: &mut HeaderMap, field: &str) {
    let mut values = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').map(str::trim))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values
        .iter()
        .any(|value| *value == "*" || value.eq_ignore_ascii_case(field))
    {
        return;
    }
    values.push(field);
    if let Ok(vary) = HeaderValue::from_str(&values.join(", ")) {
        headers.insert(header::VARY, vary);
    }
}
