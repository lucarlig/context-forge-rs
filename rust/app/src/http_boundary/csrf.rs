// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, error::Error, fmt::Write, sync::Arc};

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, Method, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use jiff::Timestamp;
use percent_encoding::percent_decode_str;
use ring::hmac;
use serde_json::json;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    access::{Authorizer, auth_cookie, cookie},
    config::{allowlist, flag, parse, value},
};

const INTERNAL_MCP: &str = "/_internal/mcp/";
pub(crate) const ADMIN_CSRF_COOKIE: &str = "mcpgateway_csrf_token";
const EXEMPT: &[&str] = &[
    "/health",
    "/auth/login",
    "/auth/logout",
    "/auth/email/login",
    "/auth/email/register",
    "/auth/email/forgot-password",
    "/auth/email/reset-password",
    "/admin",
    "/oauth/fetch-tools",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/metrics",
    "/mcp/",
    "/sse",
    "/message",
    "/rpc",
    "/api/metrics/",
    "/toolops/",
    "/tokens",
    "/teams/",
    "/llmchat/",
    "/api/logs/",
];

pub(crate) fn browser_proof_valid(
    app_origin: &str,
    trusted_origins: &HashSet<String>,
    uri: &Uri,
    headers: &HeaderMap,
) -> bool {
    let Some(submitted) = text_header(headers, &HeaderName::from_static("x-csrf-token")) else {
        return false;
    };
    let Some(proof) = cookie(headers, ADMIN_CSRF_COOKIE) else {
        return false;
    };
    if !bool::from(proof.as_bytes().ct_eq(submitted.as_bytes())) {
        return false;
    }
    let Some(candidate) = text_header(headers, &header::ORIGIN)
        .or_else(|| text_header(headers, &header::REFERER))
        .and_then(browser_origin)
    else {
        return false;
    };
    if candidate == app_origin
        || trusted_origins
            .iter()
            .any(|trusted| browser_origin(trusted).as_deref() == Some(candidate.as_str()))
    {
        return true;
    }
    let loopback = url::Url::parse(app_origin).ok().is_some_and(|app| {
        matches!(
            app.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "0.0.0.0")
        )
    });
    let host =
        text_header(headers, &header::HOST).or_else(|| uri.authority().map(|value| value.as_str()));
    loopback
        && host
            .and_then(|host| {
                browser_origin(&format!("{}://{host}", super::public_scheme(headers, uri)))
            })
            .as_deref()
            == Some(candidate.as_str())
}

fn browser_origin(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none())
    .then(|| url.origin().ascii_serialization())
}

pub(crate) struct CsrfTokens {
    key: Option<hmac::Key>,
    pub(crate) seconds: i64,
    pub(crate) cookie_name: String,
}

impl CsrfTokens {
    pub(crate) fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let seconds = parse("CSRF_TOKEN_EXPIRY", 3600)?;
        if seconds < 1 {
            return Err("invalid CSRF token expiry".into());
        }
        let mut secret = Zeroizing::new(value("CSRF_SECRET_KEY", "")?);
        if secret.is_empty() {
            secret = Zeroizing::new(value("JWT_SECRET_KEY", "")?);
        }
        Ok(Self {
            key: (!secret.is_empty()).then(|| hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes())),
            seconds,
            cookie_name: value("CSRF_COOKIE_NAME", "mcpgateway_csrf_token")?,
        })
    }

    pub(crate) fn issue(&self, email: &str, session: &str, now: i64) -> Option<String> {
        self.sign(email, session, self.window(now))
    }

    fn verify(&self, token: &str, email: &str, session: &str, now: i64) -> bool {
        let window = self.window(now);
        [window, window - self.seconds].into_iter().any(|window| {
            self.sign(email, session, window)
                .is_some_and(|expected| bool::from(token.as_bytes().ct_eq(expected.as_bytes())))
        })
    }

    fn window(&self, now: i64) -> i64 {
        now - now.rem_euclid(self.seconds)
    }

    fn sign(&self, email: &str, session: &str, window: i64) -> Option<String> {
        let key = self.key.as_ref()?;
        let message = format!("{email}:{session}:{window}");
        let signature = hmac::sign(key, message.as_bytes());
        let mut token = String::with_capacity(64);
        for byte in signature.as_ref() {
            write!(token, "{byte:02x}").ok()?;
        }
        Some(token)
    }
}

pub(super) struct Csrf {
    auth: Arc<Authorizer>,
    tokens: CsrfTokens,
    token_header: HeaderName,
    auth_header: HeaderName,
    proxy_user_header: Option<HeaderName>,
    exempt: HashSet<String>,
    origins: Option<HashSet<String>>,
}

impl Csrf {
    pub(super) fn from_env(
        auth: Arc<Authorizer>,
    ) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        if !flag("CSRF_ENABLED")?.unwrap_or(true) || !flag("AUTH_REQUIRED")?.unwrap_or(true) {
            return Ok(None);
        }
        let mut exempt = if std::env::var_os("CSRF_EXEMPT_PATHS").is_some() {
            allowlist("CSRF_EXEMPT_PATHS")?
        } else {
            EXEMPT.iter().map(|path| (*path).to_owned()).collect()
        };
        exempt.insert(INTERNAL_MCP.to_owned());
        let read_header = |name, default| -> Result<HeaderName, Box<dyn Error + Send + Sync>> {
            HeaderName::try_from(value(name, default)?)
                .map_err(|_| format!("invalid {name}").into())
        };
        let proxy_user_header = if !flag("MCP_CLIENT_AUTH_ENABLED")?.unwrap_or(true)
            && flag("TRUST_PROXY_AUTH")?.unwrap_or(false)
            && flag("TRUST_PROXY_AUTH_DANGEROUSLY")?.unwrap_or(false)
        {
            Some(read_header("PROXY_USER_HEADER", "X-Authenticated-User")?)
        } else {
            None
        };
        let origins = if flag("CSRF_CHECK_REFERER")?.unwrap_or(true) {
            let mut origins = allowlist("CSRF_TRUSTED_ORIGINS")?;
            let domain = url::Url::parse(&value("APP_DOMAIN", "http://localhost:4444")?)?;
            origins.insert(domain.origin().ascii_serialization());
            Some(origins)
        } else {
            None
        };
        Ok(Some(Self {
            auth,
            tokens: CsrfTokens::from_env()?,
            token_header: read_header("CSRF_TOKEN_NAME", "X-CSRF-Token")?,
            auth_header: read_header("AUTH_HEADER_NAME", "Authorization")?,
            proxy_user_header,
            exempt,
            origins,
        }))
    }

    pub(super) fn apply(self, router: Router) -> Router {
        router.layer(middleware::from_fn_with_state(Arc::new(self), enforce))
    }

    fn exempt_path(&self, path: &str) -> bool {
        self.exempt.iter().any(|exempt| {
            path == exempt
                || path
                    .strip_prefix(exempt.trim_end_matches('/'))
                    .is_some_and(|suffix| suffix.starts_with('/'))
        })
    }

    async fn allows(&self, method: &Method, path: &str, headers: &HeaderMap) -> bool {
        let path = percent_decode_str(path).decode_utf8_lossy();
        if matches!(
            *method,
            Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
        ) || self.exempt_path(&path)
        {
            return true;
        }
        let auth = headers
            .get(&self.auth_header)
            .filter(|value| !value.is_empty());
        if auth
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.split_once(' ').is_some_and(|(scheme, credential)| {
                    scheme.eq_ignore_ascii_case("bearer") && !credential.trim().is_empty()
                })
            })
        {
            return true;
        }
        let session = auth_cookie(headers);
        let proxy = self
            .proxy_user_header
            .as_ref()
            .and_then(|name| headers.get(name))
            .is_some_and(|value| !value.is_empty());
        if auth.is_none() && session.is_none() && !proxy {
            return true;
        }
        let Some(token) =
            text_header(headers, &self.token_header).filter(|token| token.len() == 64)
        else {
            return false;
        };
        let Some(cookie_token) = cookie(headers, &self.tokens.cookie_name) else {
            return false;
        };
        if !bool::from(token.as_bytes().ct_eq(cookie_token.as_bytes())) {
            return false;
        }
        let origin_allowed = self.origins.as_ref().is_none_or(|allowed| {
            text_header(headers, &header::REFERER)
                .or_else(|| text_header(headers, &header::ORIGIN))
                .and_then(origin)
                .is_some_and(|origin| allowed.contains(&origin))
        });
        if !origin_allowed {
            return false;
        }
        let Some(session) = session else { return false };
        let Some((email, session)) = self.auth.csrf_identity(session).await else {
            return false;
        };
        self.tokens
            .verify(token, &email, &session, Timestamp::now().as_second())
    }
}

fn text_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}

fn origin(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    let (_, rest) = value.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    (matches!(url.scheme(), "http" | "https") && !authority.is_empty() && !authority.contains('\\'))
        .then(|| format!("{}://{authority}", url.scheme()))
}

async fn enforce(State(csrf): State<Arc<Csrf>>, request: Request, next: Next) -> Response {
    if csrf
        .allows(request.method(), request.uri().path(), request.headers())
        .await
    {
        return next.run(request).await;
    }
    (
        StatusCode::FORBIDDEN,
        Json(json!({"detail":"CSRF validation failed", "code":"CSRF_TOKEN_INVALID"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_tokens_bind_identity_and_accept_two_windows() {
        let tokens = CsrfTokens {
            key: Some(hmac::Key::new(hmac::HMAC_SHA256, b"csrf fixture")),
            seconds: 60,
            cookie_name: "fixture_csrf".to_owned(),
        };
        let email = "fixture@example.com";
        let token = tokens.issue(email, "first", 119).unwrap();
        assert!(tokens.verify(&token, email, "first", 119));
        assert!(tokens.verify(&token, email, "first", 120));
        assert!(!tokens.verify(&token, email, "first", 180));
        assert!(!tokens.verify(&token, email, "second", 120));
        assert!(!tokens.verify(&token, "other@example.com", "first", 120));
    }
}
