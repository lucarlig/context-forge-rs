// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use axum::{
    body::to_bytes,
    http::{Uri, request::Parts},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

use super::*;

pub(super) const QUERY_ENCODE: AsciiSet = NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

pub(super) struct Form(HashMap<String, Zeroizing<String>>);

impl Form {
    pub(super) async fn from_request(request: Request) -> Result<(Parts, Self), AccountError> {
        let (parts, body) = request.into_parts();
        let mut fields = HashMap::new();
        if header_text(&parts.headers, header::CONTENT_TYPE).is_some_and(|value| {
            value
                .to_ascii_lowercase()
                .starts_with("application/x-www-form-urlencoded")
        }) {
            let bytes = Zeroizing::new(
                to_bytes(body, 65_536)
                    .await
                    .map_err(|_| {
                        AccountError::detail(StatusCode::PAYLOAD_TOO_LARGE, "Form body too large")
                    })?
                    .to_vec(),
            );
            fields.extend(
                url::form_urlencoded::parse(&bytes)
                    .map(|(key, value)| (key.into_owned(), Zeroizing::new(value.into_owned()))),
            );
        }
        Ok((parts, Self(fields)))
    }

    pub(super) fn get(&self, name: &str) -> &str {
        self.0.get(name).map_or("", |field| field.as_str())
    }
}

pub(super) fn nonce(headers: &HeaderMap) -> Result<String, AccountError> {
    if let Some(token) = cookie(headers, CSRF_COOKIE).filter(|value| value.len() >= 32) {
        return Ok(token.to_owned());
    }
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AccountError::unavailable())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) fn csrf(
    settings: &BrowserSettings,
    request: &Parts,
    form: &Form,
    login: bool,
) -> Result<(), AccountError> {
    if matches!(
        request.method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) || !login && auth_cookie(&request.headers).is_none()
    {
        return Ok(());
    }
    let headers = &request.headers;
    let origin_matches = header_text(headers, header::ORIGIN)
        .or_else(|| header_text(headers, header::REFERER))
        .and_then(origin)
        .is_some_and(|candidate| {
            let scheme = crate::http_boundary::public_scheme(headers, &request.uri);
            let host = header_text(headers, header::HOST)
                .or_else(|| request.uri.authority().map(|authority| authority.as_str()));
            host.and_then(|host| origin(&format!("{scheme}://{host}")))
                .as_ref()
                == Some(&candidate)
                || settings.origins.contains(&candidate)
        });
    let forbidden = |reason| AccountError::detail(StatusCode::FORBIDDEN, reason);
    if !origin_matches {
        return Err(forbidden("CSRF origin validation failed"));
    }
    let Some(proof) = cookie(headers, CSRF_COOKIE) else {
        return Err(forbidden("CSRF token cookie missing"));
    };
    let submitted = header_text(headers, HeaderName::from_static("x-csrf-token"))
        .unwrap_or_else(|| form.get("csrf_token"));
    if !bool::from(proof.as_bytes().ct_eq(submitted.as_bytes())) {
        return Err(forbidden("CSRF token validation failed"));
    }
    Ok(())
}

pub(super) fn allowed_origin(value: &str) -> Option<String> {
    if value.is_empty() || value == "*" || value.eq_ignore_ascii_case("null") {
        None
    } else if value.contains("://") {
        origin(value)
    } else {
        origin(&format!("https://{value}"))
    }
}

fn origin(value: &str) -> Option<String> {
    let (_, authority) = value.split_once("://")?;
    if authority.is_empty() || authority.starts_with('/') || value.contains('\\') {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

pub(super) fn header_text(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
}

pub(super) fn query(uri: &Uri) -> HashMap<String, String> {
    url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

pub(super) fn render(context: minijinja::Value) -> Result<Response, AccountError> {
    static TEMPLATES: std::sync::LazyLock<minijinja::Environment<'static>> =
        std::sync::LazyLock::new(|| {
            let mut environment = minijinja::Environment::new();
            environment.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
            environment
                .add_template("browser.html", include_str!("browser.html"))
                .expect("valid browser template");
            environment
        });
    let html = TEMPLATES
        .get_template("browser.html")
        .and_then(|template| template.render(context))
        .map_err(|error| {
            tracing::error!(%error, "could not render admin page");
            AccountError::unavailable()
        })?;
    Ok(([(header::CACHE_CONTROL, "no-store, private")], Html(html)).into_response())
}

pub(super) fn login_error(error: Option<&str>) -> Option<&'static str> {
    Some(match error? {
        "missing_fields" => "Enter your email and password.",
        "invalid_credentials" => "Invalid email or password.",
        "sso_required" => "Sign in through your identity provider.",
        "token_too_large" => "Your session cookie exceeds the browser limit.",
        "admin_required" => "Admin privileges required.",
        "account_disabled" => "Your account is disabled.",
        "session_expired" | "token_revoked" => "Your session ended. Sign in again.",
        _ => "Sign-in failed. Try again.",
    })
}

pub(super) fn password_error(error: Option<&str>) -> Option<&'static str> {
    Some(match error? {
        "missing_fields" => "Complete all password fields.",
        "mismatch" => "The new passwords do not match.",
        "invalid_password" => "Your current password is incorrect.",
        "weak_password" => "Choose a stronger password.",
        _ => "Your password could not be changed.",
    })
}
