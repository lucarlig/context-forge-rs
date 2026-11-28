// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use axum::{
    body::to_bytes,
    extract::{DefaultBodyLimit, FromRequest, Multipart},
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

#[derive(Default)]
pub(super) struct Form(HashMap<String, Vec<Zeroizing<String>>>);

pub(super) const MAX_FORM_BYTES: usize = 65_536;

impl Form {
    pub(super) async fn from_request(request: Request) -> Result<(Parts, Self), AccountError> {
        let (parts, body) = request.into_parts();
        let mut form = Self(HashMap::new());
        if urlencoded(&parts.headers) {
            let bytes = Zeroizing::new(
                to_bytes(body, MAX_FORM_BYTES)
                    .await
                    .map_err(|_| {
                        AccountError::detail(StatusCode::PAYLOAD_TOO_LARGE, "Form body too large")
                    })?
                    .to_vec(),
            );
            for (key, value) in url::form_urlencoded::parse(&bytes) {
                form.insert(key.into_owned(), value.into_owned());
            }
        }
        Ok((parts, form))
    }

    pub(super) async fn from_catalog_request(
        request: Request,
    ) -> Result<(Parts, Self), AccountError> {
        if !has_media_type(request.headers(), "multipart/form-data") {
            return Self::from_request(request).await;
        }
        let (parts, body) = request.into_parts();
        let mut input = Request::new(body);
        input.headers_mut().insert(
            header::CONTENT_TYPE,
            parts.headers[header::CONTENT_TYPE].clone(),
        );
        DefaultBodyLimit::max(MAX_FORM_BYTES).apply(&mut input);
        let mut multipart = Multipart::from_request(input, &())
            .await
            .map_err(|error| AccountError::detail(error.status(), "Invalid multipart form"))?;
        let mut form = Self(HashMap::new());
        let invalid = |error: axum::extract::multipart::MultipartError| {
            AccountError::detail(error.status(), "Invalid multipart form")
        };
        while let Some(field) = multipart.next_field().await.map_err(invalid)? {
            if let Some(name) = field.name().map(str::to_owned)
                && field.file_name().is_none()
            {
                form.insert(name, field.text().await.map_err(invalid)?);
            }
        }
        Ok((parts, form))
    }

    fn insert(&mut self, name: String, value: String) {
        self.0.entry(name).or_default().push(Zeroizing::new(value));
    }

    pub(super) fn get(&self, name: &str) -> &str {
        self.value(name).unwrap_or("")
    }

    pub(super) fn value(&self, name: &str) -> Option<&str> {
        self.0.get(name)?.last().map(|field| field.as_str())
    }

    pub(super) fn values(&self, name: &str) -> impl Iterator<Item = &str> {
        self.0
            .get(name)
            .into_iter()
            .flatten()
            .map(|value| value.as_str())
    }
}

pub(super) fn urlencoded(headers: &HeaderMap) -> bool {
    has_media_type(headers, "application/x-www-form-urlencoded")
}

pub(super) fn has_media_type(headers: &HeaderMap, media_type: &str) -> bool {
    header_text(headers, header::CONTENT_TYPE)
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(media_type))
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
        .or_else(|| urlencoded(headers).then(|| form.get("csrf_token")))
        .unwrap_or("");
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
    render_template("browser.html", context)
}

pub(super) fn render_template(
    template: &str,
    context: minijinja::Value,
) -> Result<Response, AccountError> {
    static TEMPLATES: std::sync::LazyLock<minijinja::Environment<'static>> =
        std::sync::LazyLock::new(|| {
            let mut environment = minijinja::Environment::new();
            environment.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
            environment
                .add_template("browser.html", include_str!("browser.html"))
                .expect("valid browser template");
            environment
                .add_template("tokens.html", include_str!("tokens.html"))
                .expect("valid API tokens template");
            environment
                .add_template("users.html", include_str!("users.html"))
                .expect("valid users template");
            environment
                .add_template("teams.html", include_str!("teams.html"))
                .expect("valid teams template");
            environment
                .add_template("team_members.html", include_str!("team_members.html"))
                .expect("valid team members template");
            environment
                .add_template("team_requests.html", include_str!("team_requests.html"))
                .expect("valid team join requests template");
            environment
                .add_template("a2a.html", include_str!("a2a.html"))
                .expect("valid A2A catalog template");
            environment
                .add_template("a2a_edit.html", include_str!("a2a_edit.html"))
                .expect("valid A2A editor template");
            environment
                .add_template("grpc.html", include_str!("grpc.html"))
                .expect("valid gRPC catalog template");
            environment
                .add_template("grpc_edit.html", include_str!("grpc_edit.html"))
                .expect("valid gRPC editor template");
            environment
                .add_template("roots.html", include_str!("roots.html"))
                .expect("valid roots template");
            environment
                .add_template("registry.html", include_str!("registry.html"))
                .expect("valid MCP registry template");
            environment
        });
    let html = TEMPLATES
        .get_template(template)
        .and_then(|template| template.render(context))
        .map_err(|error| {
            tracing::error!(%error, "could not render admin page");
            AccountError::unavailable()
        })?;
    Ok(([(header::CACHE_CONTROL, "no-store, private")], Html(html)).into_response())
}

pub(super) fn render_with_proof(
    accounts: &Accounts,
    template: &str,
    context: minijinja::Value,
    proof: &str,
) -> Result<Response, AccountError> {
    let mut response = forms::render_template(template, context)?;
    sessions::set_proof(
        &mut response,
        settings_for(accounts),
        accounts.settings.token_seconds,
        proof,
    )?;
    Ok(response)
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
