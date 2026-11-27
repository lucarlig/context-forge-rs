// SPDX-License-Identifier: Apache-2.0

use axum::http::{HeaderValue, Uri};
use subtle::ConstantTimeEq;

use super::{storage::OAuthGateway, *};
use crate::{
    access::{OAuthBrowserSession, auth_cookie, cookie},
    http_boundary::{csrf::ADMIN_CSRF_COOKIE, public_scheme},
    jwt::TokenUse,
};

pub(super) async fn fetch_tools(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    browser: Option<Extension<OAuthBrowserSession>>,
    Path(id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    if browser.is_some() && !csrf_valid(&service.gateway_oauth, &uri, &headers) {
        return CatalogApiError::detail(StatusCode::FORBIDDEN, "CSRF validation failed")
            .into_response();
    }
    super::fetch_tools(service, principal, id, headers).await
}

fn csrf_valid(settings: &GatewayOAuthSettings, uri: &Uri, headers: &HeaderMap) -> bool {
    let header = |name| headers.get(name).and_then(|value| value.to_str().ok());
    let submitted = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok());
    let Some(submitted) = submitted.filter(|token| !token.is_empty()) else {
        return false;
    };
    let Some(proof) = cookie(headers, ADMIN_CSRF_COOKIE) else {
        return false;
    };
    if !bool::from(proof.as_bytes().ct_eq(submitted.as_bytes())) {
        return false;
    }
    let Some(candidate) = header(header::ORIGIN)
        .or_else(|| header(header::REFERER))
        .and_then(origin)
    else {
        return false;
    };
    if candidate == settings.browser_origin
        || settings
            .csrf_origins
            .iter()
            .any(|trusted| origin(trusted).as_deref() == Some(candidate.as_str()))
    {
        return true;
    }
    let loopback = url::Url::parse(&settings.browser_origin)
        .ok()
        .is_some_and(|app| {
            matches!(
                app.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]" | "0.0.0.0")
            )
        });
    let host = header(header::HOST).or_else(|| uri.authority().map(|value| value.as_str()));
    loopback
        && host
            .and_then(|host| origin(&format!("{}://{host}", public_scheme(headers, uri))))
            .as_deref()
            == Some(candidate.as_str())
}

fn origin(value: &str) -> Option<String> {
    super::flow::valid_redirect(value).map(|url| url.origin().ascii_serialization())
}

pub(super) async fn callback_proof(
    service: &GatewayService,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    gateway: &OAuthGateway,
    email: &str,
) -> Option<(String, HeaderValue)> {
    let settings = &service.gateway_oauth;
    let csrf = settings.callback_csrf.as_ref()?;
    let token = auth_cookie(headers)?;
    let principal = service
        .access
        .authenticate(token, peer.map(|peer| peer.ip()), None)
        .await
        .ok()?;
    let context = gateway
        .team_id
        .as_deref()
        .map_or(RoleContext::AnyTeam, RoleContext::Team);
    if principal.token_use != TokenUse::Session
        || principal.email != email
        || !gateway.visible(&principal)
        || !service
            .access
            .allows(&principal, "gateways.update", context, true)
            .await
            .ok()?
    {
        return None;
    }
    let jwt = service.access.verify_gateway_token(token).ok()?;
    let proof = csrf.issue(&principal.email, jwt.jti()?, Timestamp::now().as_second())?;
    let path = settings.root_path();
    if path.contains(';') {
        return None;
    }
    let path = if path.is_empty() { "/" } else { path };
    let secure = if settings.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    let cookie = HeaderValue::from_str(&format!(
        "{ADMIN_CSRF_COOKIE}={proof}; Path={path}; Max-Age={}; SameSite=Strict{secure}",
        csrf.seconds.max(300)
    ))
    .ok()?;
    Some((proof, cookie))
}
