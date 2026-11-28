// SPDX-License-Identifier: Apache-2.0

use axum::http::HeaderValue;

use super::{storage::OAuthGateway, *};
use crate::{
    access::{BrowserApiSession, auth_cookie},
    http_boundary::csrf::{ADMIN_CSRF_COOKIE, browser_proof_valid},
    jwt::TokenUse,
};

pub(super) async fn fetch_tools(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    browser: Option<Extension<BrowserApiSession>>,
    Path(id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let settings = &service.gateway_oauth;
    if browser.is_some()
        && !browser_proof_valid(
            &settings.browser_origin,
            &settings.csrf_origins,
            &uri,
            &headers,
        )
    {
        return CatalogApiError::detail(StatusCode::FORBIDDEN, "CSRF validation failed")
            .into_response();
    }
    super::fetch_tools(service, principal, id, headers).await
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
