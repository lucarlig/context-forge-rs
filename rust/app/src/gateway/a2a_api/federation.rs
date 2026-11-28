// SPDX-License-Identifier: Apache-2.0

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use super::*;
use crate::uaid;

pub(super) async fn dispatch(
    app: &GatewayService,
    principal: &Principal,
    lookup: AgentLookup<'_>,
    invocation: Invocation,
    headers: &HeaderMap,
) -> Result<Value, CatalogApiError> {
    let identifier = match lookup {
        AgentLookup::Id(value) | AgentLookup::Name(value) => value,
    };
    let hops = uaid::hop_count(headers);
    check_hops(app, identifier, hops)?;
    let agent = if uaid::is_uaid(identifier) {
        if identifier.chars().count() > app.uaid.max_length
            || identifier.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(bad("Invalid UAID format"));
        }
        let mut matches = app.database.local_uaid_agents(identifier).await?;
        if matches.is_empty() {
            return forward(app, principal, identifier, invocation, headers, hops).await;
        }
        let scope = access::catalog_scope(Some(principal));
        matches
            .pop()
            .filter(|agent| matches.is_empty() && agent.visible(scope))
            .ok_or_else(|| CatalogApiError::detail(StatusCode::NOT_FOUND, "A2A Agent not found"))?
    } else {
        find(app, Some(principal), lookup).await?
    };
    invoke_recorded(app, &agent, invocation, headers).await
}

pub(super) fn check_hops(
    app: &GatewayService,
    identifier: &str,
    hops: u32,
) -> Result<(), CatalogApiError> {
    if hops >= app.uaid.max_hops {
        return Err(CatalogApiError::detail(
            StatusCode::NOT_FOUND,
            format!("A2A Agent not found (federation hop limit reached): {identifier}"),
        ));
    }
    Ok(())
}

async fn forward(
    app: &GatewayService,
    principal: &Principal,
    identifier: &str,
    invocation: Invocation,
    incoming: &HeaderMap,
    hops: u32,
) -> Result<Value, CatalogApiError> {
    let url = app.uaid.peer_destination(identifier).map_err(bad)?;
    let mut request = reqwest::Request::new(reqwest::Method::POST, url);
    let headers = request.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    uaid::stamp(headers, hops);
    if let Some(id) = crate::http_boundary::CorrelationId::current() {
        id.write_header(headers);
    }
    if app.uaid.forward_auth
        && let Some(token) = principal
            .verified_bearer(incoming)
            .filter(|token| jwt_shape(token))
    {
        let value = Zeroizing::new(format!("Bearer {token}"));
        let mut authorization =
            HeaderValue::from_str(&value).map_err(|_| bad("Invalid federation credential"))?;
        authorization.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, authorization);
        headers.insert(
            "x-contextforge-source-gateway",
            HeaderValue::from_static("unknown"),
        );
        if let Ok(actor) = HeaderValue::from_str(&principal.email) {
            headers.insert("x-contextforge-source-user", actor);
        }
    }
    *request.body_mut() = Some(json!({
        "agent_id":identifier, "parameters":invocation.parameters, "interaction_type":invocation.interaction_type,
    }).to_string().into());
    let span = OperationSpan::start(
        &app.database,"a2a.invoke","client",
        Some(SpanResource {kind:"agent",name:"federated agent",id:None}),
        || json!({"a2a.federation":true,"a2a.hop":hops+1,
            "a2a.interaction_type":invocation.interaction_type.chars().take(50).collect::<String>()}),
    ).await;
    span.inject_trace_context(request.headers_mut());
    let result = span
        .scope(Box::pin(forward_request(app, principal, request, hops)))
        .await;
    let success = matches!(&result, Ok(value) if !protocol::has_rpc_error(value));
    span.finish(Outcome::completed(success, "A2A federation request failed"))
        .await;
    result
}

async fn forward_request(
    app: &GatewayService,
    principal: &Principal,
    request: reqwest::Request,
    hops: u32,
) -> Result<Value, CatalogApiError> {
    let response = app
        .upstream
        .with_timeout_cap(Duration::from_secs(30))
        .rest_response(request, None)
        .await
        .map_err(|error| match error {
            UpstreamError::BlockedDestination | UpstreamError::InvalidUrl => {
                bad("Cross-gateway URL blocked by URL policy")
            }
            _ => bad("Cross-gateway routing failed"),
        })?;
    tracing::info!(actor = %principal.email, status = response.status.as_u16(), hop = hops + 1, "A2A federation response");
    if response.status.is_success() {
        if response.body.is_empty() {
            return Ok(json!({}));
        }
        return serde_json::from_slice(&response.body).map_err(|_| {
            CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                format!(
                    "Cross-gateway routing failed: remote returned HTTP {} with unparseable body",
                    response.status.as_u16()
                ),
            )
        });
    }
    let detail = match response.status {
        StatusCode::UNAUTHORIZED => "Remote gateway rejected authentication (HTTP 401). Ensure both gateways trust the same JWT signing key (JWT_SECRET_KEY) or configure JWKS endpoint for token validation.".into(),
        StatusCode::FORBIDDEN => "Remote gateway rejected authorization (HTTP 403). Verify token has required team memberships or roles for the target agent/resource.".into(),
        status => format!("HTTP {}", status.as_u16()),
    };
    Err(CatalogApiError::detail(
        StatusCode::BAD_REQUEST,
        format!("Cross-gateway routing failed: {detail}"),
    ))
}

fn jwt_shape(token: &str) -> bool {
    if token.starts_with("cf_sess_") || token.starts_with("cf_pat_") {
        return false;
    }
    let mut segments = token.split('.');
    (0..3).all(|_| {
        segments
            .next()
            .is_some_and(|part| !part.is_empty() && URL_SAFE_NO_PAD.decode(part).is_ok())
    }) && segments.next().is_none()
}

fn bad(detail: &'static str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::BAD_REQUEST, detail)
}
