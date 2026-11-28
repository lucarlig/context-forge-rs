// SPDX-License-Identifier: Apache-2.0

use axum::{extract::Query, http::HeaderValue, response::Html};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

use super::{
    storage::{NewOAuthState, OAuthGateway},
    *,
};
use crate::tokens::hash_token;

#[derive(Deserialize)]
pub(super) struct AuthorizeQuery {
    #[serde(default)]
    popup: bool,
}

#[derive(Deserialize)]
pub(super) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}

pub(super) async fn authorize(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, CatalogApiError> {
    let (gateway, config) =
        super::registration::configured_client(&service, &principal, &id).await?;
    let verifier = Zeroizing::new(random_secret::<32>().ok_or_else(CatalogApiError::unavailable)?);
    let binding = Zeroizing::new(random_secret::<32>().ok_or_else(CatalogApiError::unavailable)?);
    let mut state = random_secret::<32>().ok_or_else(CatalogApiError::unavailable)?;
    if query.popup {
        state.insert_str(0, "popup.");
    }
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let redirect = config
        .redirect_uri()
        .unwrap_or(&service.gateway_oauth.redirect_uri);
    valid_redirect(redirect).ok_or_else(|| {
        CatalogApiError::detail(StatusCode::BAD_REQUEST, "OAuth callback URL is invalid")
    })?;
    let origin = gateway.resource_origin();
    let location = config
        .authorize_url(
            &service.upstream,
            redirect,
            &state,
            &challenge,
            origin.as_deref(),
        )
        .map_err(|_| {
            CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                "OAuth endpoints are invalid or disallowed",
            )
        })?;
    let cookie_path = &service.gateway_oauth.callback_path;
    let hash = hash_token(&binding);
    let team_id = match &principal.visibility {
        TeamVisibility::Teams(teams) if teams.len() == 1 => teams.first().map(String::as_str),
        _ => None,
    };
    let saved = service
        .database
        .put_oauth_state(NewOAuthState {
            gateway_id: &gateway.id,
            gateway_version: gateway.version,
            state: &state,
            verifier: &verifier,
            email: &principal.email,
            redirect_uri: redirect,
            team_id,
            browser_binding_hash: &hash,
        })
        .await?;
    if !saved {
        return Err(CatalogApiError::detail(
            StatusCode::CONFLICT,
            "Gateway changed during authorization",
        ));
    }
    let cookie = transaction_cookie(&service.gateway_oauth, &state, &binding, cookie_path, 300)
        .ok_or_else(CatalogApiError::unavailable)?;
    let location =
        HeaderValue::from_str(location.as_str()).map_err(|_| CatalogApiError::unavailable())?;
    Ok((
        StatusCode::TEMPORARY_REDIRECT,
        [
            (header::LOCATION, location),
            (header::SET_COOKIE, cookie),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
        .into_response())
}

pub(super) async fn callback(
    State(service): State<Arc<GatewayService>>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let state = query.state.as_deref().filter(|state| {
        state.len() <= 500
            && state
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    });
    let popup = state.is_some_and(|state| state.starts_with("popup."));
    let result = match state {
        Some(state) => callback_inner(&service, &headers, state, &query).await,
        None => Err(CallbackFailure::InvalidState),
    };
    let mut proof_cookie = None;
    let nonce = random_secret::<18>().unwrap_or_default();
    let settings = &service.gateway_oauth;
    let root = settings.root_path();
    let mut controls = String::new();
    let mut script = String::new();
    let (status, title, message) = match result {
        Ok((gateway, email)) => {
            let payload = json!({"type":"oauth_callback","status":"success","gatewayId":gateway.id,"gatewayName":gateway.name});
            if popup {
                script = notify_opener(&nonce, payload, &settings.browser_origin);
            } else if !nonce.is_empty()
                && let Some((proof, cookie)) = super::browser::callback_proof(
                    &service,
                    &headers,
                    peer.map(|Extension(ConnectInfo(peer))| peer),
                    &gateway,
                    &email,
                )
                .await
            {
                proof_cookie = Some(cookie);
                controls = r#"<button id="fetch-tools" type="button">Fetch Tools from MCP Server</button><p id="fetch-status" role="status"></p>"#.to_owned();
                script = fetch_script(
                    &nonce,
                    &format!("{root}/oauth/fetch-tools/{}", gateway.id),
                    &proof,
                    payload,
                    &settings.browser_origin,
                );
            }
            (
                StatusCode::OK,
                "OAuth Authorization Successful",
                if popup {
                    "Authorization successful. This window will close automatically."
                } else {
                    "Authorization completed successfully."
                },
            )
        }
        Err(failure) => {
            if popup {
                let payload = json!({"type":"oauth_callback","status":"error","error":failure.code(),"errorDescription":failure.message()});
                script = notify_opener(&nonce, payload, &settings.browser_origin);
            }
            (
                failure.status(),
                "OAuth Authorization Failed",
                failure.message(),
            )
        }
    };
    if !popup {
        let root = settings
            .admin_root
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        use std::fmt::Write as _;
        let _ = write!(
            controls,
            r#"<p><a href="{root}/admin/?section=gateways#gateways">Return to Admin Panel</a></p>"#
        );
    }
    let mut response = (status, Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head><body><h1>{title}</h1><p>{message}</p>{controls}{script}</body></html>"
    ))).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Ok(csp) = HeaderValue::from_str(&format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    )) {
        headers.insert(header::CONTENT_SECURITY_POLICY, csp);
    }
    if let Some(state) = state
        && let Some(cookie) = transaction_cookie(
            &service.gateway_oauth,
            state,
            "",
            &service.gateway_oauth.callback_path,
            0,
        )
    {
        headers.append(header::SET_COOKIE, cookie);
    }
    if let Some(cookie) = proof_cookie {
        headers.append(header::SET_COOKIE, cookie);
    }
    response
}

async fn callback_inner(
    service: &GatewayService,
    headers: &HeaderMap,
    state: &str,
    query: &CallbackQuery,
) -> Result<(OAuthGateway, String), CallbackFailure> {
    let transaction = service
        .database
        .consume_oauth_state(state)
        .await
        .map_err(|_| CallbackFailure::Storage)?
        .ok_or(CallbackFailure::InvalidState)?;
    let binding = cookie(headers, &cookie_name(state))
        .filter(|binding| binding.len() <= 128)
        .ok_or(CallbackFailure::InvalidState)?;
    let actual = hash_token(binding);
    let expected = transaction
        .browser_binding_hash
        .as_deref()
        .filter(|hash| hash.len() == 64)
        .ok_or(CallbackFailure::InvalidState)?;
    if !bool::from(actual.as_bytes().ct_eq(expected.as_bytes())) {
        return Err(CallbackFailure::InvalidState);
    }
    let gateway = service
        .database
        .oauth_gateways(&[transaction.gateway_id])
        .await
        .map_err(|_| CallbackFailure::Storage)?
        .pop()
        .filter(|gateway| gateway.version == transaction.gateway_version)
        .ok_or(CallbackFailure::InvalidState)?;
    let mut config = code_config(service, &gateway)
        .await
        .map_err(|_| CallbackFailure::InvalidState)?;
    if !config.verify_response_issuer(query.iss.as_deref()) {
        return Err(CallbackFailure::IssuerMismatch);
    }
    if query.error.is_some() {
        return Err(CallbackFailure::ProviderDenied);
    }
    let code = query
        .code
        .as_deref()
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 4096
                && code.bytes().all(|byte| matches!(byte, 0x20..=0x7e))
        })
        .ok_or(CallbackFailure::MissingCode)?;
    let verifier = Zeroizing::new(
        transaction
            .code_verifier
            .ok_or(CallbackFailure::InvalidState)?,
    );
    let email = transaction
        .app_user_email
        .ok_or(CallbackFailure::InvalidState)?;
    let identity = service
        .database
        .active_identity(Some(&email), None, None)
        .await
        .map_err(|_| CallbackFailure::Storage)?
        .ok_or(CallbackFailure::InvalidState)?;
    let scope = identity
        .session_visibility(&service.database)
        .await
        .map_err(|_| CallbackFailure::Storage)?;
    if !gateway.visible_in(&identity.email, &scope) {
        return Err(CallbackFailure::InvalidState);
    }
    service
        .gateway_oauth
        .cimd
        .configure_assertion(&service.gateway_oauth.dcr, &mut config, &service.upstream)
        .map_err(|_| CallbackFailure::Exchange)?;
    let redirect = transaction
        .redirect_uri
        .as_deref()
        .or(config.redirect_uri())
        .unwrap_or(&service.gateway_oauth.redirect_uri);
    let origin = gateway.resource_origin();
    let tls = service
        .oauth_connection_tls(&gateway.id, &gateway.url, gateway.version)
        .await
        .map_err(|_| CallbackFailure::Storage)?;
    let token = config
        .exchange_user_code(
            &service.upstream,
            tls.as_ref(),
            code,
            &verifier,
            redirect,
            origin.as_deref(),
        )
        .await
        .map_err(|_| CallbackFailure::Exchange)?;
    let saved = super::token_access::write_user_token(
        service,
        &gateway.id,
        gateway.version,
        &email,
        &token,
        None,
    )
    .await
    .map_err(|_| CallbackFailure::Storage)?;
    if !saved {
        return Err(CallbackFailure::InvalidState);
    }
    Ok((gateway, email))
}

pub(super) async fn code_config(
    service: &GatewayService,
    gateway: &OAuthGateway,
) -> Result<OAuthConfig, CatalogApiError> {
    let encoded = gateway
        .oauth_config
        .as_deref()
        .filter(|encoded| {
            serde_json::from_str::<Value>(encoded)
                .ok()
                .is_some_and(|config| config.as_object().is_some_and(|object| !object.is_empty()))
        })
        .ok_or_else(|| {
            CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                "Gateway is not configured for OAuth",
            )
        })?;
    let grant = serde_json::from_str::<Value>(encoded)
        .ok()
        .and_then(|value| value["grant_type"].as_str().map(str::to_owned));
    if grant.as_deref() != Some("authorization_code") {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "Gateway is not configured for Authorization Code flow",
        ));
    }
    let vault = service
        .vault
        .as_ref()
        .ok_or_else(CatalogApiError::unavailable)?;
    OAuthConfig::load(vault, encoded)
        .await
        .map_err(|_| CatalogApiError::unavailable())
}

fn random_secret<const N: usize>() -> Option<String> {
    let mut random = Zeroizing::new([0_u8; N]);
    SystemRandom::new().fill(random.as_mut()).ok()?;
    Some(URL_SAFE_NO_PAD.encode(random.as_ref()))
}

pub(super) fn valid_redirect(url: &str) -> Option<url::Url> {
    url::Url::parse(url).ok().filter(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn cookie_name(state: &str) -> String {
    format!("oauth_bind_{}", hash_token(state))
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(field, value)| (field == name).then_some(value))
}

fn transaction_cookie(
    settings: &GatewayOAuthSettings,
    state: &str,
    binding: &str,
    path: &str,
    age: u32,
) -> Option<HeaderValue> {
    if path.contains(';') {
        return None;
    }
    let secure = if settings.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    HeaderValue::from_str(&format!(
        "{}={binding}; HttpOnly; Max-Age={age}; Path={path}; SameSite=lax{secure}",
        cookie_name(state)
    ))
    .ok()
}

fn notify_opener(nonce: &str, payload: Value, origin: &str) -> String {
    if nonce.is_empty() {
        return String::new();
    }
    let payload = script_json(payload);
    let target = script_json(json!(origin));
    format!(
        r#"<script nonce="{nonce}">if(window.opener){{window.opener.postMessage({payload},{target});window.close();}}</script>"#
    )
}

fn fetch_script(nonce: &str, path: &str, proof: &str, result: Value, origin: &str) -> String {
    let path = script_json(json!(path));
    let proof = script_json(json!(proof));
    let result = script_json(result);
    let origin = script_json(json!(origin));
    format!(
        r#"<script nonce="{nonce}">
const button = document.getElementById('fetch-tools');
const status = document.getElementById('fetch-status');
button.addEventListener('click', async () => {{
    button.disabled = true;
    status.textContent = 'Fetching tools…';
    try {{
        const response = await fetch({path}, {{
            method: 'POST',
            credentials: 'same-origin',
            headers: {{ 'Accept': 'application/json, text/html', 'X-CSRF-Token': {proof} }}
        }});
        const body = await response.json();
        if (!response.ok || body.success !== true) throw new Error();
        status.textContent = body.message;
        if (window.opener && !window.opener.closed) {{
            window.opener.postMessage({result}, {origin});
            window.close();
        }}
    }} catch {{
        status.textContent = 'Could not fetch tools. Try again.';
        button.disabled = false;
    }}
}});
</script>"#
    )
}

fn script_json(value: Value) -> String {
    value
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

#[derive(Clone, Copy)]
enum CallbackFailure {
    InvalidState,
    MissingCode,
    IssuerMismatch,
    ProviderDenied,
    Exchange,
    Storage,
}

impl CallbackFailure {
    fn status(self) -> StatusCode {
        if matches!(self, Self::Storage) {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::BAD_REQUEST
        }
    }
    fn code(self) -> &'static str {
        match self {
            Self::InvalidState => "invalid_state",
            Self::MissingCode => "missing_code",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::ProviderDenied => "access_denied",
            Self::Exchange => "token_exchange_failed",
            Self::Storage => "server_error",
        }
    }
    fn message(self) -> &'static str {
        match self {
            Self::InvalidState => "Invalid OAuth state parameter.",
            Self::MissingCode => "Missing authorization code in callback response.",
            Self::IssuerMismatch => "The OAuth provider did not match the configured issuer.",
            Self::ProviderDenied => "The OAuth provider denied the authorization request.",
            Self::Exchange => "The OAuth provider did not exchange the authorization code.",
            Self::Storage => "OAuth token storage is unavailable.",
        }
    }
}
