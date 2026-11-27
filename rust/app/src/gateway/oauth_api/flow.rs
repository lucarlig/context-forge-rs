// SPDX-License-Identifier: Apache-2.0

use axum::{extract::Query, http::HeaderValue, response::Html};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use subtle::ConstantTimeEq;

use super::{
    storage::{NewOAuthState, OAuthGateway, OAuthTokenWrite, StoredOAuthToken},
    *,
};
use crate::{oauth_client::UserOAuthTokens, tokens::hash_token};

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
    let gateway = visible_gateway(&service, &principal, &id).await?;
    let config = code_config(&service, &gateway).await?;
    if config.client_id().is_none() {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "OAuth configuration missing client_id",
        ));
    }
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
    let parsed = valid_redirect(redirect).ok_or_else(|| {
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
    let cookie_path = callback_path(&service.gateway_oauth, Some(&parsed));
    let hash = hash_token(&binding);
    let team_id = match &principal.visibility {
        TeamVisibility::Teams(teams) if teams.len() == 1 => teams.first().map(String::as_str),
        _ => None,
    };
    service
        .database
        .put_oauth_state(NewOAuthState {
            gateway_id: &gateway.id,
            state: &state,
            verifier: &verifier,
            email: &principal.email,
            redirect_uri: redirect,
            team_id,
            browser_binding_hash: &hash,
        })
        .await?;
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
    let (status, payload, message) = match result {
        Ok(gateway) => (
            StatusCode::OK,
            json!({"type":"oauth_callback","status":"success","gatewayId":gateway.id,"gatewayName":gateway.name}),
            "Authorization successful. This window will close automatically.",
        ),
        Err(failure) => (
            failure.status(),
            json!({"type":"oauth_callback","status":"error","error":failure.code(),"errorDescription":failure.message()}),
            failure.message(),
        ),
    };
    let nonce = random_secret::<18>().unwrap_or_default();
    let title = if status.is_success() {
        "OAuth Authorization Successful"
    } else {
        "OAuth Authorization Failed"
    };
    let script = if popup && !nonce.is_empty() {
        let payload = script_json(payload);
        let target = script_json(json!(service.gateway_oauth.browser_origin));
        format!(
            r#"<script nonce="{nonce}">if(window.opener){{window.opener.postMessage({payload},{target});window.close();}}</script>"#
        )
    } else {
        String::new()
    };
    let mut response=(status,Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head><body><h1>{title}</h1><p>{message}</p>{script}</body></html>"
    ))).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Ok(csp) = HeaderValue::from_str(&format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; base-uri 'none'; frame-ancestors 'none'"
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
    response
}

async fn callback_inner(
    service: &GatewayService,
    headers: &HeaderMap,
    state: &str,
    query: &CallbackQuery,
) -> Result<OAuthGateway, CallbackFailure> {
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
        .ok_or(CallbackFailure::InvalidState)?;
    let config = code_config(service, &gateway)
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
    let redirect = transaction
        .redirect_uri
        .as_deref()
        .or(config.redirect_uri())
        .unwrap_or(&service.gateway_oauth.redirect_uri);
    let origin = gateway.resource_origin();
    let token = config
        .exchange_user_code(
            &service.upstream,
            None,
            code,
            &verifier,
            redirect,
            origin.as_deref(),
        )
        .await
        .map_err(|_| CallbackFailure::Exchange)?;
    write_user_token(service, &gateway.id, &email, &token, false)
        .await
        .map_err(|_| CallbackFailure::Storage)?;
    Ok(gateway)
}

pub(super) async fn token(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Response, CatalogApiError> {
    if !service.gateway_oauth.token_retrieval {
        return Err(CatalogApiError::detail(StatusCode::NOT_FOUND, "Not Found"));
    }
    if !service
        .access
        .allows(
            &principal,
            "gateways.token_read",
            RoleContext::AnyTeam,
            true,
        )
        .await?
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    let gateway = visible_gateway(&service, &principal, &id).await?;
    let config = code_config(&service, &gateway).await?;
    let stored=service.database.user_oauth_token(&id,&principal.email).await?
        .ok_or_else(||CatalogApiError::detail(StatusCode::NOT_FOUND,
            "No OAuth token found for this gateway and user. Complete the OAuth flow at /oauth/authorize/{gateway_id} first."))?;
    let body = token_payload(&service, &gateway, &config, &principal.email, stored).await?;
    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response())
}

async fn token_payload(
    service: &GatewayService,
    gateway: &OAuthGateway,
    config: &OAuthConfig,
    email: &str,
    stored: StoredOAuthToken,
) -> Result<Value, CatalogApiError> {
    let now = Timestamp::now();
    let expiry = stored.expires_at.as_deref().and_then(parse_time);
    let expired = expiry.is_some_and(|expiry| expiry <= now);
    if stored
        .token_type
        .as_deref()
        .is_some_and(|ty| !ty.eq_ignore_ascii_case("bearer"))
    {
        return Err(reauthorize());
    }
    let scopes = stored
        .scopes
        .as_deref()
        .and_then(|value| serde_json::from_str::<Value>(value).ok());
    if let Some(refresh) = stored.refresh_token
        && expiry.is_some_and(|expiry| {
            expiry.as_second() - now.as_second() <= service.gateway_oauth.refresh_threshold
        })
    {
        let clear = open_token(service, refresh).await?;
        let origin = gateway.resource_origin();
        match config
            .refresh_user_token(&service.upstream, None, &clear, origin.as_deref())
            .await
        {
            Ok(new) => {
                write_user_token(service, &gateway.id, email, &new, true).await?;
                return Ok(
                    json!({"gateway_id":gateway.id,"access_token":new.access_token.as_str(),"token_type":"Bearer",
                    "expires_at":new.expires_at.map(|value|value.to_string()),"scopes":new.scopes.as_ref().map(|scopes|json!(scopes)).or(scopes)}),
                );
            }
            Err(UpstreamError::Status(400 | 401)) => return Err(reauthorize()),
            Err(_) if expired => {
                return Err(CatalogApiError::detail(
                    StatusCode::BAD_GATEWAY,
                    "OAuth provider could not refresh the access token",
                ));
            }
            Err(_) => {}
        }
    }
    if expired {
        return Err(reauthorize());
    }
    let access = open_token(service, stored.access_token).await?;
    Ok(
        json!({"gateway_id":gateway.id,"access_token":access.as_str(),"token_type":"Bearer",
        "expires_at":stored.expires_at.map(|value|value.replacen(' ',"T",1)),"scopes":scopes}),
    )
}

async fn code_config(
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

async fn write_user_token(
    service: &GatewayService,
    gateway: &str,
    email: &str,
    tokens: &UserOAuthTokens,
    preserve_refresh: bool,
) -> Result<(), CatalogApiError> {
    let vault = service
        .vault
        .as_ref()
        .ok_or_else(CatalogApiError::unavailable)?;
    let access = vault
        .seal(tokens.access_token.clone())
        .await
        .map_err(|_| CatalogApiError::unavailable())?;
    let refresh = if let Some(refresh) = tokens.refresh_token.as_ref() {
        Some(
            vault
                .seal(refresh.clone())
                .await
                .map_err(|_| CatalogApiError::unavailable())?,
        )
    } else {
        None
    };
    if !service
        .database
        .write_oauth_tokens(OAuthTokenWrite {
            gateway_id: gateway,
            email,
            subject: &tokens.subject,
            access_token: &access,
            refresh_token: refresh.as_deref(),
            expires_at: tokens.expires_at,
            scopes: tokens.scopes.as_deref(),
            learned_aud: tokens.learned_aud.as_ref(),
            learned_iss: tokens.learned_iss.as_deref(),
            preserve_refresh,
        })
        .await?
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "User authentication required",
        ));
    }
    Ok(())
}

async fn open_token(
    service: &GatewayService,
    encrypted: String,
) -> Result<Zeroizing<String>, CatalogApiError> {
    let vault = service
        .vault
        .as_ref()
        .ok_or_else(CatalogApiError::unavailable)?;
    vault.open(encrypted).await.map_err(|_| {
        CatalogApiError::detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Stored OAuth token is unreadable",
        )
    })
}

fn reauthorize() -> CatalogApiError {
    CatalogApiError::detail(
        StatusCode::CONFLICT,
        "OAuth reauthorization required for this gateway and user",
    )
}

fn random_secret<const N: usize>() -> Option<String> {
    let mut random = Zeroizing::new([0_u8; N]);
    SystemRandom::new().fill(random.as_mut()).ok()?;
    Some(URL_SAFE_NO_PAD.encode(random.as_ref()))
}

fn valid_redirect(url: &str) -> Option<url::Url> {
    url::Url::parse(url).ok().filter(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

fn callback_path<'a>(
    settings: &'a GatewayOAuthSettings,
    redirect: Option<&'a url::Url>,
) -> &'a str {
    redirect.map_or(settings.callback_path.as_str(), url::Url::path)
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
