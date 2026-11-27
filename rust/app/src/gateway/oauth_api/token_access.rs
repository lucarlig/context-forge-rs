// SPDX-License-Identifier: Apache-2.0

use axum::http::HeaderValue;

use super::{
    flow::code_config,
    storage::{OAuthTokenWrite, StoredOAuthToken},
    *,
};
use crate::oauth_client::UserOAuthTokens;

pub(in crate::gateway) struct TokenTarget<'a> {
    pub(in crate::gateway) gateway_id: &'a str,
    pub(in crate::gateway) gateway_url: &'a str,
    pub(in crate::gateway) version: i32,
    pub(in crate::gateway) tls: Option<&'a TlsMaterial>,
    pub(in crate::gateway) config: &'a OAuthConfig,
}

struct ResolvedToken {
    access: Zeroizing<String>,
    expiration: Option<String>,
    scopes: Option<Value>,
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
    let tls = service
        .oauth_connection_tls(&id, &gateway.url, gateway.version)
        .await
        .map_err(|_| CatalogApiError::unavailable())?;
    let target = TokenTarget {
        gateway_id: &id,
        gateway_url: &gateway.url,
        version: gateway.version,
        tls: tls.as_ref(),
        config: &config,
    };
    let resolved=resolve(&service,&target,&principal.email).await?.ok_or_else(||
        CatalogApiError::detail(StatusCode::NOT_FOUND,
            "No OAuth token found for this gateway and user. Complete the OAuth flow at /oauth/authorize/{gateway_id} first."))?;
    let body = json!({"gateway_id":id,"access_token":resolved.access.as_str(),"token_type":"Bearer",
        "expires_at":resolved.expiration,"scopes":resolved.scopes});
    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response())
}

pub(in crate::gateway) async fn authorization_header(
    service: &GatewayService,
    target: TokenTarget<'_>,
    email: &str,
) -> Result<HeaderValue, ToolError> {
    let token = match resolve(service, &target, email).await {
        Ok(Some(token)) => token,
        Ok(None) => return Err(ToolError::OAuthRequired(target.gateway_id.to_owned())),
        Err(error) if error.0 == StatusCode::CONFLICT => {
            return Err(ToolError::OAuthRequired(target.gateway_id.to_owned()));
        }
        Err(_) => return Err(ToolError::Unavailable),
    };
    let value = Zeroizing::new(format!("Bearer {}", token.access.as_str()));
    let mut header = HeaderValue::from_str(&value).map_err(|_| ToolError::Unavailable)?;
    header.set_sensitive(true);
    Ok(header)
}

async fn resolve(
    service: &GatewayService,
    target: &TokenTarget<'_>,
    email: &str,
) -> Result<Option<ResolvedToken>, CatalogApiError> {
    let id = target.gateway_id;
    let Some(mut stored) = service
        .database
        .user_oauth_token(id, email, target.version)
        .await?
    else {
        return Ok(None);
    };
    let claim = Uuid::new_v4().simple().to_string();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
    loop {
        if !refresh_due(&stored, service.gateway_oauth.refresh_threshold) {
            return open_current(service, stored).await.map(Some);
        }
        if service
            .database
            .claim_oauth_refresh(id, email, &claim)
            .await?
        {
            let result = refresh_locked(service, target, email).await;
            if let Err(error) = service
                .database
                .release_oauth_refresh(id, email, &claim)
                .await
            {
                tracing::warn!(%error,"could not release OAuth refresh claim");
            }
            return result;
        }
        if tokio::time::Instant::now() >= deadline {
            return if stored
                .expires_at
                .as_deref()
                .and_then(parse_time)
                .is_some_and(|expiry| expiry <= Timestamp::now())
            {
                Err(CatalogApiError::detail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "OAuth token refresh is in progress",
                ))
            } else {
                open_current(service, stored).await.map(Some)
            };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let Some(latest) = service
            .database
            .user_oauth_token(id, email, target.version)
            .await?
        else {
            return Ok(None);
        };
        stored = latest;
    }
}

fn refresh_due(stored: &StoredOAuthToken, threshold: i64) -> bool {
    stored.refresh_token.is_some()
        && bearer_type(stored)
        && stored
            .expires_at
            .as_deref()
            .and_then(parse_time)
            .is_some_and(|expiry| expiry.as_second() - Timestamp::now().as_second() <= threshold)
}

async fn refresh_locked(
    service: &GatewayService,
    target: &TokenTarget<'_>,
    email: &str,
) -> Result<Option<ResolvedToken>, CatalogApiError> {
    let id = target.gateway_id;
    let Some(stored) = service
        .database
        .user_oauth_token(id, email, target.version)
        .await?
    else {
        return Ok(None);
    };
    let refresh = stored
        .refresh_token
        .as_ref()
        .filter(|_| refresh_due(&stored, service.gateway_oauth.refresh_threshold));
    let Some(refresh) = refresh else {
        return open_current(service, stored).await.map(Some);
    };
    let clear = open_token(service, refresh.clone()).await?;
    let origin = resource_origin(target.gateway_url);
    let upstream = service.upstream.with_timeout_cap(Duration::from_secs(30));
    let mut config = target.config.clone();
    service
        .gateway_oauth
        .cimd
        .configure_assertion(&service.gateway_oauth.dcr, &mut config, &upstream)
        .map_err(|_| CatalogApiError::unavailable())?;
    match config
        .refresh_user_token(&upstream, target.tls, &clear, origin.as_deref())
        .await
    {
        Ok(tokens) => {
            if write_user_token(
                service,
                id,
                target.version,
                email,
                &tokens,
                Some(&stored.access_token),
            )
            .await?
            {
                let scopes = tokens
                    .scopes
                    .as_ref()
                    .map(|scopes| json!(scopes))
                    .or_else(|| {
                        stored
                            .scopes
                            .as_deref()
                            .and_then(|value| serde_json::from_str(value).ok())
                    });
                return Ok(Some(ResolvedToken {
                    access: tokens.access_token,
                    expiration: tokens.expires_at.map(|date| date.to_string()),
                    scopes,
                }));
            }
            let Some(latest) = service
                .database
                .user_oauth_token(id, email, target.version)
                .await?
            else {
                return Ok(None);
            };
            open_current(service, latest).await.map(Some)
        }
        Err(UpstreamError::Status(400 | 401)) => {
            if let Some(latest) = service
                .database
                .user_oauth_token(id, email, target.version)
                .await?
                && latest.access_token != stored.access_token
            {
                return open_current(service, latest).await.map(Some);
            }
            Err(reauthorize())
        }
        Err(_)
            if stored
                .expires_at
                .as_deref()
                .and_then(parse_time)
                .is_some_and(|expiry| expiry <= Timestamp::now()) =>
        {
            Err(CatalogApiError::detail(
                StatusCode::BAD_GATEWAY,
                "OAuth provider could not refresh the access token",
            ))
        }
        Err(_) => open_current(service, stored).await.map(Some),
    }
}

fn bearer_type(stored: &StoredOAuthToken) -> bool {
    stored
        .token_type
        .as_deref()
        .is_none_or(|token| token.eq_ignore_ascii_case("bearer"))
}

async fn open_current(
    service: &GatewayService,
    stored: StoredOAuthToken,
) -> Result<ResolvedToken, CatalogApiError> {
    if !bearer_type(&stored)
        || stored
            .expires_at
            .as_deref()
            .and_then(parse_time)
            .is_some_and(|expiry| expiry <= Timestamp::now())
    {
        return Err(reauthorize());
    }
    let access = open_token(service, stored.access_token).await?;
    Ok(ResolvedToken {
        access,
        expiration: stored.expires_at.map(|date| date.replacen(' ', "T", 1)),
        scopes: stored
            .scopes
            .as_deref()
            .and_then(|scope| serde_json::from_str(scope).ok()),
    })
}

pub(super) async fn read_validation_token(
    service: &GatewayService,
    id: &str,
    version: i32,
    email: &str,
) -> Result<Zeroizing<String>, &'static str> {
    let stored = service
        .database
        .user_oauth_token(id, email, version)
        .await
        .map_err(|_| "token_storage_unavailable")?
        .ok_or("authorization_missing")?;
    if !bearer_type(&stored) {
        return Err("invalid_token");
    }
    if let Some(expiration) = stored.expires_at.as_deref() {
        let expiration = parse_time(expiration).ok_or("invalid_token")?;
        if expiration <= Timestamp::now() {
            return Err("token_expired");
        }
    }
    let access = open_token(service, stored.access_token)
        .await
        .map_err(|_| "invalid_token")?;
    if access.is_empty() || access.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err("invalid_token");
    }
    Ok(access)
}

pub(super) async fn write_user_token(
    service: &GatewayService,
    gateway: &str,
    version: i32,
    email: &str,
    tokens: &UserOAuthTokens,
    expected_access: Option<&str>,
) -> Result<bool, CatalogApiError> {
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
    Ok(service
        .database
        .write_oauth_tokens(OAuthTokenWrite {
            gateway_id: gateway,
            gateway_version: version,
            email,
            subject: &tokens.subject,
            access_token: &access,
            refresh_token: refresh.as_deref(),
            expires_at: tokens.expires_at,
            scopes: tokens.scopes.as_deref(),
            learned_aud: tokens.learned_aud.as_ref(),
            learned_iss: tokens.learned_iss.as_deref(),
            preserve_refresh: expected_access.is_some(),
            expected_access,
        })
        .await?)
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
