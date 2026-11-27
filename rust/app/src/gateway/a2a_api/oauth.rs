// SPDX-License-Identifier: Apache-2.0

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

use super::*;
use crate::oauth_client::A2aOAuthError;

pub(super) fn validate_config(
    app: &GatewayService,
    config: &OAuthConfig,
    existing: Option<&DbJson<Value>>,
) -> Result<(), CatalogApiError> {
    let invalid = |message| CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message);
    if !config.supports_a2a() {
        return Err(invalid(
            "A2A agents support only the client_credentials OAuth grant type",
        ));
    }
    config
        .check_a2a_endpoints(&app.upstream)
        .map_err(|_| invalid("A2A OAuth URL blocked by URL policy"))?;
    if config.masked_a2a_secret()
        && existing.and_then(|stored| stored.0["token_url"].as_str())
            != Some(config.token_endpoint())
    {
        return Err(invalid(
            "Send the OAuth client secret again when you change the token URL.",
        ));
    }
    Ok(())
}

pub(super) async fn store(
    app: &GatewayService,
    config: &OAuthConfig,
) -> Result<DbJson<Value>, CatalogApiError> {
    validate_config(app, config, None)?;
    let vault = app
        .vault
        .as_ref()
        .ok_or_else(CatalogApiError::unavailable)?;
    let (encoded, _) = config
        .store(vault)
        .await
        .map_err(|_| CatalogApiError::unavailable())?;
    serde_json::from_str(&encoded)
        .map(DbJson)
        .map_err(|_| CatalogApiError::unavailable())
}

pub(super) async fn authorization(
    app: &GatewayService,
    agent: &AgentRecord,
) -> Result<HeaderValue, CatalogApiError> {
    let config = agent
        .oauth_config
        .as_ref()
        .filter(|config| config.0.is_object())
        .ok_or_else(|| {
            CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                format!(
                    "A2A agent '{}' uses OAuth but has no oauth_config",
                    agent.name
                ),
            )
        })?;
    let policy = app.gateway_oauth.a2a_token_policy;
    let encoded = config.0.to_string();
    let identity = json!([
        agent.id,
        agent.version,
        agent.updated_at,
        agent.endpoint_url,
        encoded,
        policy.strict_resource
    ]);
    let digest = BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(identity.to_string().as_bytes()));
    let cache_key = format!("cf:oauth-a2a:v1:{digest}");
    let request = async {
        let vault = app.vault.as_ref().ok_or(A2aOAuthError::Configuration)?;
        let config = OAuthConfig::load(vault, &encoded)
            .await
            .map_err(|_| A2aOAuthError::Configuration)?;
        let upstream = app
            .upstream
            .with_timeout_cap(app.gateway_oauth.request_timeout);
        config
            .a2a_authorization(&upstream, &agent.endpoint_url, policy)
            .await
    };
    app.exchanged_tokens
        .a2a_authorization(&cache_key, app.credential_cipher.as_ref(), request)
        .await
        .map_err(|error| {
            tracing::warn!(agent_id = %agent.id, "A2A OAuth token unavailable");
            CatalogApiError::detail(StatusCode::BAD_REQUEST, message(&agent.name, error))
        })
}

fn message(agent: &str, error: A2aOAuthError) -> String {
    match error {
        A2aOAuthError::Configuration => {
            format!("OAuth configuration is invalid for A2A agent '{agent}'")
        }
        A2aOAuthError::Request => format!("OAuth token request failed for A2A agent '{agent}'"),
        A2aOAuthError::Claims {
            audience,
            scopes,
            issuer,
        } => {
            let reasons = [
                audience.then_some("Token audience mismatch: token aud does not match expected resource or gateway URL"),
                scopes.then_some("Token may be missing required scopes"),
                issuer.then_some("Token issuer mismatch"),
            ].into_iter().flatten().collect::<Vec<_>>().join("; ");
            format!(
                "Refusing to forward OAuth token for A2A agent '{agent}': {reasons}. Fix oauth_config (resource/scopes/issuer) or the IdP token request."
            )
        }
    }
}
