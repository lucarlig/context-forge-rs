// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Map;

use super::{identity::authenticate_identity, oidc, *};
use crate::upstream_tls::TlsMaterial;

pub struct ExternalIdentitySettings {
    pub(crate) upstream: UpstreamClient,
    pub(crate) provisioning: UserProvisioning,
    pub(crate) internal_issuer: String,
    pub(crate) approval_required: bool,
}

impl ExternalIdentitySettings {
    pub(crate) async fn authenticate(
        &self,
        database: &Database,
        token: &str,
    ) -> Result<Option<(String, i64)>, sqlx::Error> {
        let Some(unverified) = unverified_access_claims(token) else {
            return Ok(None);
        };
        let Some(issuer) = unverified
            .get("iss")
            .and_then(Value::as_str)
            .filter(|issuer| {
                !issuer.is_empty()
                    && issuer.len() <= 500
                    && issuer.trim_end_matches('/') != self.internal_issuer.trim_end_matches('/')
            })
        else {
            return Ok(None);
        };
        let Some(provider) = database.trusted_sso_provider(issuer).await? else {
            return Ok(None);
        };
        let Some(audience) = provider
            .config
            .api_audience
            .as_deref()
            .filter(|audience| !audience.trim().is_empty())
        else {
            return Ok(None);
        };
        let Ok(tls) = TlsMaterial::from_pem(provider.config.ca_certificate.as_deref(), None, None)
        else {
            return Ok(None);
        };
        let Some(mut claims) = oidc::verify(
            &self.upstream,
            issuer,
            audience,
            provider.config.jwks_uri.as_deref(),
            tls.as_ref(),
            token,
        )
        .await
        else {
            return Ok(None);
        };
        let Some(expiry) = claims
            .get("exp")
            .and_then(Value::as_i64)
            .filter(|expiry| *expiry > Timestamp::now().as_second())
        else {
            return Ok(None);
        };
        if !database
            .sso_provider(&provider.id)
            .await?
            .is_some_and(|current| current.config == provider.config)
        {
            return Ok(None);
        }
        if let Some(client) = service_client(&claims) {
            let client: String = client
                .chars()
                .take(150)
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect();
            claims.insert(
                "email".to_owned(),
                format!("svc-{client}@{}.service.local", provider.id).into(),
            );
            claims.insert("email_verified".to_owned(), Value::Bool(true));
            claims.insert("name".to_owned(), format!("service:{client}").into());
        }
        Ok(authenticate_identity(
            database,
            &self.provisioning,
            &provider,
            &claims,
            self.approval_required,
        )
        .await?
        .map(|user| (user.email, expiry)))
    }
}

fn unverified_access_claims(token: &str) -> Option<Map<String, Value>> {
    if token.len() > 24 * 1024 {
        return None;
    }
    let mut sections = token.split('.');
    sections.next()?;
    let payload = sections.next()?;
    sections.next()?;
    if sections.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Map<String, Value> = serde_json::from_slice(&bytes).ok()?;
    if claims.contains_key("nonce") || claims.contains_key("at_hash") {
        return None;
    }
    Some(claims)
}

fn service_client(claims: &Map<String, Value>) -> Option<&str> {
    let claim = |name: &str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    };
    if ["email", "given_name", "family_name", "name"]
        .iter()
        .any(|name| claim(name).is_some())
    {
        return None;
    }
    let sub = claim("sub")?;
    if claim("azp") == Some(sub)
        || claim("client_id") == Some(sub)
        || claim("typ") == Some("at+jwt")
        || claim("clientId").is_some()
        || claim("preferred_username").is_some_and(|user| user.starts_with("service-account-"))
    {
        return Some(claim("azp").or_else(|| claim("client_id")).unwrap_or(sub));
    }
    None
}
