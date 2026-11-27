// SPDX-License-Identifier: Apache-2.0

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{Jwk, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use serde_json::Map;

use super::{providers::Provider, *};
use crate::upstream_tls::TlsMaterial;

#[derive(Deserialize)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct PublicKeys {
    keys: Vec<Value>,
}

pub(super) async fn id_token_claims(
    settings: &SsoSettings,
    provider: &Provider,
    token: &str,
    nonce: &str,
    tls: Option<&TlsMaterial>,
) -> Option<Map<String, Value>> {
    let issuer = provider
        .config
        .issuer
        .as_deref()
        .filter(|issuer| !issuer.is_empty())?;
    let claims = verify(
        &settings.upstream,
        issuer,
        &provider.config.client_id,
        provider.config.jwks_uri.as_deref(),
        tls,
        token,
    )
    .await?;
    if claims.get("nonce").and_then(Value::as_str) != Some(nonce)
        || claims
            .get("azp")
            .is_some_and(|azp| azp.as_str() != Some(provider.config.client_id.as_str()))
        || claims
            .get("aud")
            .and_then(Value::as_array)
            .is_some_and(|audiences| audiences.len() > 1)
            && !claims.contains_key("azp")
    {
        return None;
    }
    Some(claims)
}

async fn verify(
    upstream: &UpstreamClient,
    issuer: &str,
    audience: &str,
    jwks_uri: Option<&str>,
    tls: Option<&TlsMaterial>,
    token: &str,
) -> Option<Map<String, Value>> {
    if token.len() > 24 * 1024 || audience.trim().is_empty() {
        return None;
    }
    let header = decode_header(token).ok()?;
    if matches!(
        header.alg,
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
    ) {
        return None;
    }
    let metadata;
    let jwks_uri = match jwks_uri.filter(|uri| !uri.is_empty()) {
        Some(uri) => uri,
        None => {
            let url = url::Url::parse(issuer).ok()?;
            if url.query().is_some() || url.fragment().is_some() {
                return None;
            }
            metadata = upstream
                .oauth_document::<OidcDiscovery>(
                    &format!(
                        "{}/.well-known/openid-configuration",
                        issuer.trim_end_matches('/')
                    ),
                    tls,
                    None,
                    None,
                )
                .await
                .ok()?;
            if metadata.issuer != issuer {
                return None;
            }
            &metadata.jwks_uri
        }
    };
    let keys = upstream
        .oauth_document::<PublicKeys>(jwks_uri, tls, None, None)
        .await
        .ok()?;
    if keys.keys.len() > 100 {
        return None;
    }
    let mut valid_keys = keys
        .keys
        .into_iter()
        .filter_map(|value| serde_json::from_value::<Jwk>(value).ok())
        .filter(|key| {
            let usage = &key.common;
            header
                .kid
                .as_ref()
                .is_none_or(|kid| usage.key_id.as_ref() == Some(kid))
                && usage
                    .key_algorithm
                    .is_none_or(|alg| alg == KeyAlgorithm::from(header.alg))
                && usage
                    .public_key_use
                    .as_ref()
                    .is_none_or(|usage| *usage == PublicKeyUse::Signature)
                && usage
                    .key_operations
                    .as_ref()
                    .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
        });
    let key = DecodingKey::from_jwk(&valid_keys.next()?).ok()?;
    if valid_keys.next().is_some() {
        return None;
    }
    let mut validation = Validation::new(header.alg);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.validate_nbf = true;
    let claims = decode::<Map<String, Value>>(token, &key, &validation)
        .ok()?
        .claims;
    let now = Timestamp::now().as_second();
    if claims
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(|sub| sub.is_empty() || sub.len() > 512)
        || claims
            .get("iat")
            .is_some_and(|iat| iat.as_i64().is_none_or(|issued| issued > now + 60))
    {
        return None;
    }
    Some(claims)
}
