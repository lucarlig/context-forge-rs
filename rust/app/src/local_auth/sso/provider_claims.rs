// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use serde_json::Map;

use super::{oidc, providers::Provider, *};
use crate::{
    config::{flag, parse},
    upstream_tls::TlsMaterial,
};

pub(super) fn normalize_adfs(claims: &mut Map<String, Value>) {
    claims.entry("email_verified").or_insert(Value::Bool(true));
    if claims.get("name").and_then(Value::as_str).is_none()
        && let Some((first, last)) = claims
            .get("given_name")
            .and_then(Value::as_str)
            .zip(claims.get("family_name").and_then(Value::as_str))
    {
        claims.insert("name".to_owned(), format!("{first} {last}").into());
    }
}

pub(super) fn keycloak_split_host(provider: &Provider) -> bool {
    let metadata = &provider.config.provider_metadata;
    provider.id == "keycloak"
        && metadata
            .get("public_base_url")
            .and_then(Value::as_str)
            .is_some_and(|public| {
                !public.is_empty()
                    && metadata.get("base_url").and_then(Value::as_str) != Some(public)
            })
}

pub(super) async fn enrich_github(
    settings: &SsoSettings,
    provider: &Provider,
    user_info: &mut Map<String, Value>,
    authorization: &HeaderValue,
    tls: Option<&TlsMaterial>,
) {
    if let Some(verified) = user_info
        .get("verified")
        .filter(|claim| !claim.is_null())
        .cloned()
    {
        user_info.entry("email_verified").or_insert(verified);
    }
    if let Some(login) = user_info
        .get("login")
        .and_then(Value::as_str)
        .map(str::to_owned)
        && user_info.get("name").and_then(Value::as_str).is_none()
    {
        user_info.insert("name".to_owned(), login.into());
    }
    user_info.remove("organizations");
    if !settings.identity_policy.github_admin_orgs.is_empty()
        && has_origin(&provider.config.userinfo_url, "https://api.github.com")
    {
        #[derive(Deserialize)]
        struct Organization {
            login: String,
        }
        if let Ok(organizations) = settings
            .upstream
            .oauth_document::<Vec<Organization>>(
                "https://api.github.com/user/orgs",
                tls,
                Some(authorization),
                None,
            )
            .await
        {
            user_info.insert(
                "organizations".to_owned(),
                json!(
                    organizations
                        .into_iter()
                        .map(|org| org.login)
                        .collect::<Vec<_>>()
                ),
            );
        }
    }
}

pub(super) async fn enrich_oidc(
    settings: &SsoSettings,
    provider: &Provider,
    identity: &Map<String, Value>,
    user_info: &mut Map<String, Value>,
    access_token: &str,
    authorization: &HeaderValue,
    tls: Option<&TlsMaterial>,
) {
    match provider.id.as_str() {
        "keycloak" => {
            let role_claims = ["realm_access", "resource_access", "groups"];
            if role_claims
                .iter()
                .all(|claim| user_info.contains_key(*claim) || identity.contains_key(*claim))
            {
                return;
            }
            let Some(issuer) = provider.config.issuer.as_deref() else {
                return;
            };
            let token_claims = oidc::verify(
                &settings.upstream,
                issuer,
                &[&provider.config.client_id, "account"],
                provider.config.jwks_uri.as_deref(),
                tls,
                access_token,
            )
            .await;
            if let Some(mut token_claims) = token_claims.filter(|claims| {
                claims.get("sub") == identity.get("sub")
                    && claims.get("azp").and_then(Value::as_str) == Some(&provider.config.client_id)
                    && !oidc::is_id_token(claims)
            }) {
                for claim in role_claims {
                    if !identity.contains_key(claim)
                        && let Some(value) = token_claims.remove(claim)
                    {
                        user_info.entry(claim).or_insert(value);
                    }
                }
            }
        }
        "entra" => {
            if let Some(groups) = identity.get("groups") {
                user_info.insert("groups".to_owned(), groups.clone());
            }
            if let Some(roles) = identity.get("roles") {
                user_info.insert("roles".to_owned(), roles.clone());
            }
            if entra_group_overage(identity)
                && has_origin(&provider.config.userinfo_url, "https://graph.microsoft.com")
                && let Some(groups) = graph_groups(settings, provider, authorization, tls).await
            {
                user_info.insert("groups".to_owned(), json!(groups));
            }
        }
        _ => {}
    }
}

fn has_origin(endpoint: &str, origin: &str) -> bool {
    url::Url::parse(endpoint).is_ok_and(|url| url.origin().ascii_serialization() == origin)
}

fn entra_group_overage(claims: &Map<String, Value>) -> bool {
    claims
        .get("_claim_names")
        .and_then(Value::as_object)
        .is_some_and(|claims| claims.contains_key("groups"))
        || claims.get("hasgroups").and_then(Value::as_bool) == Some(true)
        || claims.keys().any(|key| key.starts_with("groups:src"))
        || claims.get("groups").is_some_and(Value::is_string)
}

async fn graph_groups(
    settings: &SsoSettings,
    provider: &Provider,
    authorization: &HeaderValue,
    tls: Option<&TlsMaterial>,
) -> Option<Vec<String>> {
    const ENDPOINT: &str = "https://graph.microsoft.com/v1.0/me/getMemberObjects";
    let metadata = &provider.config.provider_metadata;
    let enabled = metadata
        .get("graph_api_enabled")
        .and_then(Value::as_bool)
        .or_else(|| flag("SSO_ENTRA_GRAPH_API_ENABLED").ok().flatten())
        .unwrap_or(true);
    if !enabled {
        return None;
    }
    let timeout = metadata
        .get("graph_api_timeout")
        .and_then(Value::as_u64)
        .filter(|timeout| (1..=120).contains(timeout))
        .unwrap_or_else(|| {
            parse("SSO_ENTRA_GRAPH_API_TIMEOUT", 10)
                .unwrap_or(10)
                .clamp(1, 120)
        });
    let limit = metadata
        .get("graph_api_max_groups")
        .and_then(Value::as_u64)
        .and_then(|limit| usize::try_from(limit).ok())
        .unwrap_or_else(|| parse("SSO_ENTRA_GRAPH_API_MAX_GROUPS", 0).unwrap_or(0));
    let request = json!({"securityEnabledOnly":true});
    let response = tokio::time::timeout(
        Duration::from_secs(timeout),
        settings.upstream.oauth_document::<Value>(
            ENDPOINT,
            tls,
            Some(authorization),
            Some(&request),
        ),
    )
    .await
    .ok()?
    .ok()?;
    let groups = response.get("value").and_then(Value::as_array);
    let mut seen = HashSet::new();
    Some(
        groups
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|group| !group.is_empty() && seen.insert(*group))
            .take(if limit == 0 { usize::MAX } else { limit })
            .map(str::to_owned)
            .collect(),
    )
}
