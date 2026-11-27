// SPDX-License-Identifier: Apache-2.0

use serde_json::Map;

use super::{providers::Provider, *};

pub(super) async fn authenticate_identity(
    database: &Database,
    provisioning: &UserProvisioning,
    provider: &Provider,
    claims: &Map<String, Value>,
) -> Result<Option<storage::LocalUser>, sqlx::Error> {
    let raw_email = match provider
        .config
        .provider_metadata
        .get("email_claim")
        .and_then(Value::as_str)
    {
        Some(claim) => claims.get(claim).and_then(Value::as_str),
        None => ["email", "preferred_username", "upn", "unique_name", "mail"]
            .into_iter()
            .filter_map(|claim| claims.get(claim).and_then(Value::as_str))
            .find(|value| value.contains('@')),
    };
    let Some(email) = raw_email
        .map(|email| email.trim().to_ascii_lowercase())
        .filter(|email| valid_email(email))
    else {
        return Ok(None);
    };
    if claims
        .get("email_verified")
        .is_some_and(|claim| !email_verified(claim))
    {
        return Ok(None);
    }
    if !provider.config.trusted_domains.is_empty()
        && email.rsplit_once('@').is_none_or(|(_, domain)| {
            provider
                .config
                .trusted_domains
                .iter()
                .all(|trusted| !trusted.eq_ignore_ascii_case(domain))
        })
    {
        return Ok(None);
    }
    if let Some(user) = database.local_user(&email).await? {
        if user.auth_provider != provider.id || !user.is_active || user.locked(Timestamp::now()) {
            return Ok(None);
        }
        return database.record_successful_login(&user).await;
    }
    if !provider.config.auto_create_users {
        return Ok(None);
    }
    let name = claims
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&email)
        .chars()
        .filter(|ch| !ch.is_control())
        .take(255)
        .collect();
    let user = storage::NewUser {
        email: email.clone(),
        full_name: Some(name),
        is_admin: false,
        is_active: true,
        password_hash: None,
        auth_provider: provider.id.clone(),
        password_change_required: false,
        granted_by: None,
        admin_origin: None,
    };
    database.create_local_user(&user, provisioning).await?;
    Ok(database.local_user(&email).await?.filter(|user| {
        user.auth_provider == provider.id && user.is_active && !user.locked(Timestamp::now())
    }))
}

pub(super) fn email_verified(claim: &Value) -> bool {
    claim.as_bool().unwrap_or_else(|| {
        claim.as_i64() == Some(1)
            || claim.as_str().is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes"
                )
            })
    })
}
