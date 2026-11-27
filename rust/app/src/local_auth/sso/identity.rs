// SPDX-License-Identifier: Apache-2.0

use serde_json::Map;

use super::{providers::Provider, *};

pub(super) async fn authenticate_identity(
    database: &Database,
    provisioning: &UserProvisioning,
    provider: &Provider,
    claims: &Map<String, Value>,
    approval_required: bool,
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
    let verified = [
        "email_verified",
        "verified_primary_email",
        "verified_secondary_email",
    ]
    .iter()
    .find_map(|field| claims.get(*field))
    .map(email_verified);
    if verified == Some(false) {
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
    let name: String = claims
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&email)
        .chars()
        .filter(|ch| !ch.is_control())
        .take(255)
        .collect();
    if approval_required {
        let mut metadata = json!({
            "email":email,"full_name":name,"avatar_url":claims.get("picture"),
            "provider":provider.id,"provider_id":claims.get("sub"),
            "groups":groups(provider, claims),
            "username":claims.get("preferred_username").and_then(Value::as_str)
                .or_else(||email.split_once('@').map(|(local,_)|local)),
        });
        if let Some(verified) = verified {
            metadata["email_verified"] = verified.into();
        }
        database
            .queue_sso_approval(&email, &name, &provider.id, metadata)
            .await?;
    }
    let user = storage::NewUser {
        email: email.clone(),
        full_name: Some(name),
        is_admin: false,
        is_active: true,
        password_hash: None,
        auth_provider: provider.id.clone(),
        approval_required,
        password_change_required: false,
        granted_by: None,
        admin_origin: None,
    };
    database.create_local_user(&user, provisioning).await?;
    Ok(database.local_user(&email).await?.filter(|user| {
        user.auth_provider == provider.id && user.is_active && !user.locked(Timestamp::now())
    }))
}

fn groups<'a>(provider: &Provider, claims: &'a Map<String, Value>) -> Vec<&'a str> {
    let claim = provider
        .config
        .provider_metadata
        .get("groups_claim")
        .and_then(Value::as_str)
        .unwrap_or("groups");
    let mut groups = Vec::new();
    for value in [claims.get(claim), claims.get("roles")]
        .into_iter()
        .flatten()
    {
        match value {
            Value::String(group) => groups.push(group.as_str()),
            Value::Array(names) => groups.extend(names.iter().filter_map(Value::as_str)),
            Value::Object(buckets) => {
                for values in buckets.values() {
                    match values {
                        Value::String(group) => groups.push(group.as_str()),
                        Value::Array(names) => {
                            groups.extend(names.iter().filter_map(Value::as_str))
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    let mut seen = HashSet::new();
    groups.retain(|group| seen.insert(*group));
    groups
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
