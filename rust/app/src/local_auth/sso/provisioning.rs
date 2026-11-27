// SPDX-License-Identifier: Apache-2.0

use axum::body::Bytes;

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedSsoUser {
    email: String,
    auth_provider: String,
    full_name: Option<String>,
    #[serde(default)]
    is_admin: bool,
    is_active: Option<bool>,
}

pub(super) async fn create_user(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<Value>), AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let media = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|content| content.split(';').next())
        .is_some_and(|content| content.trim().eq_ignore_ascii_case("application/json"));
    if !media {
        return Err(AccountError::detail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json",
        ));
    }
    let payload: Value = serde_json::from_slice(&body)
        .map_err(|_| AccountError::bad_request("Invalid JSON in request body"))?;
    if payload.get("password").is_some() {
        return Err(AccountError::bad_request(
            "password not allowed for SSO users",
        ));
    }
    let input: ManagedSsoUser = serde_json::from_value(payload).map_err(|_| {
        AccountError::detail(StatusCode::UNPROCESSABLE_ENTITY, "Invalid SSO user request")
    })?;
    if input.is_admin && !principal.is_global_admin() {
        return Err(AccountError::detail(
            StatusCode::FORBIDDEN,
            "Administrator creation requires a platform administrator",
        ));
    }
    let email = input.email.trim().to_ascii_lowercase();
    let full_name = input.full_name.map(|name| name.trim().to_owned());
    if !valid_email(&email)
        || full_name
            .as_ref()
            .is_some_and(|name| name.chars().count() > 255)
    {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid SSO user request",
        ));
    }
    let provider = input.auth_provider.trim().to_ascii_lowercase();
    let provider = if provider == "azure-ad" {
        "entra"
    } else {
        &provider
    };
    if provider.is_empty() {
        return Err(AccountError::bad_request("SSO provider ID is required"));
    }
    if provider.chars().count() > 50 {
        return Err(AccountError::bad_request(
            "SSO provider ID exceeds 50 characters",
        ));
    }
    let provider = accounts
        .database
        .sso_provider(provider)
        .await?
        .ok_or_else(|| {
            AccountError::bad_request(format!("SSO provider '{provider}' is not configured"))
        })?;
    if !provider.config.is_enabled {
        return Err(AccountError::bad_request(format!(
            "SSO provider '{}' is disabled",
            provider.id
        )));
    }
    let new_user = storage::NewUser {
        email: email.clone(),
        full_name,
        is_admin: input.is_admin,
        is_active: input.is_active.unwrap_or(true),
        password_hash: None,
        auth_provider: provider.id,
        approval_required: false,
        email_verified: false,
        password_change_required: false,
        granted_by: Some(principal.email.clone()),
        admin_origin: input.is_admin.then_some("api"),
    };
    if !accounts
        .database
        .create_local_user(&new_user, &accounts.settings.provisioning)
        .await?
    {
        return Err(duplicate_user(&email));
    }
    let user = accounts
        .database
        .local_user(&email)
        .await?
        .ok_or_else(AccountError::unavailable)?;
    Ok((StatusCode::CREATED, Json(user.metadata())))
}
