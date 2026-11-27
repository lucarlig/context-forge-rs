// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::jwt::TokenUse;

#[derive(Deserialize)]
pub(super) struct PasswordChange {
    old_password: String,
    new_password: String,
}

#[derive(Default, Deserialize)]
pub(super) struct UserPatch {
    pub(super) full_name: Option<String>,
    pub(super) is_admin: Option<bool>,
    pub(super) is_active: Option<bool>,
    pub(super) email_verified: Option<bool>,
    pub(super) password_change_required: Option<bool>,
    password: Option<String>,
}

pub(super) async fn change_password(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(input): Json<PasswordChange>,
) -> Result<Json<Value>, AccountError> {
    if principal.token_use != TokenUse::Session {
        return Err(AccountError::detail(
            StatusCode::FORBIDDEN,
            "An interactive session is required",
        ));
    }
    let client = Client::new(Some(peer), &headers);
    change_local_password(
        &accounts,
        &principal.email,
        Zeroizing::new(input.old_password),
        Zeroizing::new(input.new_password),
        &client,
    )
    .await?;
    Ok(success("Password changed successfully"))
}

pub(super) async fn change_local_password(
    accounts: &Arc<Accounts>,
    email: &str,
    old_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
    client: &Client,
) -> Result<storage::LocalUser, AccountError> {
    let user = verify_local_password(accounts, email, old_password, client)
        .await?
        .ok_or_else(|| {
            AccountError::detail(StatusCode::UNAUTHORIZED, "Current password is incorrect")
        })?;
    let hash = prepare_password(accounts, &user, user.is_admin, new_password).await?;
    let patch = UserPatch {
        password_change_required: Some(false),
        ..UserPatch::default()
    };
    let updated = accounts
        .database
        .edit_local_user(
            &user,
            &patch,
            Some(storage::CredentialChange {
                hash: &hash,
                reason: "password_change",
                reset_token: None,
            }),
            &user.email,
            &accounts.settings,
        )
        .await?;
    accounts
        .database
        .local_event(&user.email, "password_change", true, client, None)
        .await?;
    Ok(updated)
}

pub(super) async fn edit_user(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(email): Path<String>,
    Json(mut patch): Json<UserPatch>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let email = email.trim().to_ascii_lowercase();
    let user = accounts
        .database
        .local_user(&email)
        .await?
        .ok_or_else(AccountError::missing)?;
    if patch
        .full_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > 255)
    {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Full name is too long",
        ));
    }
    let promotes = !user.is_admin && patch.is_admin == Some(true);
    if (promotes || patch.is_admin == Some(false) && user.is_admin) && !principal.is_global_admin()
    {
        return Err(AccountError::detail(
            StatusCode::FORBIDDEN,
            "Administrator status changes require a platform administrator",
        ));
    }
    if user.password_hash.is_none() && patch.password_change_required == Some(true) {
        return Err(AccountError::bad_request(
            "Password change cannot be required for passwordless users",
        ));
    }
    let hash = if let Some(password) = patch.password.take() {
        Some(
            prepare_password(
                &accounts,
                &user,
                patch.is_admin.unwrap_or(user.is_admin),
                Zeroizing::new(password),
            )
            .await?,
        )
    } else {
        None
    };
    let edited = accounts
        .database
        .edit_local_user(
            &user,
            &patch,
            hash.as_deref().map(|hash| storage::CredentialChange {
                hash,
                reason: "admin_password_reset",
                reset_token: None,
            }),
            &principal.email,
            &accounts.settings,
        )
        .await?;
    Ok(Json(edited.metadata()))
}

pub(super) async fn unlock_user(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(email): Path<String>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let email = email.trim().to_ascii_lowercase();
    if !accounts.database.unlock_local_user(&email).await? {
        return Err(AccountError::detail(
            StatusCode::NOT_FOUND,
            format!("User {email} not found"),
        ));
    }
    Ok(success(format!("User {email} has been unlocked")))
}

pub(super) async fn delete_user(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(email): Path<String>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let email = email.trim().to_ascii_lowercase();
    if email == principal.email {
        return Err(AccountError::bad_request("Cannot delete your own account"));
    }
    accounts
        .database
        .delete_local_user(&email, &principal.email, &accounts.settings.bootstrap_email)
        .await?;
    Ok(success(format!("User {email} has been deleted")))
}

pub(super) async fn prepare_password(
    accounts: &Accounts,
    user: &storage::LocalUser,
    admin: bool,
    password: Zeroizing<String>,
) -> Result<String, AccountError> {
    let old = user.password_hash.as_ref().ok_or_else(|| {
        AccountError::bad_request("Local password updates are not allowed for passwordless users")
    })?;
    passwords::validate(&accounts.settings, &password, &user.email, admin)?;
    if passwords::verify(password.clone(), old.clone()).await? {
        return Err(AccountError::bad_request(
            "New password must be different from current password",
        ));
    }
    let count = accounts.settings.password_history;
    let prior = accounts
        .database
        .local_password_history(&user.email, count)
        .await?;
    for hashed in prior {
        if passwords::verify(password.clone(), hashed).await? {
            return Err(AccountError::bad_request(format!(
                "Password was used recently. Please choose a different password (last {count} passwords cannot be reused)"
            )));
        }
    }
    passwords::hash(password, accounts.settings.kdf).await
}

pub(super) fn success(message: impl Into<String>) -> Json<Value> {
    Json(json!({"success":true,"message":message.into()}))
}
