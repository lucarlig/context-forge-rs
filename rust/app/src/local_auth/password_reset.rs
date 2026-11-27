// SPDX-License-Identifier: Apache-2.0

use ring::rand::{SecureRandom, SystemRandom};

use super::{
    user_lifecycle::{prepare_password, success},
    *,
};
use crate::tokens::hash_token;

pub(crate) struct ResetSettings {
    pub(crate) enabled: bool,
    pub(crate) lifetime: i64,
    pub(crate) window: i64,
    pub(crate) limit: i64,
    pub(crate) response_floor: Duration,
    pub(crate) lockout_email: bool,
    pub(crate) frontend: String,
}

#[derive(Deserialize)]
pub(super) struct ForgotPassword {
    email: String,
}

#[derive(Deserialize)]
pub(super) struct ResetPassword {
    new_password: String,
    confirm_password: String,
}

pub(super) async fn forgot(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(input): Json<ForgotPassword>,
) -> Result<Json<Value>, AccountError> {
    enabled(&accounts)?;
    let start = Instant::now();
    let email = input.email.trim().to_ascii_lowercase();
    if !valid_email(&email) {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid email format",
        ));
    }
    let mut random = [0_u8; 48];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| AccountError::unavailable())?;
    let token = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random));
    let hash = hash_token(&token);
    let client = Client::new(Some(peer), &headers);
    let outcome = accounts
        .database
        .request_local_password_reset(&email, &hash, &client, &accounts.settings.reset)
        .await?;
    let limited = match outcome {
        storage::ResetRequest::Limited => true,
        storage::ResetRequest::Accepted => false,
        storage::ResetRequest::Issued(full_name) => {
            let clerk = accounts.clone();
            tokio::spawn(async move {
                let name = display_name(&email, full_name.as_deref());
                let link = format!(
                    "{}/reset-password/{}",
                    clerk.settings.reset.frontend,
                    token.as_str()
                );
                let body = format!(
                    "Hi {name},\n\nUse this link to reset your ContextForge password:\n{link}\n\nThe link expires in {} minutes.",
                    clerk.settings.reset.lifetime / 60,
                );
                if let Some(mailer) = clerk.settings.mailer.as_ref() {
                    mailer
                        .send(&email, "Reset your ContextForge password", body)
                        .await;
                }
            });
            false
        }
    };
    tokio::time::sleep(
        accounts
            .settings
            .reset
            .response_floor
            .saturating_sub(start.elapsed()),
    )
    .await;
    if limited {
        return Err(AccountError::detail(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Please try again later.",
        ));
    }
    Ok(success(
        "If this email is registered, you will receive a reset link.",
    ))
}

pub(super) async fn validate(
    State(accounts): State<Arc<Accounts>>,
    Path(token): Path<String>,
) -> Result<Json<Value>, AccountError> {
    enabled(&accounts)?;
    let token = Zeroizing::new(token);
    let reset = find(&accounts, &hash_token(&token)).await?;
    Ok(Json(
        json!({"valid":true,"message":"Reset token is valid","expires_at":reset.expires_at.replacen(' ',"T",1)}),
    ))
}

pub(super) async fn complete(
    State(accounts): State<Arc<Accounts>>,
    Path(token): Path<String>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(input): Json<ResetPassword>,
) -> Result<Json<Value>, AccountError> {
    enabled(&accounts)?;
    let password = Zeroizing::new(input.new_password);
    let confirmation = Zeroizing::new(input.confirm_password);
    let password = password.trim();
    if password.chars().count() < 8 {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "New password must be at least 8 characters long",
        ));
    }
    if password != confirmation.trim() {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Passwords do not match",
        ));
    }
    let token = Zeroizing::new(token);
    let hash = hash_token(&token);
    let reset = find(&accounts, &hash).await?;
    let user = accounts
        .database
        .local_user(&reset.user_email)
        .await?
        .filter(|user| user.is_active && user.password_hash.is_some())
        .ok_or_else(invalid)?;
    let password_hash = prepare_password(
        &accounts,
        &user,
        user.is_admin,
        Zeroizing::new(password.to_owned()),
    )
    .await?;
    accounts
        .database
        .edit_local_user(
            &user,
            &user_lifecycle::UserPatch::default(),
            Some(storage::CredentialChange {
                hash: &password_hash,
                reason: "password_reset",
                reset_token: Some(&hash),
            }),
            &user.email,
            &accounts.settings,
        )
        .await?;
    let client = Client::new(Some(peer), &headers);
    accounts
        .database
        .local_event(&user.email, "PASSWORD_RESET_COMPLETED", true, &client, None)
        .await?;
    if accounts.settings.mailer.is_some() {
        tokio::spawn(async move {
            let name = display_name(&user.email, user.full_name.as_deref());
            let body = format!(
                "Hi {name},\n\nYour ContextForge password was changed. If you did not request this change, contact your administrator."
            );
            if let Some(mailer) = accounts.settings.mailer.as_ref() {
                mailer
                    .send(&user.email, "Your ContextForge password was changed", body)
                    .await;
            }
        });
    }
    Ok(success(
        "Password reset successful. Please sign in with your new password.",
    ))
}

pub(super) fn notify_lockout(accounts: &Arc<Accounts>, email: String, full_name: Option<String>) {
    if !accounts.settings.reset.lockout_email || accounts.settings.mailer.is_none() {
        return;
    }
    let accounts = accounts.clone();
    tokio::spawn(async move {
        let name = display_name(&email, full_name.as_deref());
        let link = format!("{}/forgot-password", accounts.settings.reset.frontend);
        let body = format!(
            "Hi {name},\n\nYour ContextForge account is temporarily locked after multiple failed login attempts.\nTo reset your password, use {link}"
        );
        if let Some(mailer) = accounts.settings.mailer.as_ref() {
            mailer
                .send(
                    &email,
                    "Your ContextForge account was temporarily locked",
                    body,
                )
                .await;
        }
    });
}

fn display_name<'a>(email: &'a str, name: Option<&'a str>) -> &'a str {
    name.filter(|name| !name.is_empty())
        .unwrap_or_else(|| email.split('@').next().unwrap_or(email))
}

fn enabled(accounts: &Accounts) -> Result<(), AccountError> {
    if !accounts.settings.reset.enabled {
        return Err(AccountError::detail(
            StatusCode::FORBIDDEN,
            "Password reset is disabled",
        ));
    }
    Ok(())
}

pub(super) fn invalid() -> AccountError {
    AccountError::bad_request("This reset link is invalid")
}

pub(super) fn expired() -> AccountError {
    AccountError::detail(StatusCode::GONE, "This reset link has expired")
}

async fn find(accounts: &Accounts, hash: &str) -> Result<storage::ResetToken, AccountError> {
    let reset = accounts
        .database
        .local_password_reset(hash)
        .await?
        .filter(|token| !token.used)
        .ok_or_else(invalid)?;
    if parse_timestamp(&reset.expires_at).is_none_or(|expires| expires <= Timestamp::now()) {
        return Err(expired());
    }
    Ok(reset)
}
