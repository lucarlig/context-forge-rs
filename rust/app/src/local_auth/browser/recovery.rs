// SPDX-License-Identifier: Apache-2.0

use axum::http::Uri;
use percent_encoding::AsciiSet;

use super::*;

const FORGOT: &str = "/admin/forgot-password";
const RESET: &str = "/admin/reset-password";
const TOKEN_PATH: AsciiSet = forms::QUERY_ENCODE.add(b'/');

pub(super) async fn forgot_page(
    State(accounts): State<Arc<Accounts>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let query = forms::query(&uri);
    let proof = forms::nonce(&headers)?;
    let mut response = render(context! {
        title => "Forgot Password - MCP Gateway",
        page => "forgot",
        root => settings.root,
        proof => proof,
        enabled => accounts.settings.reset.enabled,
        error => forgot_error(query.get("error").map(String::as_str)),
    })?;
    sessions::set_proof(
        &mut response,
        settings,
        accounts.settings.token_seconds,
        &proof,
    )?;
    Ok(response)
}

pub(super) async fn forgot(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let (parts, form) = Form::from_request(request).await?;
    csrf(settings, &parts, &form, false)?;
    if !accounts.settings.reset.enabled {
        return Ok(settings.error(FORGOT, "password_reset_disabled", None));
    }
    let email = form.get("email").trim().to_ascii_lowercase();
    if email.is_empty() {
        return Ok(settings.error(FORGOT, "missing_email", None));
    }
    let client = Client::new(Some(peer), &parts.headers);
    Ok(
        match password_reset::request(&accounts, email, &client).await {
            Ok(()) => settings.redirect("/admin/login?notice=reset_email_sent"),
            Err(AccountError(StatusCode::TOO_MANY_REQUESTS, _)) => {
                settings.error(FORGOT, "rate_limited", None)
            }
            Err(_) => settings.error(FORGOT, "server_error", None),
        },
    )
}

pub(super) async fn reset_page(
    State(accounts): State<Arc<Accounts>>,
    Path(token): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    if !accounts.settings.reset.enabled {
        return Ok(settings.error(FORGOT, "password_reset_disabled", None));
    }
    let token = Zeroizing::new(token);
    let link_error = match password_reset::check_link(&accounts, &token).await {
        Ok(_) => None,
        Err(AccountError(StatusCode::BAD_REQUEST | StatusCode::GONE, body)) => {
            body["detail"].as_str().map(str::to_owned)
        }
        Err(error) => return Err(error),
    };
    let proof = forms::nonce(&headers)?;
    let query = forms::query(&uri);
    let mut response = render(context! {
        title => "Reset Password - ContextForge",
        page => "reset",
        root => settings.root,
        proof => proof,
        path => reset_path(&token),
        minimum => settings.reset_form_minimum,
        link_error => link_error,
        error => reset_error(query.get("error").map(String::as_str)),
    })?;
    sessions::set_proof(
        &mut response,
        settings,
        accounts.settings.token_seconds,
        &proof,
    )?;
    Ok(response)
}

pub(super) async fn reset(
    State(accounts): State<Arc<Accounts>>,
    Path(token): Path<String>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let (parts, form) = Form::from_request(request).await?;
    csrf(settings, &parts, &form, false)?;
    if !accounts.settings.reset.enabled {
        return Ok(settings.error(FORGOT, "password_reset_disabled", None));
    }
    let token = Zeroizing::new(token);
    let path = reset_path(&token);
    let password = form.get("password");
    let confirmation = form.get("confirm_password");
    if password.is_empty() || confirmation.is_empty() {
        return Ok(settings.error(&path, "missing_fields", None));
    }
    if password != confirmation {
        return Ok(settings.error(&path, "password_mismatch", None));
    }
    let client = Client::new(Some(peer), &parts.headers);
    Ok(
        match password_reset::reset(
            &accounts,
            &token,
            Zeroizing::new(password.to_owned()),
            &client,
        )
        .await
        {
            Ok(()) => settings.redirect("/admin/login?notice=password_reset_success"),
            Err(AccountError(StatusCode::GONE, _)) => {
                settings.error(FORGOT, "reset_link_expired", None)
            }
            Err(AccountError(StatusCode::BAD_REQUEST, body)) => match body["detail"].as_str() {
                Some(password_reset::INVALID_LINK) => {
                    settings.error(FORGOT, "reset_link_invalid", None)
                }
                Some(password_reset::USED_LINK) => settings.error(FORGOT, "reset_link_used", None),
                Some(detail) => settings.error(&path, detail, None),
                None => settings.error(&path, "server_error", None),
            },
            Err(_) => settings.error(&path, "server_error", None),
        },
    )
}

fn reset_path(token: &str) -> String {
    format!("{RESET}/{}", utf8_percent_encode(token, &TOKEN_PATH))
}

pub(super) fn notice(notice: Option<&str>) -> Option<&'static str> {
    match notice? {
        "reset_email_sent" => Some("If the account exists, a password reset link has been sent."),
        "password_reset_success" => {
            Some("Password reset successful. Sign in with your new password.")
        }
        _ => None,
    }
}

fn forgot_error(error: Option<&str>) -> Option<&'static str> {
    Some(match error? {
        "missing_email" => "Please provide an email address.",
        "rate_limited" => "Too many requests. Please try again later.",
        "reset_link_expired" => "The reset link expired. Request a new one.",
        "reset_link_used" => "This reset link was already used. Request a new one.",
        "reset_link_invalid" => "Invalid reset link. Request a new one.",
        "password_reset_disabled" => "Password reset is disabled.",
        _ => "Request failed. Please try again.",
    })
}

fn reset_error(error: Option<&str>) -> Option<&str> {
    Some(match error? {
        "missing_fields" => "Complete both password fields.",
        "password_mismatch" => "Passwords do not match.",
        "server_error" => "The password could not be reset. Please try again.",
        detail => detail,
    })
}
