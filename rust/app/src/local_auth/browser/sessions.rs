// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use super::*;
use crate::{access::AuthError, jwt::JwtError};
use axum::http::Uri;

pub(super) struct Session<'a> {
    pub(super) principal: Principal,
    pub(super) token: &'a str,
}

pub(super) async fn access<'a>(
    accounts: &Accounts,
    headers: &'a HeaderMap,
    uri: &Uri,
    peer: IpAddr,
) -> Result<Session<'a>, Denial> {
    let settings = settings_for(accounts);
    let token = bearer_token(settings, headers)
        .or_else(|| auth_cookie(headers))
        .ok_or(Denial(
            StatusCode::UNAUTHORIZED,
            "Authentication required",
            None,
        ))?;
    let principal = match accounts.access.authenticate(token, Some(peer), None).await {
        Ok(principal) => principal,
        Err(AuthError::Storage(_)) => {
            return Err(Denial(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication error",
                None,
            ));
        }
        Err(AuthError::TeamRevoked) => {
            return Err(Denial(
                StatusCode::FORBIDDEN,
                "Token is invalid: User is no longer a member of the associated team",
                None,
            ));
        }
        Err(AuthError::Forbidden) => {
            return Err(Denial(StatusCode::FORBIDDEN, "Access denied", None));
        }
        Err(_) => {
            let verified = accounts.access.verify_gateway_token(token);
            let (reason, error) = match verified.as_ref() {
                Err(JwtError::Expired) => ("Token has expired", Some("session_expired")),
                Ok(jwt) => {
                    if let Some(jti) = jwt.jti() {
                        match accounts.database.browser_token_revoked(jti).await {
                            Ok(true) => {
                                return Err(Denial(
                                    StatusCode::UNAUTHORIZED,
                                    "Token has been revoked",
                                    Some("token_revoked"),
                                ));
                            }
                            Ok(false) => {}
                            Err(_) => {
                                return Err(Denial(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    "Authentication error",
                                    None,
                                ));
                            }
                        }
                    }
                    ("Invalid token", None)
                }
                Err(_) => ("Invalid token", None),
            };
            return Err(Denial(StatusCode::UNAUTHORIZED, reason, error));
        }
    };
    let team = request_team(uri, &principal);
    match accounts
        .access
        .allows_admin_ui(&principal, role_context(team.as_deref()))
        .await
    {
        Ok(true) => Ok(Session { principal, token }),
        Ok(false) => Err(Denial(
            StatusCode::FORBIDDEN,
            "Admin privileges required",
            Some("admin_required"),
        )),
        Err(_) => Err(Denial(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Authentication error",
            None,
        )),
    }
}

pub(super) fn bearer_token<'a>(
    settings: &BrowserSettings,
    headers: &'a HeaderMap,
) -> Option<&'a str> {
    forms::header_text(headers, settings.auth_header.clone())
        .and_then(|value| value.split_once(' '))
        .filter(|(scheme, credential)| {
            scheme.eq_ignore_ascii_case("bearer") && !credential.trim().is_empty()
        })
        .map(|(_, credential)| credential.trim())
}

pub(super) fn request_team(uri: &Uri, principal: &Principal) -> Option<String> {
    let team = forms::query(uri).remove("team_id")?;
    let team = Uuid::parse_str(&team).map_or(team, |id| id.simple().to_string());
    match &principal.visibility {
        TeamVisibility::Admin => Some(team),
        TeamVisibility::Teams(teams) if teams.contains(&team) => Some(team),
        _ => None,
    }
}

pub(super) fn role_context(team: Option<&str>) -> RoleContext<'_> {
    team.map_or(RoleContext::Global, RoleContext::Team)
}

pub(super) struct Denial(pub StatusCode, pub &'static str, pub Option<&'static str>);

impl Denial {
    pub(super) fn response(self, settings: &BrowserSettings, headers: &HeaderMap) -> Response {
        let Self(status, detail, error) = self;
        let suffix = error.map_or_else(String::new, |error| format!("?error={error}"));
        let location = format!("{}{LOGIN}{suffix}", settings.root);
        if htmx(headers) {
            return (StatusCode::OK, [("hx-redirect", location)]).into_response();
        }
        if forms::header_text(headers, header::ACCEPT)
            .is_some_and(|value| value.contains("text/html"))
        {
            return (StatusCode::FOUND, [(header::LOCATION, location)]).into_response();
        }
        (status, Json(json!({"detail":detail}))).into_response()
    }
}

fn htmx(headers: &HeaderMap) -> bool {
    headers
        .get("hx-request")
        .is_some_and(|header| header == "true")
}

pub(super) async fn create_session(
    accounts: &Accounts,
    user: &storage::LocalUser,
    mut response: Response,
    email: Option<&str>,
) -> Result<Response, AccountError> {
    let settings = settings_for(accounts);
    let (token, session, now) = issue_local_session(accounts, user).await?;
    let proof = accounts
        .settings
        .csrf
        .issue(&user.email, &session, now)
        .ok_or_else(AccountError::unavailable)?;
    let cookie = cookie_header(
        "jwt_token",
        &token,
        settings.cookie_path(),
        3600,
        &settings.same_site,
        settings.secure,
        true,
    )?;
    if cookie.len() > 4096 {
        return Ok(settings.error(
            LOGIN,
            "token_too_large",
            email.map(|email| ("email", email)),
        ));
    }
    response.headers_mut().append(header::SET_COOKIE, cookie);
    set_proof(
        &mut response,
        settings,
        accounts.settings.token_seconds,
        &proof,
    )?;
    Ok(response)
}

pub(super) fn proof(
    accounts: &Accounts,
    headers: &HeaderMap,
    principal: &Principal,
    token: &str,
) -> Result<String, AccountError> {
    match accounts
        .access
        .verify_gateway_token(token)
        .ok()
        .and_then(|jwt| {
            accounts
                .settings
                .csrf
                .issue(&principal.email, jwt.jti()?, Timestamp::now().as_second())
        }) {
        Some(proof) => Ok(proof),
        None => forms::nonce(headers),
    }
}

pub(super) fn set_proof(
    response: &mut Response,
    settings: &BrowserSettings,
    seconds: i64,
    proof: &str,
) -> Result<(), AccountError> {
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie_header(
            CSRF_COOKIE,
            proof,
            settings.cookie_path(),
            seconds.max(300),
            "strict",
            settings.secure,
            false,
        )?,
    );
    Ok(())
}

pub(super) fn clear_invalid_cookies(response: &mut Response) {
    for cookie in [
        "jwt_token=; Path=/; Max-Age=0; SameSite=lax",
        "access_token=; Path=/; Max-Age=0; SameSite=lax",
    ] {
        response
            .headers_mut()
            .append(header::SET_COOKIE, HeaderValue::from_static(cookie));
    }
}

pub(super) fn clear_session_cookies(
    account: &AccountSettings,
    settings: &BrowserSettings,
    response: &mut Response,
) -> Result<(), AccountError> {
    for (name, path, same_site, secure, http_only) in [
        (
            "jwt_token",
            settings.cookie_path(),
            settings.same_site.as_str(),
            settings.secure,
            true,
        ),
        (
            account.csrf.cookie_name.as_str(),
            "/",
            account.csrf_samesite.as_str(),
            account.csrf_secure,
            account.csrf_httponly,
        ),
        (
            sso::ID_TOKEN_HINT_COOKIE,
            settings.cookie_path(),
            settings.same_site.as_str(),
            settings.secure,
            true,
        ),
        (
            CSRF_COOKIE,
            settings.cookie_path(),
            "strict",
            settings.secure,
            false,
        ),
    ] {
        response.headers_mut().append(
            header::SET_COOKIE,
            cookie_header(name, "", path, 0, same_site, secure, http_only)?,
        );
    }
    Ok(())
}

fn cookie_header(
    name: &str,
    value: &str,
    path: &str,
    max_age: i64,
    same_site: &str,
    secure: bool,
    http_only: bool,
) -> Result<HeaderValue, AccountError> {
    let mut value = format!("{name}={value}; Path={path}; Max-Age={max_age}; SameSite={same_site}");
    if http_only {
        value.push_str("; HttpOnly");
    }
    if secure {
        value.push_str("; Secure");
    }
    let mut header = HeaderValue::from_str(&value).map_err(|_| AccountError::unavailable())?;
    header.set_sensitive(true);
    Ok(header)
}

pub(super) async fn revoke(accounts: &Accounts, token: &str) -> Result<(), AccountError> {
    let Ok(jwt) = accounts.access.verify_gateway_token(token) else {
        return Ok(());
    };
    let (Some(jti), Ok(principal)) = (
        jwt.jti(),
        accounts.access.authenticate(token, None, None).await,
    ) else {
        return Ok(());
    };
    let expiry = jwt.payload()["exp"]
        .as_i64()
        .and_then(|seconds| Timestamp::from_second(seconds).ok());
    let activity = jwt.payload()["last_activity"]
        .as_i64()
        .and_then(|seconds| Timestamp::from_second(seconds).ok());
    accounts
        .database
        .revoke_browser_token(jti, &principal.email, expiry, activity)
        .await?;
    Ok(())
}

impl Database {
    async fn revoke_browser_token(
        &self,
        jti: &str,
        email: &str,
        expiry: Option<Timestamp>,
        activity: Option<Timestamp>,
    ) -> Result<(), sqlx::Error> {
        macro_rules! revoke {
            ($pool:ident, $expiry:literal, $activity:literal) => {{
                sqlx::query(concat!(
                    "INSERT INTO token_revocations(jti, revoked_by, reason, token_expiry, last_activity)
                     VALUES ($1, $2, 'admin_logout', ", $expiry, ", ", $activity, ")
                     ON CONFLICT (jti) DO NOTHING"
                ))
                    .bind(jti)
                    .bind(email)
                    .bind(expiry.map(|time| time.to_string()))
                    .bind(activity.map(|time| time.to_string()))
                    .execute($pool).await?;
            }};
        }
        match self {
            Self::Sqlite(pool) => revoke!(pool, "$3", "$4"),
            Self::Postgres(pool) => revoke!(
                pool,
                "CAST($3 AS TEXT)::timestamptz",
                "CAST($4 AS TEXT)::timestamptz"
            ),
        }
        Ok(())
    }

    async fn browser_token_revoked(&self, jti: &str) -> Result<bool, sqlx::Error> {
        const QUERY: &str = "SELECT EXISTS (SELECT 1 FROM token_revocations WHERE jti=$1)";
        match self {
            Self::Sqlite(pool) => sqlx::query_scalar(QUERY).bind(jti).fetch_one(pool).await,
            Self::Postgres(pool) => sqlx::query_scalar(QUERY).bind(jti).fetch_one(pool).await,
        }
    }
}
