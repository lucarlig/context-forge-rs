// SPDX-License-Identifier: Apache-2.0

mod catalog;
mod forms;
mod keycloak;
mod recovery;
mod sessions;
mod token;
mod users;

use std::error::Error;

use axum::{
    extract::Request,
    http::{HeaderName, Method},
    response::{Html, Redirect},
};
use minijinja::context;
use percent_encoding::utf8_percent_encode;

use self::forms::{Form, csrf, render};
use self::sessions::{Denial, Session, access, clear_session_cookies, create_session};
use super::*;
use crate::{
    access::{auth_cookie, browser_request, cookie},
    auth::TeamVisibility,
    catalog::ManagedCatalog,
    config::{flag, parse, value},
    http_boundary::{allowed_origins, csrf::ADMIN_CSRF_COOKIE as CSRF_COOKIE},
    jwt::TokenUse,
};

const LOGIN: &str = "/admin/login";
const CHANGE: &str = "/admin/change-password-required";

pub(crate) struct BrowserSettings {
    root: String,
    secure: bool,
    same_site: String,
    origins: Vec<String>,
    auth_header: HeaderName,
    ui: bool,
    password_error_limit: usize,
    reset_form_minimum: usize,
    preserve_admin_auth: bool,
    keycloak: Option<keycloak::KeycloakLogout>,
}

impl BrowserSettings {
    pub(crate) fn from_env() -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        if !flag("MCPGATEWAY_ADMIN_API_ENABLED")?.unwrap_or(false) {
            return Ok(None);
        }
        let root = value("APP_ROOT_PATH", "")?;
        let root = root.trim().trim_matches('/');
        let root = if root.is_empty()
            || root.contains("://")
            || root
                .chars()
                .any(|c| c.is_control() || matches!(c, '\\' | '?' | '#' | ';' | ' '))
        {
            String::new()
        } else {
            format!("/{root}")
        };
        let same_site = value("COOKIE_SAMESITE", "lax")?;
        if !["lax", "strict", "none"]
            .iter()
            .any(|item| same_site.eq_ignore_ascii_case(item))
        {
            return Err("invalid COOKIE_SAMESITE".into());
        }
        let origins = allowed_origins(parse("PORT", 4444)?)?
            .into_iter()
            .filter_map(|origin| forms::allowed_origin(&origin))
            .collect();
        Ok(Some(Self {
            root,
            secure: flag("SECURE_COOKIES")?.unwrap_or(true)
                || value("ENVIRONMENT", "development")? == "production",
            same_site,
            origins,
            auth_header: HeaderName::try_from(value("AUTH_HEADER_NAME", "Authorization")?)
                .map_err(|_| "invalid AUTH_HEADER_NAME")?,
            ui: flag("MCPGATEWAY_UI_ENABLED")?.unwrap_or(false),
            password_error_limit: parse("PASSWORD_ERROR_MESSAGE_MAX_LENGTH", 200)?,
            reset_form_minimum: parse("PASSWORD_MIN_LENGTH", 8)?,
            preserve_admin_auth: flag("SSO_ENABLED")?.unwrap_or(false)
                && flag("SSO_PRESERVE_ADMIN_AUTH")?.unwrap_or(true),
            keycloak: keycloak::KeycloakLogout::from_env()?,
        }))
    }

    fn redirect(&self, path: &str) -> Response {
        Redirect::to(&format!("{}{path}", self.root)).into_response()
    }

    fn error(&self, page: &str, error: &str, query: Option<(&str, &str)>) -> Response {
        let error = utf8_percent_encode(error, &forms::QUERY_ENCODE);
        let mut path = format!("{page}?error={error}");
        if let Some((name, value)) = query.filter(|(_, value)| !value.is_empty()) {
            use std::fmt::Write as _;
            let _ = write!(
                path,
                "&{name}={}",
                utf8_percent_encode(value, &forms::QUERY_ENCODE)
            );
        }
        self.redirect(&path)
    }

    fn cookie_path(&self) -> &str {
        if self.root.is_empty() {
            "/"
        } else {
            &self.root
        }
    }
}

pub(super) fn router(
    accounts: Arc<Accounts>,
    settings: &BrowserSettings,
    catalog: Arc<GatewayService>,
) -> Router {
    let mut router = Router::new();
    for path in ["/admin", "/v1/admin"] {
        router = router
            .route(&format!("{path}/login"), get(login_page).post(login))
            .route(&format!("{path}/logout"), get(logout).post(logout))
            .route(
                &format!("{path}/forgot-password"),
                get(recovery::forgot_page).post(recovery::forgot),
            )
            .route(
                &format!("{path}/reset-password/{{token}}"),
                get(recovery::reset_page).post(recovery::reset),
            )
            .route(
                &format!("{path}/change-password-required"),
                get(password_page).post(change_password),
            )
            .route(&format!("{path}/"), get(home))
            .route(path, get(home))
            .route(&format!("{path}/tokens"), post(token::create))
            .route(&format!("{path}/tokens/partial"), get(token::partial))
            .route(&format!("{path}/tokens/search"), get(token::search))
            .route(
                &format!("{path}/tokens/{{id}}"),
                axum::routing::delete(token::revoke),
            )
            .route(&format!("{path}/tokens/{{id}}/revoke"), post(token::revoke))
            .route(&format!("{path}/tokens/{{id}}/usage"), get(token::usage));
        router = users::routes(router, path);
        for kind in ManagedCatalog::ALL {
            let base = format!("{path}/{}", kind.name());
            router = router
                .route(
                    &base,
                    get(catalog::list)
                        .post(catalog::editor::save)
                        .layer(Extension(kind)),
                )
                .route(
                    &format!("{base}/new"),
                    get(catalog::editor::page).layer(Extension(kind)),
                )
                .route(
                    &format!("{base}/{{id}}/edit"),
                    get(catalog::editor::page)
                        .post(catalog::editor::save)
                        .layer(Extension(kind)),
                );
            if matches!(kind, ManagedCatalog::Tools) {
                router = router.route(
                    &format!("{base}/{{id}}/edit/"),
                    post(catalog::editor::save).layer(Extension(kind)),
                );
            }
            if matches!(kind, ManagedCatalog::Gateways) {
                router = router
                    .route(
                        &format!("{base}/{{id}}"),
                        get(catalog::gateway_detail)
                            .put(catalog::editor::save)
                            .delete(catalog::delete_gateway)
                            .layer(Extension(kind)),
                    )
                    .route(
                        &format!("{base}/{{id}}/tools/refresh"),
                        post(catalog::mutate).layer(Extension((kind, catalog::Action::Refresh))),
                    );
            }
            for action in [catalog::Action::State, catalog::Action::Delete] {
                router = router.route(
                    &format!("{path}/{}/{{id}}/{}", kind.name(), action.path()),
                    post(catalog::mutate).layer(Extension((kind, action))),
                );
            }
        }
    }
    if settings.ui {
        router = router.route(
            "/",
            get(|State(accounts): State<Arc<Accounts>>| async move {
                settings_for(&accounts).redirect("/admin/")
            }),
        );
    }
    router.with_state(accounts).layer(Extension(catalog))
}

fn settings_for(accounts: &Accounts) -> &BrowserSettings {
    accounts
        .settings
        .browser
        .as_ref()
        .expect("admin routes are enabled")
}

async fn login_page(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Query(query): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let mut clear = false;
    if query.get("error").is_none_or(String::is_empty)
        && let Some(token) = auth_cookie(&headers)
    {
        match accounts
            .access
            .authenticate(token, Some(peer.ip()), None)
            .await
        {
            Ok(principal) => {
                if accounts
                    .access
                    .allows_admin_ui(&principal, RoleContext::Global)
                    .await?
                {
                    return Ok(settings.redirect("/admin"));
                }
            }
            Err(_) => clear = true,
        }
    }
    let proof = forms::nonce(&headers)?;
    let mut response = render(context! {
        title => "Sign In - ContextForge",
        page => "login",
        root => settings.root,
        proof => proof,
        email => query.get("email"),
        error => forms::login_error(query.get("error").map(String::as_str)),
        password_reset => accounts.settings.reset.enabled,
        notice => recovery::notice(query.get("notice").map(String::as_str)),
    })?;
    sessions::set_proof(
        &mut response,
        settings,
        accounts.settings.token_seconds,
        &proof,
    )?;
    if clear {
        sessions::clear_invalid_cookies(&mut response);
    }
    Ok(response)
}

async fn login(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let (parts, form) = Form::from_request(request).await?;
    csrf(settings, &parts, &form, true)?;
    let email = form.get("email");
    let password = form.get("password");
    if email.is_empty() || password.is_empty() {
        return Ok(settings.error(LOGIN, "missing_fields", Some(("email", email))));
    }
    let client = Client::new(Some(peer), &parts.headers);
    let using_default = password == accounts.settings.default_password.as_str();
    let user = match verify_local_password(
        &accounts,
        &email.trim().to_ascii_lowercase(),
        Zeroizing::new(password.to_owned()),
        &client,
    )
    .await
    {
        Ok(Some(user)) => user,
        _ => return Ok(settings.error(LOGIN, "invalid_credentials", Some(("email", email)))),
    };
    if settings.preserve_admin_auth && !user.is_admin {
        return Ok(settings.error(LOGIN, "sso_required", Some(("email", email))));
    }
    let change = requires_password_change(&accounts, &user, using_default).await?;
    let target = if change { CHANGE } else { "/admin" };
    create_session(&accounts, &user, settings.redirect(target), Some(email)).await
}

async fn home(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Extension(service): Extension<Arc<GatewayService>>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let Session { principal, token } =
        match access(&accounts, request.headers(), request.uri(), peer.ip()).await {
            Ok(session) => session,
            Err(denial) => return Ok(denial.response(settings, request.headers())),
        };
    if password_change_pending(&accounts, &principal).await? {
        return Ok(settings.redirect(CHANGE));
    }
    if let Some(team) = forms::query(request.uri()).get("team_id")
        && !team.is_empty()
        && Uuid::parse_str(team).is_err()
    {
        return Err(AccountError::bad_request("Invalid team ID"));
    }
    let team = sessions::request_team(request.uri(), &principal);
    if !accounts
        .access
        .allows(
            &principal,
            "admin.dashboard",
            sessions::role_context(team.as_deref()),
            false,
        )
        .await?
    {
        return Ok(Denial(
            StatusCode::FORBIDDEN,
            "Permission denied",
            Some("admin_required"),
        )
        .response(settings, request.headers()));
    }
    if !request.uri().path().ends_with('/') {
        let path = if request.uri().path().starts_with("/v1/") {
            "/v1/admin/"
        } else {
            "/admin/"
        };
        let query = request
            .uri()
            .query()
            .map_or_else(String::new, |query| format!("?{query}"));
        return Ok(Redirect::temporary(&format!("{}{path}{query}", settings.root)).into_response());
    }
    let proof = sessions::proof(&accounts, request.headers(), &principal, token)?;
    let (parts, _) = request.into_parts();
    let response = async {
        let catalog =
            match catalog::dashboard(&accounts, &service, &principal, &parts.uri, team.as_deref())
                .await
            {
                Ok(catalog) => catalog,
                Err(error) => return error.into_response(),
            };
        render(context! {
            title => "ContextForge",
            page => "home",
            root => settings.root,
            email => principal.email,
            proof => proof,
            catalog => catalog,
        })
        .and_then(|mut response| {
            sessions::set_proof(
                &mut response,
                settings,
                accounts.settings.token_seconds,
                &proof,
            )?;
            Ok(response)
        })
        .unwrap_or_else(IntoResponse::into_response)
    };
    Ok(catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await)
}

async fn password_change_pending(
    accounts: &Accounts,
    principal: &Principal,
) -> Result<bool, AccountError> {
    if accounts.settings.enforce_password_change
        && principal.token_use == TokenUse::Session
        && let Some(user) = accounts.database.local_user(&principal.email).await?
    {
        return requires_password_change(accounts, &user, false).await;
    }
    Ok(false)
}

async fn password_page(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let session = match access(&accounts, request.headers(), request.uri(), peer.ip()).await {
        Ok(session) => session,
        Err(denial) => return Ok(denial.response(settings, request.headers())),
    };
    let proof = forms::nonce(request.headers())?;
    let query = forms::query(request.uri());
    let minimum = if session.principal.is_admin() {
        accounts.settings.password_min_admin
    } else {
        accounts.settings.password_min_user
    };
    let mut response = render(context! {
        title => "Password Change Required - ContextForge",
        page => "password",
        root => settings.root,
        proof => proof,
        minimum => accounts.settings.password_policy.then_some(minimum),
        error => forms::password_error(query.get("error").map(String::as_str)),
        details => query.get("details"),
    })?;
    sessions::set_proof(
        &mut response,
        settings,
        accounts.settings.token_seconds,
        &proof,
    )?;
    Ok(response)
}

async fn change_password(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    if let Err(denial) = access(&accounts, request.headers(), request.uri(), peer.ip()).await {
        return Ok(denial.response(settings, request.headers()));
    }
    let (parts, form) = Form::from_request(request).await?;
    csrf(settings, &parts, &form, false)?;
    let old = form.get("current_password");
    let new = form.get("new_password");
    let confirm = form.get("confirm_password");
    if [old, new, confirm].iter().any(|item| item.is_empty()) {
        return Ok(settings.error(CHANGE, "missing_fields", None));
    }
    if new != confirm {
        return Ok(settings.error(CHANGE, "mismatch", None));
    }
    let Some(token) = cookie(&parts.headers, "jwt_token") else {
        return Ok(settings.error(LOGIN, "session_expired", None));
    };
    let Ok(principal) = accounts
        .access
        .authenticate(token, Some(peer.ip()), None)
        .await
    else {
        return Ok(settings.error(LOGIN, "session_expired", None));
    };
    if principal.token_use != TokenUse::Session {
        return Ok(settings.error(LOGIN, "session_expired", None));
    }
    let client = Client::new(Some(peer), &parts.headers);
    let user = match user_lifecycle::change_local_password(
        &accounts,
        &principal.email,
        Zeroizing::new(old.to_owned()),
        Zeroizing::new(new.to_owned()),
        &client,
    )
    .await
    {
        Ok(user) => user,
        Err(AccountError(StatusCode::UNAUTHORIZED, _)) => {
            return Ok(settings.error(CHANGE, "invalid_password", None));
        }
        Err(AccountError(StatusCode::BAD_REQUEST, body)) => {
            let text = body["detail"].as_str().unwrap_or_default();
            let limit = settings.password_error_limit;
            let mut details = text.to_owned();
            if text.chars().count() > limit {
                details = text.chars().take(limit.saturating_sub(3)).collect();
                details.push_str("...");
            }
            return Ok(settings.error(CHANGE, "weak_password", Some(("details", &details))));
        }
        Err(_) => return Ok(settings.error(CHANGE, "server_error", None)),
    };
    create_session(&accounts, &user, settings.redirect("/admin"), None).await
}

async fn logout(
    State(accounts): State<Arc<Accounts>>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let (parts, form) = Form::from_request(request).await?;
    csrf(settings, &parts, &form, false)?;
    let token = cookie(&parts.headers, "jwt_token");
    if let Some(token) = token {
        sessions::revoke(&accounts, token).await?;
    }
    let mut response = match parts.method {
        Method::GET if !browser_request(&parts.headers) => "Logged out".into_response(),
        Method::POST => settings
            .keycloak
            .as_ref()
            .zip(token)
            .and_then(|(keycloak, token)| {
                keycloak.redirect(&accounts.access, token, &parts, &settings.root)
            })
            .unwrap_or_else(|| settings.redirect(LOGIN)),
        _ => settings.redirect(LOGIN),
    };
    clear_session_cookies(&accounts.settings, settings, &mut response)?;
    Ok(response)
}
