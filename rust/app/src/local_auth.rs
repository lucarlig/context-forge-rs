// SPDX-License-Identifier: Apache-2.0

pub(crate) mod browser;
pub(crate) mod mail;
mod password_reset;
mod passwords;
mod rbac;
mod sso;
mod storage;
mod teams;
mod user_lifecycle;

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    access::{Authorizer, Principal, RoleContext},
    config::SecretKdf,
    database::Database,
    http_boundary::csrf::CsrfTokens,
    jwt::JwtIssuer,
};

pub(crate) use password_reset::ResetSettings;
pub use sso::ExternalIdentitySettings;
pub(crate) use sso::{
    SsoIdentityPolicy, SsoSettings, is_id_token, unverified_jwt_claims, verify_oidc_jwt,
};
pub(crate) use storage::{POSTGRES_MIGRATION, SQLITE_MIGRATION};
pub(crate) use teams::TeamSettings;

pub struct AccountSettings {
    pub(crate) bootstrap_email: String,
    pub(crate) bootstrap_name: String,
    pub(crate) bootstrap_password: Option<Zeroizing<String>>,
    pub(crate) bootstrap_require_change: bool,
    pub(crate) default_password: Zeroizing<String>,
    pub(crate) public_registration: bool,
    pub(crate) provisioning: UserProvisioning,
    pub(crate) teams: TeamSettings,
    pub(crate) enforce_password_change: bool,
    pub(crate) detect_default_password: bool,
    pub(crate) require_change_for_default: bool,
    pub(crate) password_max_age_days: i64,
    pub(crate) password_min_user: usize,
    pub(crate) password_min_admin: usize,
    pub(crate) password_policy: bool,
    pub(crate) password_history: u32,
    pub(crate) invalidate_sessions: bool,
    pub(crate) reset: ResetSettings,
    pub(crate) mailer: Option<mail::Mailer>,
    pub(crate) protect_admins: bool,
    pub(crate) lockout_attempts: i32,
    pub(crate) lockout_seconds: i64,
    pub(crate) failure_floor: Duration,
    pub(crate) token_seconds: i64,
    pub(crate) csrf: CsrfTokens,
    pub(crate) csrf_samesite: String,
    pub(crate) csrf_secure: bool,
    pub(crate) csrf_httponly: bool,
    pub(crate) browser: Option<browser::BrowserSettings>,
    pub(crate) a2a_enabled: bool,
    pub(crate) page_size: u32,
    pub(crate) max_page_size: u32,
    pub(crate) kdf: SecretKdf,
    pub(crate) sso: Option<SsoSettings>,
}

pub(crate) struct UserProvisioning {
    pub(crate) personal_teams: bool,
    pub(crate) personal_team_prefix: String,
    pub(crate) admin_role: String,
    pub(crate) user_role: String,
    pub(crate) owner_role: String,
}

struct Accounts {
    database: Database,
    access: Arc<Authorizer>,
    signer: JwtIssuer,
    settings: AccountSettings,
    dummy_hash: String,
}

#[derive(Debug)]
struct AccountError(StatusCode, Value);

impl AccountError {
    fn detail(status: StatusCode, message: impl Into<String>) -> Self {
        Self(status, json!({"detail":message.into()}))
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::detail(StatusCode::BAD_REQUEST, message)
    }

    fn unavailable() -> Self {
        Self::detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication service unavailable",
        )
    }

    fn missing() -> Self {
        Self::detail(StatusCode::NOT_FOUND, "User not found")
    }
}

impl From<sqlx::Error> for AccountError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "local account storage failed");
        Self::unavailable()
    }
}

impl IntoResponse for AccountError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

pub async fn router(
    database: Database,
    access: Arc<Authorizer>,
    signer: JwtIssuer,
    mut settings: AccountSettings,
) -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    let bootstrap = settings.bootstrap_password.take();
    let dummy_hash = passwords::hash(Zeroizing::new(Uuid::new_v4().to_string()), settings.kdf)
        .await
        .map_err(|_| "could not initialize local password verification")?;
    let state = Arc::new(Accounts {
        database,
        access,
        signer,
        settings,
        dummy_hash,
    });
    let bootstrap_email = state.settings.bootstrap_email.trim().to_ascii_lowercase();
    if let Some(password) = bootstrap {
        if !valid_email(&bootstrap_email) {
            return Err("invalid PLATFORM_ADMIN_EMAIL".into());
        }
        if state.database.local_user(&bootstrap_email).await?.is_none() {
            let password_change_required = state.settings.enforce_password_change
                && state.settings.bootstrap_require_change
                && *password == *state.settings.default_password;
            let password_hash = passwords::hash(password, state.settings.kdf)
                .await
                .map_err(|_| "could not hash the platform administrator password")?;
            let user = storage::NewUser {
                email: bootstrap_email.clone(),
                full_name: Some(state.settings.bootstrap_name.clone()),
                is_admin: true,
                is_active: true,
                password_hash: Some(password_hash),
                auth_provider: "local".to_owned(),
                approval_required: false,
                email_verified: true,
                password_change_required,
                granted_by: Some(bootstrap_email),
                admin_origin: Some("bootstrap"),
            };
            state
                .database
                .create_local_user(&user, &state.settings.provisioning)
                .await?;
        }
    }
    let mut public = Router::new();
    let mut protected = Router::new();
    for base in ["/auth/email", "/v1/auth/email"] {
        public = public
            .route(&format!("{base}/login"), post(login))
            .route(&format!("{base}/register"), post(register))
            .route(
                &format!("{base}/forgot-password"),
                post(password_reset::forgot),
            )
            .route(
                &format!("{base}/reset-password/{{token}}"),
                get(password_reset::validate).post(password_reset::complete),
            );
        protected = protected
            .route(&format!("{base}/me"), get(profile))
            .route(
                &format!("{base}/change-password"),
                post(user_lifecycle::change_password),
            )
            .route(&format!("{base}/events"), get(events))
            .route(&format!("{base}/admin/events"), get(admin_events))
            .route(
                &format!("{base}/admin/users"),
                get(list_users).post(create_user),
            )
            .route(
                &format!("{base}/admin/users/{{email}}"),
                get(get_user)
                    .patch(user_lifecycle::edit_user)
                    .delete(user_lifecycle::delete_user),
            )
            .route(
                &format!("{base}/admin/users/{{email}}/unlock"),
                post(user_lifecycle::unlock_user),
            );
    }
    let protected = protected.merge(rbac::router()).merge(teams::router());
    let mut router = public
        .with_state(state.clone())
        .merge(state.access.protect_api_with_message(
            protected.with_state(state.clone()),
            "Authentication required",
        ));
    if let Some(settings) = state.settings.browser.as_ref() {
        router = router.merge(browser::router(state.clone(), settings));
    }
    if let Some(settings) = state.settings.sso.as_ref() {
        sso::bootstrap(&state.database, settings).await;
        let (sso_public, sso_admin) = sso::routers(settings);
        router = router.merge(sso_public.with_state(state.clone())).merge(
            state.access.protect_api_with_message(
                sso_admin.with_state(state.clone()),
                "Authorization token required",
            ),
        );
    }
    Ok(router)
}

#[derive(Deserialize)]
struct Login {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct ManagedUser {
    email: String,
    password: String,
    full_name: Option<String>,
    #[serde(default)]
    is_admin: bool,
    is_active: Option<bool>,
    #[serde(default)]
    password_change_required: bool,
}

#[derive(Deserialize)]
struct Registration {
    email: String,
    password: String,
    full_name: Option<String>,
}

#[derive(Default, Deserialize)]
struct UserQuery {
    cursor: Option<String>,
    limit: Option<u32>,
    #[serde(default)]
    include_pagination: bool,
}

#[derive(Deserialize, Serialize)]
struct UserCursor {
    created_at: String,
    email: String,
}

#[derive(Deserialize)]
struct EventQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    user_email: Option<String>,
}

#[derive(Clone)]
struct Client {
    address: Option<String>,
    user_agent: Option<String>,
}

impl Client {
    fn new(address: Option<SocketAddr>, headers: &HeaderMap) -> Self {
        Self {
            address: address.map(|peer| peer.ip().to_string()),
            user_agent: headers
                .get(header::USER_AGENT)
                .and_then(|agent| agent.to_str().ok())
                .map(str::to_owned),
        }
    }
}

async fn login(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> Result<Response, AccountError> {
    let email = input.email.trim().to_ascii_lowercase();
    let password = Zeroizing::new(input.password);
    if !valid_email(&email) {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid email format",
        ));
    }
    let client = Client::new(Some(peer), &headers);
    let using_default = *password == *accounts.settings.default_password;
    let Some(user) = verify_local_password(&accounts, &email, password, &client).await? else {
        return Err(AccountError::detail(
            StatusCode::UNAUTHORIZED,
            "Invalid email or password",
        ));
    };
    if requires_password_change(&accounts, &user, using_default).await? {
        let flagged = user.password_change_required;
        let mut hint =
            "Use the Admin UI at /admin/change-password-required to set a new password.".to_owned();
        if flagged {
            hint.push_str(" If this is a headless deployment locked out at bootstrap, set ADMIN_REQUIRE_PASSWORD_CHANGE_ON_BOOTSTRAP=false and restart.");
        }
        return Ok((
                StatusCode::FORBIDDEN,
                [("x-password-change-required", "true")],
                Json(json!({"detail":"Password change required. Please change your password before continuing.", "hint":hint})),
            ).into_response());
    }
    session_response(&accounts, &user, true).await
}

async fn requires_password_change(
    accounts: &Accounts,
    user: &storage::LocalUser,
    using_default: bool,
) -> Result<bool, AccountError> {
    let settings = &accounts.settings;
    if !settings.enforce_password_change {
        return Ok(false);
    }
    let expired = user
        .password_changed_at
        .as_deref()
        .and_then(parse_timestamp)
        .map(|changed| (Timestamp::now().as_second() - changed.as_second()) / 86_400)
        .is_some_and(|age| age >= settings.password_max_age_days);
    let is_default =
        settings.detect_default_password && settings.require_change_for_default && using_default;
    if is_default && !user.password_change_required && !expired {
        accounts
            .database
            .require_local_password_change(&user.email)
            .await?;
    }
    Ok(user.password_change_required || expired || is_default)
}

async fn verify_local_password(
    accounts: &Arc<Accounts>,
    email: &str,
    password: Zeroizing<String>,
    client: &Client,
) -> Result<Option<storage::LocalUser>, AccountError> {
    let commenced = Instant::now();
    let now = Timestamp::now();
    let initial = accounts.database.local_user(email).await?;
    let mut failure = match initial.as_ref() {
        None => Some("User not found"),
        Some(user) if !user.is_active => Some("Account is disabled"),
        Some(user) if user.locked(now) && !(user.is_admin && accounts.settings.protect_admins) => {
            Some("Account is locked")
        }
        Some(user) if user.password_hash.is_none() => {
            Some("Local password authentication disabled")
        }
        Some(_) => None,
    };
    let hash = initial
        .as_ref()
        .filter(|_| failure.is_none())
        .and_then(|user| user.password_hash.clone())
        .unwrap_or_else(|| accounts.dummy_hash.clone());
    let verified = passwords::verify(password, hash).await?;
    let Some(user) = initial.as_ref().filter(|_| failure.is_none() && verified) else {
        if let Some(user) = initial.as_ref().filter(|_| failure.is_none()) {
            let lockout = accounts
                .database
                .record_login_failure(user, &accounts.settings)
                .await?;
            failure = Some(if lockout {
                "Account locked due to too many failed attempts"
            } else {
                "Invalid password"
            });
            if lockout {
                accounts
                    .database
                    .local_event(email, "ACCOUNT_LOCKED", true, client, None)
                    .await?;
                password_reset::notify_lockout(accounts, email.to_owned(), user.full_name.clone());
            }
        }
        accounts
            .database
            .local_event(email, "login", false, client, failure)
            .await?;
        tokio::time::sleep(
            accounts
                .settings
                .failure_floor
                .saturating_sub(commenced.elapsed()),
        )
        .await;
        return Ok(None);
    };
    let Some(user) = accounts.database.record_successful_login(user).await? else {
        return Ok(None);
    };
    accounts
        .database
        .local_event(email, "login", true, client, None)
        .await?;
    Ok(Some(user))
}

async fn register(
    State(accounts): State<Arc<Accounts>>,
    Json(value): Json<Value>,
) -> Result<Response, AccountError> {
    if let Some(extra) = value.as_object().and_then(|object| {
        object
            .keys()
            .find(|key| !matches!(key.as_str(), "email" | "password" | "full_name"))
    }) {
        return Err(AccountError(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"detail":[{"loc":["body", extra], "msg":"Extra inputs are not permitted", "type":"extra_forbidden"}]}),
        ));
    }
    let input: Registration = serde_json::from_value(value).map_err(|_| {
        AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid registration request",
        )
    })?;
    if !accounts.settings.public_registration {
        return Err(AccountError::detail(
            StatusCode::FORBIDDEN,
            "Public registration is disabled. Please contact an administrator to create an account.",
        ));
    }
    let user = create_account(
        &accounts,
        ManagedUser {
            email: input.email,
            password: input.password,
            full_name: input.full_name,
            is_admin: false,
            is_active: Some(true),
            password_change_required: false,
        },
        None,
    )
    .await?;
    session_response(&accounts, &user, false).await
}

async fn create_user(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Json(input): Json<ManagedUser>,
) -> Result<(StatusCode, Json<Value>), AccountError> {
    require_user_admin(&accounts, &principal).await?;
    if input.is_admin && !principal.is_global_admin() {
        return Err(AccountError::detail(
            StatusCode::FORBIDDEN,
            "Administrator creation requires a platform administrator",
        ));
    }
    let user = create_account(&accounts, input, Some(&principal.email)).await?;
    Ok((StatusCode::CREATED, Json(user.metadata())))
}

async fn create_account(
    accounts: &Accounts,
    input: ManagedUser,
    actor: Option<&str>,
) -> Result<storage::LocalUser, AccountError> {
    let email = input.email.trim().to_ascii_lowercase();
    if !valid_email(&email) {
        return Err(AccountError::bad_request("Invalid email format"));
    }
    if input
        .full_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > 255)
    {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Full name is too long",
        ));
    }
    if accounts.database.local_user(&email).await?.is_some() {
        return Err(duplicate_user(&email));
    }
    let password = Zeroizing::new(input.password);
    passwords::validate(&accounts.settings, &password, &email, input.is_admin)?;
    let require_change = input.password_change_required
        || (actor.is_some()
            && accounts.settings.enforce_password_change
            && accounts.settings.require_change_for_default
            && *password == *accounts.settings.default_password);
    let hash = passwords::hash(password, accounts.settings.kdf).await?;
    let new = storage::NewUser {
        email: email.clone(),
        full_name: input.full_name,
        is_admin: input.is_admin,
        is_active: input.is_active.unwrap_or(true),
        password_hash: Some(hash),
        auth_provider: "local".to_owned(),
        approval_required: false,
        email_verified: actor.is_some(),
        password_change_required: require_change,
        granted_by: actor.map(str::to_owned),
        admin_origin: input.is_admin.then_some("api"),
    };
    if !accounts
        .database
        .create_local_user(&new, &accounts.settings.provisioning)
        .await?
    {
        return Err(duplicate_user(&email));
    }
    accounts
        .database
        .local_user(&email)
        .await?
        .ok_or_else(AccountError::unavailable)
}

async fn profile(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, AccountError> {
    let user = accounts
        .database
        .local_user(&principal.email)
        .await?
        .ok_or_else(AccountError::missing)?;
    let mut data = user.metadata();
    data["features"] = json!({"a2a": accounts.settings.a2a_enabled});
    Ok(Json(data))
}

async fn get_user(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(email): Path<String>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let user = accounts
        .database
        .local_user(&email.trim().to_ascii_lowercase())
        .await?
        .ok_or_else(AccountError::missing)?;
    Ok(Json(user.metadata()))
}

async fn list_users(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<UserQuery>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let limit = query.limit.unwrap_or(accounts.settings.page_size);
    if limit > accounts.settings.max_page_size {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid user pagination limit",
        ));
    }
    let cursor = query
        .cursor
        .as_ref()
        .and_then(|cursor| URL_SAFE.decode(cursor).ok())
        .and_then(|json| serde_json::from_slice::<UserCursor>(&json).ok())
        .filter(|cursor| {
            parse_timestamp(&cursor.created_at).is_some() && valid_email(&cursor.email)
        });
    let fetch = if limit == 0 { -1 } else { i64::from(limit) + 1 };
    let mut users = accounts
        .database
        .local_users(cursor.as_ref(), fetch)
        .await?;
    let next = if limit != 0 && users.len() > limit as usize {
        users.truncate(limit as usize);
        users.last().and_then(|user| {
            serde_json::to_vec(&UserCursor {
                created_at: user.created_at.replacen(' ', "T", 1),
                email: user.email.clone(),
            })
            .ok()
            .map(|json| URL_SAFE.encode(json))
        })
    } else {
        None
    };
    let users = users
        .iter()
        .map(storage::LocalUser::metadata)
        .collect::<Vec<_>>();
    Ok(Json(if query.include_pagination {
        json!({"users":users,"nextCursor":next})
    } else {
        json!(users)
    }))
}

async fn events(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Value>, AccountError> {
    list_events(
        &accounts,
        Some(&principal.email),
        query.limit.unwrap_or(50),
        query.offset.unwrap_or(0),
    )
    .await
}

async fn admin_events(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    list_events(
        &accounts,
        query.user_email.as_deref(),
        query.limit.unwrap_or(100),
        query.offset.unwrap_or(0),
    )
    .await
}

async fn list_events(
    accounts: &Accounts,
    email: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Json<Value>, AccountError> {
    if limit < 0 || offset < 0 {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid event pagination",
        ));
    }
    let rows = accounts.database.local_events(email, limit, offset).await?;
    Ok(Json(json!(rows)))
}

async fn require_user_admin(
    accounts: &Accounts,
    principal: &Principal,
) -> Result<(), AccountError> {
    if !accounts
        .access
        .allows(
            principal,
            "admin.user_management",
            RoleContext::Global,
            principal.is_global_admin(),
        )
        .await?
    {
        return Err(AccountError::detail(StatusCode::FORBIDDEN, "Access denied"));
    }
    Ok(())
}

fn duplicate_user(email: &str) -> AccountError {
    AccountError::detail(
        StatusCode::CONFLICT,
        format!("User with email {email} already exists"),
    )
}

async fn session_response(
    accounts: &Accounts,
    user: &storage::LocalUser,
    set_csrf: bool,
) -> Result<Response, AccountError> {
    let (token, jti, now) = issue_local_session(accounts, user).await?;
    let mut response = Json(json!({
        "access_token":token.as_str(),
        "token_type":"bearer",
        "expires_in":accounts.settings.token_seconds,
        "user":user.metadata(),
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if set_csrf && let Some(cookie) = csrf_cookie(&accounts.settings, &user.email, &jti, now) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    Ok(response)
}

async fn issue_local_session(
    accounts: &Accounts,
    user: &storage::LocalUser,
) -> Result<(Zeroizing<String>, String, i64), AccountError> {
    let now = Timestamp::now().as_second();
    let jti = Uuid::new_v4().to_string();
    let expires = now + accounts.settings.token_seconds;
    let permissions = if user.auth_provider == "local" || user.is_admin {
        &["*"][..]
    } else {
        &[][..]
    };
    let claims = json!({
        "sub":user.id, "jti":jti, "iat":now, "exp":expires, "last_activity":now,
        "token_use":"session", "auth_provider":user.auth_provider,
        "scopes":{"server_id":null,"permissions":permissions,"ip_restrictions":[],"time_restrictions":{}},
    });
    let token = Zeroizing::new(
        accounts
            .signer
            .sign(claims)
            .map_err(|_| AccountError::unavailable())?,
    );
    if !accounts
        .database
        .remember_local_session(user, &jti, expires)
        .await?
    {
        return Err(AccountError::detail(
            StatusCode::UNAUTHORIZED,
            "Invalid authentication credentials",
        ));
    }
    Ok((token, jti, now))
}

fn csrf_cookie(
    settings: &AccountSettings,
    email: &str,
    session: &str,
    now: i64,
) -> Option<HeaderValue> {
    use std::fmt::Write as _;
    let token = settings.csrf.issue(email, session, now)?;
    let mut cookie = format!("{}={token}", settings.csrf.cookie_name);
    let same_site = match settings.csrf_samesite.to_ascii_lowercase().as_str() {
        "none" => "None",
        "lax" => "Lax",
        _ => "Strict",
    };
    write!(
        cookie,
        "; Max-Age={}; Path=/; SameSite={same_site}",
        settings.csrf.seconds
    )
    .ok()?;
    if settings.csrf_secure {
        cookie.push_str("; Secure");
    }
    if settings.csrf_httponly {
        cookie.push_str("; HttpOnly");
    }
    HeaderValue::from_str(&cookie).ok()
}

fn parse_timestamp(value: &str) -> Option<Timestamp> {
    let iso = value.replacen(' ', "T", 1);
    iso.parse().or_else(|_| format!("{iso}Z").parse()).ok()
}

fn valid_email(email: &str) -> bool {
    use std::sync::LazyLock;
    static PATTERN: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("valid email pattern")
    });
    email.len() <= 255 && PATTERN.is_match(email)
}
