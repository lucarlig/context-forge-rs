// SPDX-License-Identifier: Apache-2.0

use axum::http::{Uri, request::Parts};

use super::{catalog::AuthorizedForm, *};
use crate::gateway::{CatalogApiError, PaginationMeta};
use user_lifecycle::UserPatch;

const MANAGE: &str = "admin.user_management";

pub(super) fn routes(router: Router<Arc<Accounts>>, base: &str) -> Router<Arc<Accounts>> {
    use axum::routing::delete;
    let root = format!("{base}/users");
    let item = format!("{root}/{{email}}");
    let mut router = router
        .route(&root, get(list).post(create))
        .route(&format!("{root}/search"), get(search))
        .route(&format!("{root}/partial"), get(partial))
        .route(&format!("{item}/edit"), get(edit))
        .route(&item, delete(mutate).layer(Extension(Action::Delete)));
    for (name, action) in [
        ("activate", Action::Activate),
        ("deactivate", Action::Deactivate),
        ("update", Action::Update),
        ("unlock", Action::Unlock),
        ("force-password-change", Action::RequirePasswordChange),
        ("delete", Action::Delete),
    ] {
        router = router.route(
            &format!("{item}/{name}"),
            post(mutate).layer(Extension(action)),
        );
    }
    router
}

pub(super) async fn visible(
    accounts: &Accounts,
    principal: &Principal,
) -> Result<bool, sqlx::Error> {
    accounts
        .access
        .allows(principal, MANAGE, RoleContext::Global, false)
        .await
}

#[derive(Deserialize)]
struct DirectoryQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    format: Option<String>,
    render: Option<String>,
    q: Option<String>,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
    limit: Option<i64>,
}

fn query<T: serde::de::DeserializeOwned>(uri: &Uri) -> Result<T, CatalogApiError> {
    Query::try_from_uri(uri)
        .map(|Query(query)| query)
        .map_err(|_| {
            CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, "Invalid user query")
        })
}

fn normalize_search(value: Option<&str>) -> Result<String, CatalogApiError> {
    let search = value.unwrap_or_default();
    if search.chars().count() > 500 {
        return Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "User search must be at most 500 characters",
        ));
    }
    Ok(search.trim().to_lowercase())
}

fn match_prefix(search: &str) -> Option<String> {
    if search.is_empty() {
        return None;
    }
    let mut pattern = String::with_capacity(search.len() + 1);
    for character in search.chars() {
        if matches!(character, '\\' | '%' | '_') {
            pattern.push('\\');
        }
        pattern.push(character);
    }
    pattern.push('%');
    Some(pattern)
}

fn summary(user: &storage::LocalUser) -> Value {
    json!({"email": user.email, "full_name": user.full_name,
           "is_active": user.is_active, "is_admin": user.is_admin})
}

#[derive(Serialize)]
struct Row {
    user: Value,
    path: String,
    has_password: bool,
    can_change_state: bool,
    can_delete: bool,
}

fn row(user: &storage::LocalUser, principal: &Principal, active_admins: i64) -> Row {
    let own = user.email == principal.email;
    let last_admin = user.is_admin && user.is_active && active_admins <= 1;
    let protected = last_admin || (user.is_admin && own);
    let email = utf8_percent_encode(&user.email, percent_encoding::NON_ALPHANUMERIC);
    Row {
        user: user.metadata(),
        path: format!("/admin/users/{email}"),
        has_password: user.password_hash.is_some(),
        can_change_state: !protected,
        can_delete: !own && !last_admin,
    }
}

#[derive(Serialize)]
pub(super) struct Panel {
    rows: Vec<Row>,
    query: String,
    pagination: PaginationMeta,
    previous: Option<String>,
    next: Option<String>,
    can_promote: bool,
}

async fn directory(
    accounts: &Accounts,
    service: &GatewayService,
    page: i64,
    size: i64,
    search: &str,
) -> Result<(Vec<storage::LocalUser>, PaginationMeta, i64), CatalogApiError> {
    let prefix = match_prefix(search);
    let (total, admins) = accounts
        .database
        .user_directory_counts(prefix.as_deref())
        .await?;
    let pagination = PaginationMeta::new(page, size, total);
    let users = accounts
        .database
        .user_directory(
            prefix.as_deref(),
            size,
            service.admin_page_offset(&pagination),
        )
        .await?;
    Ok((users, pagination, admins))
}

pub(super) async fn panel(
    accounts: &Accounts,
    service: &GatewayService,
    principal: &Principal,
    uri: &Uri,
) -> Result<Panel, CatalogApiError> {
    let query: DirectoryQuery = query(uri)?;
    let search = normalize_search(query.q.as_deref())?;
    let (page, size) = service.admin_page_params(query.page, query.per_page)?;
    let (users, pagination, admins) = directory(accounts, service, page, size, &search).await?;
    let page_link = |page: i64| {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("section", "users");
        if !search.is_empty() {
            params.append_pair("q", &search);
        }
        params
            .append_pair("page", &page.to_string())
            .append_pair("per_page", &size.to_string());
        format!(
            "{}/admin/?{}#users",
            settings_for(accounts).root,
            params.finish()
        )
    };
    Ok(Panel {
        rows: users
            .iter()
            .map(|user| row(user, principal, admins))
            .collect(),
        previous: pagination.has_prev.then(|| page_link(pagination.page - 1)),
        next: pagination.has_next.then(|| page_link(pagination.page + 1)),
        pagination,
        query: search,
        can_promote: principal.is_global_admin(),
    })
}

async fn authorize_read(
    accounts: &Accounts,
    request: Request,
    peer: SocketAddr,
    search: bool,
) -> Result<(Principal, Parts, String), Box<Response>> {
    let settings = settings_for(accounts);
    let Session { principal, token } =
        access(accounts, request.headers(), request.uri(), peer.ip())
            .await
            .map_err(|denial| Box::new(denial.response(settings, request.headers())))?;
    if password_change_pending(accounts, &principal)
        .await
        .map_err(|error| Box::new(error.into_response()))?
    {
        return Err(Box::new(settings.redirect(CHANGE)));
    }
    if sessions::bearer_token(settings, request.headers()).is_none()
        && !browser_request(request.headers())
    {
        return Err(Box::new(
            Denial(
                StatusCode::UNAUTHORIZED,
                "Cookie authentication not allowed for API requests. Use Authorization header.",
                None,
            )
            .response(settings, request.headers()),
        ));
    }
    let may_manage = visible(accounts, &principal).await;
    let permission = match may_manage {
        Ok(false) if search => {
            accounts
                .access
                .allows(
                    &principal,
                    "teams.manage_members",
                    RoleContext::AnyTeam,
                    false,
                )
                .await
        }
        other => other,
    };
    if !permission.map_err(|error| Box::new(AccountError::from(error).into_response()))? {
        return Err(Box::new(
            Denial(StatusCode::FORBIDDEN, "Permission denied", None)
                .response(settings, request.headers()),
        ));
    }
    let proof = sessions::proof(accounts, request.headers(), &principal, token)
        .map_err(|error| Box::new(error.into_response()))?;
    let (parts, _) = request.into_parts();
    Ok((principal, parts, proof))
}

pub(super) async fn list(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let (principal, parts, _) = match authorize_read(&accounts, request, peer, false).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let query: DirectoryQuery = query(&parts.uri)?;
        let (page, size) = service.admin_page_params(query.page, query.per_page)?;
        let dropdown = query.format.as_deref() == Some("json")
            || forms::header_text(&parts.headers, header::ACCEPT)
                .is_some_and(|accept| accept.contains("application/json"));
        if dropdown {
            let (_, size) = service.admin_page_params(
                None,
                Some(100_i64.min(i64::from(accounts.settings.max_page_size))),
            )?;
            let users = accounts.database.user_directory(None, size, 0).await?;
            return Ok::<_, CatalogApiError>(Json(json!({
                "users": users.iter().map(summary).collect::<Vec<_>>(),
            })));
        }
        let (users, pagination, _) = directory(&accounts, &service, page, size, "").await?;
        let links = service.admin_page_links(&pagination, "/admin/users", false, None);
        Ok(Json(json!({
            "data": users.iter().map(summary).collect::<Vec<_>>(),
            "pagination": pagination,
            "links": links,
        })))
    };
    let response = async { response.await.into_response() };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

pub(super) async fn search(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let (principal, parts, _) = match authorize_read(&accounts, request, peer, true).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let SearchQuery { q, limit } = query(&parts.uri)?;
        let search = normalize_search(q.as_deref())?;
        let limit = limit.unwrap_or(i64::from(accounts.settings.page_size));
        if !(1..=i64::from(accounts.settings.max_page_size)).contains(&limit) {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid user search limit",
            ));
        }
        let items = if let Some(prefix) = match_prefix(&search) {
            accounts
                .database
                .user_directory(Some(&prefix), limit, 0)
                .await?
        } else {
            Vec::new()
        }
        .iter()
        .map(|user| {
            let full_name = user.full_name.as_deref().unwrap_or_default();
            let name = user
                .full_name
                .as_deref()
                .filter(|name| !name.is_empty())
                .unwrap_or(&user.email);
            json!({"id": user.email, "name": name, "email": user.email,
                   "full_name": full_name, "is_admin": user.is_admin, "is_active": user.is_active})
        })
        .collect::<Vec<_>>();
        Ok(Json(json!({
            "users": items, "items": items, "count": items.len(),
            "entity_type": "users", "query": search,
            "filters_applied": {"q": search, "tags": "", "tag_groups": []},
        })))
    };
    let response = async { response.await.into_response() };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

pub(super) async fn partial(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorize_read(&accounts, request, peer, false).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let query: DirectoryQuery = match query(&parts.uri) {
            Ok(query) => query,
            Err(error) => return error.into_response(),
        };
        let controls = match query.render.as_deref() {
            Some("controls") => true,
            None | Some("") => false,
            Some(_) => {
                return AccountError::detail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid render mode",
                )
                .into_response();
            }
        };
        let users = match panel(&accounts, &service, &principal, &parts.uri).await {
            Ok(users) => users,
            Err(error) => return error.into_response(),
        };
        let settings = settings_for(&accounts);
        forms::render_template(
            "users.html",
            context! {
                users, controls, proof, root => &settings.root,
            },
        )
        .and_then(|mut response| {
            sessions::set_proof(
                &mut response,
                settings,
                accounts.settings.token_seconds,
                &proof,
            )?;
            Ok(response)
        })
        .into_response()
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

pub(super) async fn edit(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(email): Path<String>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorize_read(&accounts, request, peer, false).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let email = email.trim().to_ascii_lowercase();
    let response = async {
        let user = accounts
            .database
            .local_user(&email)
            .await?
            .ok_or_else(AccountError::missing)?;
        let user = row(&user, &principal, 0);
        let settings = settings_for(&accounts);
        let mut response = render(context! {
            page => "user-edit", title => "Edit user", user, proof,
            can_promote => principal.is_global_admin(),
            root => &settings.root,
            from_directory => forms::query(&parts.uri).contains_key("directory"),
        })?;
        sessions::set_proof(
            &mut response,
            settings,
            accounts.settings.token_seconds,
            &proof,
        )?;
        Ok::<_, AccountError>(response)
    };
    let response = async { response.await.into_response() };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

#[derive(Clone, Copy)]
pub(super) enum Action {
    Activate,
    Deactivate,
    Update,
    Unlock,
    RequirePasswordChange,
    Delete,
}

pub(super) async fn create(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, MANAGE, request, peer.ip(), false).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let is_admin = form.get("is_admin") == "on";
        let result = if is_admin && !principal.is_global_admin() {
            Err(AccountError::detail(
                StatusCode::FORBIDDEN,
                "Administrator creation requires a platform administrator",
            ))
        } else {
            create_account(
                &accounts,
                ManagedUser {
                    email: form.get("email").to_owned(),
                    password: form.get("password").to_owned(),
                    full_name: Some(form.get("full_name").to_owned()),
                    is_admin,
                    is_active: None,
                    password_change_required: false,
                },
                Some(&principal.email),
            )
            .await
        };
        match result {
            Ok(_) if forms::query(&parts.uri).contains_key("directory") => {
                settings_for(&accounts).redirect("/admin/?section=users#users")
            }
            Ok(_) => (
                StatusCode::CREATED,
                [("HX-Trigger", "userCreated")],
                Html("<p>User created successfully!</p>"),
            )
                .into_response(),
            Err(error) => action_error(&accounts, error, None),
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

pub(super) async fn mutate(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Extension(action): Extension<Action>,
    Path(email): Path<String>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, MANAGE, request, peer.ip(), false).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let email = email.trim().to_ascii_lowercase();
    let response = async {
        let result = apply_action(&accounts, &principal, &email, action, &form).await;
        let user = match result {
            Ok(user) => user,
            Err(error) => return action_error(&accounts, error, Some(action)),
        };
        let settings = settings_for(&accounts);
        if forms::query(&parts.uri).contains_key("directory") {
            return settings.redirect("/admin/?section=users#users");
        }
        match action {
            Action::Delete => Html("").into_response(),
            Action::Update => (
                [("HX-Trigger", r#"{"adminUserAction":{"closeUserEditModal":true,"refreshUsersList":true,"delayMs":1500}}"#)],
                Html("<p>User updated successfully</p>"),
            ).into_response(),
            _ => {
                let row = row(&user.expect("account action returns the updated account"), &principal, 0);
                forms::render_template("users.html", context! { row, root => &settings.root })
                    .into_response()
            }
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

async fn apply_action(
    accounts: &Accounts,
    principal: &Principal,
    email: &str,
    action: Action,
    form: &Form,
) -> Result<Option<storage::LocalUser>, AccountError> {
    if matches!(action, Action::Delete) {
        user_lifecycle::remove_account(accounts, principal, email).await?;
        return Ok(None);
    }
    if matches!(action, Action::Unlock) {
        if !accounts.database.unlock_local_user(email).await? {
            return Err(AccountError::missing());
        }
        return accounts
            .database
            .local_user(email)
            .await?
            .map(Some)
            .ok_or_else(AccountError::missing);
    }
    let mut patch = UserPatch {
        admin_origin: Some("ui"),
        ..UserPatch::default()
    };
    match action {
        Action::Activate => patch.is_active = Some(true),
        Action::Deactivate => patch.is_active = Some(false),
        Action::RequirePasswordChange => patch.password_change_required = Some(true),
        Action::Update => {
            let password = form.get("password");
            if !password.is_empty() && password != form.get("confirm_password") {
                return Err(AccountError::bad_request("Passwords do not match"));
            }
            patch.full_name = form.value("full_name").map(str::to_owned);
            // Administrators with limited scope can edit other fields without changing roles.
            if principal.is_global_admin() || form.get("is_admin") == "on" {
                patch.is_admin = Some(form.get("is_admin") == "on");
            }
            patch.email_verified = Some(form.get("email_verified") == "on");
            patch.password = (!password.trim().is_empty()).then(|| password.trim().to_owned());
        }
        Action::Unlock | Action::Delete => unreachable!(),
    }
    user_lifecycle::update_account(accounts, principal, email, patch)
        .await
        .map(Some)
}

fn action_error(accounts: &Accounts, error: AccountError, action: Option<Action>) -> Response {
    let status = match (error.0, action) {
        (StatusCode::NOT_FOUND, Some(Action::Unlock | Action::RequirePasswordChange)) => error.0,
        (StatusCode::NOT_FOUND | StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY, _) => {
            StatusCode::BAD_REQUEST
        }
        _ => error.0,
    };
    let message = error.1["detail"]
        .as_str()
        .unwrap_or("Account change failed");
    let response = render(context! {
        page => "user-error", title => "Account change failed", error => message,
        root => &settings_for(accounts).root,
    });
    let Ok(mut response) = response else {
        return response.into_response();
    };
    *response.status_mut() = status;
    if matches!(action, Some(Action::Update)) {
        response.headers_mut().insert(
            "HX-Retarget",
            axum::http::HeaderValue::from_static("#edit-user-error"),
        );
    }
    response
}
