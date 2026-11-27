// SPDX-License-Identifier: Apache-2.0

mod storage;

use std::collections::{BTreeMap, BTreeSet};

use axum::routing::delete;

use super::*;
use crate::auth::TeamVisibility;

const INVALID: &str = "Invalid request. Please check your input and try again.";

pub(super) fn router() -> Router<Arc<Accounts>> {
    let mut routes = Router::new();
    for base in ["/rbac", "/v1/rbac"] {
        routes = routes
            .route(&format!("{base}/roles"), get(list).post(create))
            .route(
                &format!("{base}/roles/{{id}}"),
                get(detail).put(edit).delete(remove),
            )
            .route(
                &format!("{base}/users/{{user}}/roles"),
                get(assignments).post(assign),
            )
            .route(
                &format!("{base}/users/{{user}}/roles/{{id}}"),
                delete(revoke),
            )
            .route(&format!("{base}/permissions/check"), post(check))
            .route(
                &format!("{base}/permissions/user/{{user}}"),
                get(user_permissions),
            )
            .route(&format!("{base}/permissions/available"), get(available))
            .route(&format!("{base}/my/roles"), get(my_roles))
            .route(&format!("{base}/my/permissions"), get(my_permissions));
    }
    routes
}

#[derive(Deserialize)]
pub(super) struct RoleCreate {
    name: String,
    description: Option<String>,
    scope: String,
    permissions: Vec<String>,
    inherits_from: Option<String>,
    #[serde(default)]
    is_system_role: bool,
}

#[derive(Default, Deserialize)]
pub(super) struct RoleEdit {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
    inherits_from: Option<String>,
    is_active: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct Assign {
    role_id: String,
    scope: String,
    scope_id: Option<String>,
    expires_at: Option<String>,
}

#[derive(Deserialize)]
struct ListQuery {
    scope: Option<String>,
    active_only: Option<bool>,
    team_id: Option<String>,
    scope_id: Option<String>,
}

#[derive(Deserialize)]
struct PermissionQuery {
    team_id: Option<String>,
}

#[derive(Deserialize)]
struct CheckPermission {
    user_email: String,
    permission: String,
    team_id: Option<String>,
}

async fn list(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let roles = accounts
        .database
        .rbac_roles(query.scope.as_deref(), query.active_only.unwrap_or(true))
        .await?;
    Ok(Json(json!(
        roles
            .iter()
            .map(storage::Role::metadata)
            .collect::<Vec<_>>()
    )))
}

async fn detail(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let role = accounts
        .database
        .rbac_role(&id)
        .await?
        .ok_or_else(role_missing)?;
    Ok(Json(role.metadata()))
}

async fn create(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Json(input): Json<RoleCreate>,
) -> Result<Json<Value>, AccountError> {
    require_admin(&principal)?;
    validate_role(&input.name, &input.scope, &input.permissions)?;
    let role = accounts
        .database
        .create_rbac_role(&input, &principal.email)
        .await?;
    Ok(Json(role.metadata()))
}

async fn edit(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(input): Json<RoleEdit>,
) -> Result<Json<Value>, AccountError> {
    require_admin(&principal)?;
    let role = accounts.database.change_rbac_role(&id, &input).await?;
    Ok(Json(role.metadata()))
}

async fn remove(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AccountError> {
    require_admin(&principal)?;
    accounts
        .database
        .change_rbac_role(
            &id,
            &RoleEdit {
                is_active: Some(false),
                ..RoleEdit::default()
            },
        )
        .await?;
    Ok(Json(json!({"message":"Role deleted successfully"})))
}

async fn my_roles(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AccountError> {
    let rows = accounts
        .database
        .rbac_assignments(
            &principal.email,
            query.scope.as_deref(),
            query.team_id.as_deref(),
            false,
        )
        .await?;
    Ok(Json(json!(rows)))
}

async fn assignments(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(user): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let rows = accounts
        .database
        .rbac_assignments(
            &user.trim().to_ascii_lowercase(),
            query.scope.as_deref(),
            query.team_id.as_deref(),
            !query.active_only.unwrap_or(true),
        )
        .await?;
    Ok(Json(json!(rows)))
}

async fn assign(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(user): Path<String>,
    Json(input): Json<Assign>,
) -> Result<Json<Value>, AccountError> {
    require_admin(&principal)?;
    let expiry = input
        .expires_at
        .as_deref()
        .map(|raw| parse_timestamp(raw).ok_or_else(invalid))
        .transpose()?;
    if expiry.is_some_and(|time| time <= Timestamp::now()) {
        return Err(invalid());
    }
    let assignment = accounts
        .database
        .assign_rbac_role(
            &user.trim().to_ascii_lowercase(),
            &input,
            expiry,
            &principal.email,
        )
        .await?;
    Ok(Json(json!(assignment)))
}

async fn revoke(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path((user, id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AccountError> {
    require_admin(&principal)?;
    let removed = accounts
        .database
        .revoke_rbac_role(
            &user.trim().to_ascii_lowercase(),
            &id,
            query.scope.as_deref(),
            query.scope_id.as_deref(),
        )
        .await?;
    if !removed {
        return Err(AccountError::detail(
            StatusCode::NOT_FOUND,
            "Role assignment not found",
        ));
    }
    Ok(Json(json!({"message":"Role revoked successfully"})))
}

async fn my_permissions(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<PermissionQuery>,
) -> Result<Json<Value>, AccountError> {
    let scope = principal.visibility.clone();
    let team = query.team_id.as_deref().filter(|team| match &scope {
        TeamVisibility::Admin => true,
        TeamVisibility::Teams(teams) => teams.iter().any(|allowed| allowed == team),
        TeamVisibility::Public => false,
    });
    let mut result = effective_permissions(&accounts.database, &principal.email, team).await?;
    result.retain(|permission| principal.token_allows(permission));
    Ok(Json(json!(result)))
}

async fn user_permissions(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(user): Path<String>,
    Query(query): Query<PermissionQuery>,
) -> Result<Json<Value>, AccountError> {
    require_audit(&accounts, &principal).await?;
    Ok(Json(json!(
        effective_permissions(
            &accounts.database,
            &user.trim().to_ascii_lowercase(),
            query.team_id.as_deref()
        )
        .await?
    )))
}

async fn check(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Json(input): Json<CheckPermission>,
) -> Result<Json<Value>, AccountError> {
    require_audit(&accounts, &principal).await?;
    let target = input.user_email.trim().to_ascii_lowercase();
    let permissions =
        effective_permissions(&accounts.database, &target, input.team_id.as_deref()).await?;
    Ok(Json(json!({
        "user_email":input.user_email, "permission":input.permission,
        "granted":permissions.contains("*") || permissions.contains(&input.permission),
        "checked_by":principal.email, "checked_at":Timestamp::now().to_string(),
    })))
}

async fn available() -> Json<Value> {
    let all = permissions().collect::<Vec<_>>();
    let mut resources = BTreeMap::<&str, Vec<&str>>::new();
    for permission in &all {
        let resource = permission
            .split_once(['.', ':'])
            .map_or(*permission, |(resource, _)| resource);
        resources.entry(resource).or_default().push(permission);
    }
    Json(json!({"all_permissions":all,"total_count":all.len(),"permissions_by_resource":resources}))
}

async fn effective_permissions(
    database: &Database,
    email: &str,
    team: Option<&str>,
) -> Result<BTreeSet<String>, AccountError> {
    let mut permissions = BTreeSet::new();
    if database
        .active_identity(Some(email), None, None)
        .await?
        .is_none()
    {
        return Ok(permissions);
    }
    let memberships = database.memberships(email).await?;
    let team = team.filter(|team| memberships.iter().any(|member| member == team));
    for grant in database.grants(email).await? {
        if grant.scope == "global"
            || grant.scope == "personal"
            || team.is_some() && (grant.team_id.is_none() || grant.team_id.as_deref() == team)
        {
            permissions.extend(grant.permissions);
        }
    }
    Ok(permissions)
}

async fn require_audit(accounts: &Accounts, principal: &Principal) -> Result<(), AccountError> {
    if !accounts
        .access
        .allows(
            principal,
            "admin.security_audit",
            RoleContext::Global,
            principal.is_global_admin(),
        )
        .await?
    {
        return Err(AccountError::detail(StatusCode::FORBIDDEN, "Access denied"));
    }
    Ok(())
}

fn require_admin(principal: &Principal) -> Result<(), AccountError> {
    if !principal.is_global_admin() || !principal.token_allows("admin.user_management") {
        return Err(AccountError::detail(StatusCode::FORBIDDEN, "Access denied"));
    }
    Ok(())
}

fn permissions() -> impl Iterator<Item = &'static str> {
    include_str!("rbac/permissions.txt").lines()
}

fn validate_role(name: &str, scope: &str, scopes: &[String]) -> Result<(), AccountError> {
    if name.trim().is_empty()
        || name.chars().count() > 255
        || name.chars().any(char::is_control)
        || !matches!(scope, "global" | "team" | "personal")
        || scopes
            .iter()
            .any(|scope| scope != "*" && !permissions().any(|permission| permission == scope))
    {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> AccountError {
    AccountError::bad_request(INVALID)
}

fn role_missing() -> AccountError {
    AccountError::detail(StatusCode::NOT_FOUND, "Role not found")
}
