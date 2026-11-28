// SPDX-License-Identifier: Apache-2.0

pub(super) mod dashboard;
mod membership;
mod storage;

use std::collections::HashSet;

use axum::routing::{delete, put};

use super::{user_lifecycle::success, *};
use crate::{auth::TeamVisibility, catalog::slugify};

pub(crate) struct TeamSettings {
    pub(crate) allow_creation: bool,
    pub(crate) allow_join_requests: bool,
    pub(crate) allow_invitations: bool,
    pub(crate) verify_invite_email: bool,
    pub(crate) max_members: i32,
    pub(crate) max_teams: i64,
    pub(crate) max_seeds: usize,
    pub(crate) expires_in_seconds: i64,
    pub(crate) member_role: String,
}

pub(super) fn router() -> Router<Arc<Accounts>> {
    let mut routes = Router::new();
    for base in ["/teams", "/v1/teams"] {
        routes = routes
            .route(base, get(list).post(create))
            .route(&format!("{base}/"), get(list).post(create))
            .route(&format!("{base}/discover"), get(discover))
            .route(
                &format!("{base}/{{id}}"),
                get(detail).put(edit).delete(remove),
            )
            .route(
                &format!("{base}/{{id}}/members"),
                get(members).post(membership::add),
            )
            .route(
                &format!("{base}/{{id}}/members/{{email}}"),
                put(membership::change).delete(membership::remove),
            )
            .route(
                &format!("{base}/{{id}}/invitations"),
                get(membership::list_invites).post(membership::invite),
            )
            .route(
                &format!("{base}/invitations/{{token}}/accept"),
                post(membership::accept),
            )
            .route(
                &format!("{base}/invitations/{{token}}/decline"),
                post(membership::decline),
            )
            .route(
                &format!("{base}/invitations/{{invitation}}"),
                delete(membership::cancel_invite),
            )
            .route(&format!("{base}/{{id}}/join"), post(membership::join))
            .route(&format!("{base}/{{id}}/leave"), delete(membership::leave))
            .route(
                &format!("{base}/{{id}}/join-requests"),
                get(membership::list_requests),
            )
            .route(
                &format!("{base}/{{id}}/join-requests/{{request}}/approve"),
                post(membership::approve),
            )
            .route(
                &format!("{base}/{{id}}/join-requests/{{request}}"),
                delete(membership::reject),
            );
    }
    routes
}

#[derive(Default, Deserialize)]
struct ListQuery {
    skip: Option<usize>,
    limit: Option<usize>,
    cursor: Option<String>,
    #[serde(default)]
    include_pagination: bool,
}

#[derive(Default, Deserialize)]
struct TeamPatch {
    name: Option<String>,
    description: Option<String>,
    visibility: Option<String>,
    #[serde(default, deserialize_with = "present")]
    max_members: Option<Option<i32>>,
}

fn present<'de, T: Deserialize<'de>, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<T>>, D::Error> {
    Option::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct TeamCreate {
    name: String,
    description: Option<String>,
    visibility: Option<String>,
    max_members: Option<i32>,
    members: Option<Vec<MemberInput>>,
}

#[derive(Deserialize)]
struct MemberInput {
    email: String,
    role: Option<String>,
}

#[derive(Clone, Copy)]
struct TeamActor<'a> {
    email: &'a str,
    admin: bool,
}

impl<'a> From<&'a Principal> for TeamActor<'a> {
    fn from(principal: &'a Principal) -> Self {
        Self {
            email: &principal.email,
            admin: principal.is_global_admin(),
        }
    }
}

async fn create(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Json(input): Json<TeamCreate>,
) -> Result<(StatusCode, Json<Value>), AccountError> {
    permit(&accounts, &principal, "teams.create", None).await?;
    let result = create_team(&accounts, &principal, input).await?;
    Ok((StatusCode::CREATED, Json(result)))
}

async fn create_team(
    accounts: &Arc<Accounts>,
    principal: &Principal,
    mut input: TeamCreate,
) -> Result<Value, AccountError> {
    let actor = TeamActor::from(principal);
    if !accounts.settings.teams.allow_creation && !actor.admin {
        return Err(denied("Team creation is currently disabled"));
    }
    input.name = team_name(&input.name)?;
    validate_team_fields(
        &accounts.settings.teams,
        actor,
        input.description.as_deref(),
        input.visibility.as_deref(),
        input.max_members,
    )?;
    let seeds = input.members.get_or_insert_with(Vec::new);
    if seeds.len() > accounts.settings.teams.max_seeds {
        return Err(AccountError::bad_request("Too many seeded team members"));
    }
    let mut identities = HashSet::new();
    for seed in &mut *seeds {
        seed.email = seed.email.trim().to_ascii_lowercase();
        if !valid_email(&seed.email)
            || seed.email == actor.email
            || !identities.insert(seed.email.clone())
        {
            return Err(AccountError::bad_request(
                "Invalid or duplicate seeded team member",
            ));
        }
        check_member_role(seed.role.as_deref().unwrap_or("member"))?;
    }
    let result = accounts
        .database
        .create_managed_team(&input, actor, &accounts.settings)
        .await?;
    let mut body = result.team.metadata();
    body["members_added"] = json!(result.members);
    body["invitations_sent"] = json!(
        result
            .invites
            .iter()
            .map(storage::Invitation::seed_metadata)
            .collect::<Vec<_>>()
    );
    if !result.invites.is_empty() && accounts.settings.mailer.is_some() {
        let accounts = accounts.clone();
        tokio::spawn(async move {
            for invitation in &result.invites {
                membership::send_invitation(&accounts, invitation).await;
            }
        });
    }
    Ok(body)
}

async fn detail(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AccountError> {
    let team = access_team(
        &accounts,
        &principal,
        &id,
        "teams.read",
        TeamAccess::MemberOrAdmin,
    )
    .await?;
    Ok(Json(team.metadata()))
}

async fn list(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AccountError> {
    permit(&accounts, &principal, "teams.read", None).await?;
    let limit = team_page_size(&accounts, &query)?;
    let actor = TeamActor::from(&principal);
    let mut rows = accounts.database.managed_teams(actor).await?;
    rows.retain(|team| in_token_scope(&principal, &team.id));
    let count = rows.len();
    let start = page_start(&query, &rows, |team| &team.id);
    let end = start.saturating_add(limit).min(count);
    let page = &rows[start..end];
    let teams = page.iter().map(storage::Team::metadata).collect::<Vec<_>>();
    Ok(Json(if query.include_pagination {
        let next = (end < count)
            .then(|| page.last())
            .flatten()
            .map(|team| page_cursor(&team.id));
        json!({"teams":teams,"nextCursor":next})
    } else {
        json!({"teams":teams,"total":count})
    }))
}

async fn discover(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AccountError> {
    permit(&accounts, &principal, "teams.read", None).await?;
    let limit = team_page_size(&accounts, &query)?;
    let skip = query.skip.unwrap_or_default();
    let teams = accounts
        .database
        .discover_teams(&principal.email, limit, skip)
        .await?;
    Ok(Json(json!(
        teams
            .iter()
            .map(storage::Team::discovery_metadata)
            .collect::<Vec<_>>()
    )))
}

async fn edit(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(input): Json<TeamPatch>,
) -> Result<Json<Value>, AccountError> {
    access_team(
        &accounts,
        &principal,
        &id,
        "teams.update",
        TeamAccess::OwnerOrAdmin,
    )
    .await?;
    let team = update_team(&accounts, &principal, &id, input).await?;
    Ok(Json(team.metadata()))
}

async fn update_team(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    mut input: TeamPatch,
) -> Result<storage::Team, AccountError> {
    let actor = TeamActor::from(principal);
    if let Some(name) = input.name.as_deref() {
        input.name = Some(team_name(name)?);
    }
    validate_team_fields(
        &accounts.settings.teams,
        actor,
        input.description.as_deref(),
        input.visibility.as_deref(),
        input.max_members.flatten(),
    )?;
    accounts
        .database
        .edit_managed_team(id, &input, actor, &accounts.settings.teams)
        .await
}

async fn remove(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AccountError> {
    access_team(
        &accounts,
        &principal,
        &id,
        "teams.delete",
        TeamAccess::OwnerOrAdmin,
    )
    .await?;
    accounts
        .database
        .delete_managed_team(&id, TeamActor::from(&principal))
        .await?;
    Ok(success("Team deleted successfully"))
}

async fn members(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, AccountError> {
    access_team(&accounts, &principal, &id, "teams.read", TeamAccess::Member).await?;
    let limit = team_page_size(&accounts, &query)?;
    let rows = accounts.database.managed_members(&id).await?;
    let count = rows.len();
    let start = page_start(&query, &rows, |member| &member.id);
    let end = if query.include_pagination || query.limit.is_some() || query.cursor.is_some() {
        start.saturating_add(limit).min(count)
    } else {
        count
    };
    let page = &rows[start..end];
    let members = page
        .iter()
        .map(storage::Member::metadata)
        .collect::<Vec<_>>();
    Ok(Json(if query.include_pagination {
        let next = (end < count)
            .then(|| page.last())
            .flatten()
            .map(|member| page_cursor(&member.id));
        json!({"members":members,"nextCursor":next})
    } else {
        json!(members)
    }))
}

async fn permit(
    accounts: &Accounts,
    principal: &Principal,
    permission: &str,
    id: Option<&str>,
) -> Result<(), AccountError> {
    let scope = id.map_or(RoleContext::AnyTeam, RoleContext::Team);
    if !accounts
        .access
        .allows(principal, permission, scope, true)
        .await?
    {
        return Err(denied("Access denied"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TeamAccess {
    Member,
    MemberOrAdmin,
    Owner,
    OwnerOrAdmin,
}

async fn access_team(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    permission: &str,
    rule: TeamAccess,
) -> Result<storage::Team, AccountError> {
    permit(accounts, principal, permission, Some(id)).await?;
    scoped_team(accounts, principal, id, rule).await
}

async fn scoped_team(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    rule: TeamAccess,
) -> Result<storage::Team, AccountError> {
    if !in_token_scope(principal, id) {
        return Err(denied("Access denied"));
    }
    let team = accounts
        .database
        .managed_team(id)
        .await?
        .ok_or_else(missing_team)?;
    if principal.is_global_admin()
        && matches!(rule, TeamAccess::MemberOrAdmin | TeamAccess::OwnerOrAdmin)
    {
        return Ok(team);
    }
    let membership = accounts
        .database
        .managed_member(id, &principal.email)
        .await?;
    if !membership.is_some_and(|member| {
        matches!(rule, TeamAccess::Member | TeamAccess::MemberOrAdmin) || member.role == "owner"
    }) {
        return Err(denied("Access denied"));
    }
    Ok(team)
}

fn in_token_scope(principal: &Principal, id: &str) -> bool {
    match &principal.visibility {
        TeamVisibility::Admin => true,
        TeamVisibility::Teams(teams) => teams.iter().any(|allowed| allowed == id),
        TeamVisibility::Public => false,
    }
}

fn page_cursor(id: &str) -> String {
    URL_SAFE.encode(json!({"id":id}).to_string())
}

fn page_start<T>(query: &ListQuery, rows: &[T], identify: impl Fn(&T) -> &str) -> usize {
    let cursor = query
        .cursor
        .as_ref()
        .and_then(|cursor| URL_SAFE.decode(cursor).ok())
        .and_then(|decoded| serde_json::from_slice::<Value>(&decoded).ok());
    cursor
        .as_ref()
        .and_then(|cursor| cursor["id"].as_str())
        .and_then(|id| rows.iter().position(|row| identify(row) == id))
        .map_or_else(
            || query.skip.unwrap_or_default().min(rows.len()),
            |index| index + 1,
        )
}

fn team_page_size(accounts: &Accounts, query: &ListQuery) -> Result<usize, AccountError> {
    let limit = query.limit.unwrap_or(accounts.settings.page_size as usize);
    if !(1..=accounts.settings.max_page_size as usize).contains(&limit) {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid team pagination limit",
        ));
    }
    Ok(limit)
}

fn team_name(name: &str) -> Result<String, AccountError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > 255
        || name.chars().any(|character| {
            !(character.is_alphanumeric() || matches!(character, ' ' | '.' | '_' | '-'))
        })
        || slugify(name).is_empty()
    {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid team name",
        ));
    }
    Ok(name.to_owned())
}

fn validate_team_fields(
    settings: &TeamSettings,
    actor: TeamActor<'_>,
    description: Option<&str>,
    visibility: Option<&str>,
    capacity: Option<i32>,
) -> Result<(), AccountError> {
    if description.is_some_and(|description| description.chars().count() > 1000)
        || visibility.is_some_and(|visibility| !matches!(visibility, "public" | "private"))
        || capacity.is_some_and(|capacity| capacity < 1)
    {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid team data",
        ));
    }
    if !actor.admin && capacity.is_some_and(|capacity| capacity > settings.max_members) {
        return Err(AccountError::bad_request(format!(
            "max_members cannot exceed the configured limit of {}",
            settings.max_members
        )));
    }
    Ok(())
}

fn check_member_role(role: &str) -> Result<(), AccountError> {
    if !matches!(role, "owner" | "member") {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid team member role",
        ));
    }
    Ok(())
}

fn missing_team() -> AccountError {
    AccountError::detail(StatusCode::NOT_FOUND, "Team not found")
}

fn denied(message: &str) -> AccountError {
    AccountError::detail(StatusCode::FORBIDDEN, message)
}
