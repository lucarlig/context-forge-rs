// SPDX-License-Identifier: Apache-2.0

use super::*;
use storage::MemberMutation;

pub(in crate::local_auth) const READ: &str = "teams.read";
pub(in crate::local_auth) const CREATE: &str = "teams.create";
pub(in crate::local_auth) const UPDATE: &str = "teams.update";
pub(in crate::local_auth) const DELETE: &str = "teams.delete";
pub(in crate::local_auth) const MEMBERS: &str = "teams.manage_members";
pub(in crate::local_auth) const JOIN: &str = "teams.join";

pub(in crate::local_auth) async fn allowed(
    accounts: &Accounts,
    principal: &Principal,
    permission: &str,
    team: Option<&str>,
) -> Result<bool, sqlx::Error> {
    accounts
        .access
        .allows(
            principal,
            permission,
            team.map_or(RoleContext::AnyTeam, RoleContext::Team),
            false,
        )
        .await
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::local_auth) enum View {
    List,
    Explore,
    Unified,
    Discover,
    Search,
    Ids,
}

#[derive(Default, Deserialize)]
pub(in crate::local_auth) struct DirectoryQuery {
    pub(in crate::local_auth) page: Option<i64>,
    pub(in crate::local_auth) per_page: Option<i64>,
    pub(in crate::local_auth) limit: Option<i64>,
    pub(in crate::local_auth) q: Option<String>,
    #[serde(default, deserialize_with = "query_flag")]
    pub(in crate::local_auth) include_inactive: bool,
    pub(in crate::local_auth) visibility: Option<String>,
    pub(in crate::local_auth) relationship: Option<String>,
    pub(in crate::local_auth) render: Option<String>,
    #[serde(default, deserialize_with = "query_flag")]
    pub(in crate::local_auth) unified: bool,
}

fn query_flag<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    let input = String::deserialize(deserializer)?;
    crate::gateway::catalog_query_flag(Some(&input))
        .map_err(|_| serde::de::Error::custom("Invalid boolean query parameter"))
}

impl DirectoryQuery {
    pub(in crate::local_auth) fn validate(&self) -> Result<(), AccountError> {
        if self.q.as_ref().is_some_and(|q| q.chars().count() > 500)
            || self
                .visibility
                .as_deref()
                .is_some_and(|v| !matches!(v, "" | "private" | "public"))
            || self
                .relationship
                .as_deref()
                .is_some_and(|r| !matches!(r, "" | "owner" | "member" | "public"))
        {
            return Err(AccountError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid team query",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub(in crate::local_auth) struct Row {
    pub(in crate::local_auth) team: Value,
    pub(in crate::local_auth) relationship: &'static str,
    pub(in crate::local_auth) edit: bool,
    pub(in crate::local_auth) delete: bool,
    pub(in crate::local_auth) members: bool,
    pub(in crate::local_auth) join: bool,
    pub(in crate::local_auth) cancel_join: bool,
    pub(in crate::local_auth) review: bool,
    pub(in crate::local_auth) leave: bool,
}

pub(in crate::local_auth) async fn directory(
    accounts: &Accounts,
    principal: &Principal,
    query: &DirectoryQuery,
    view: View,
) -> Result<Vec<Value>, AccountError> {
    let public_discovery = view == View::Discover && principal.can_discover_public_teams();
    let discover = public_discovery
        || matches!(view, View::Explore | View::Unified)
            && (!principal.is_admin()
                || view == View::Unified
                || query.relationship.as_deref() == Some("public"));
    let actor = TeamActor {
        email: &principal.email,
        admin: principal.is_admin()
            && !matches!(view, View::Unified | View::Discover)
            && query.relationship.as_deref().is_none_or(str::is_empty),
    };
    let rows = accounts
        .database
        .team_directory(
            actor,
            discover,
            view != View::List && query.include_inactive,
        )
        .await?;
    let query_text = query.q.as_deref().unwrap_or_default();
    let text = if view == View::Search {
        query_text.trim()
    } else {
        query_text
    }
    .to_lowercase();
    let mut output = Vec::new();
    for row in rows {
        let team = row.team;
        if !(in_token_scope(principal, &team.id)
            || public_discovery
                && team.is_active
                && !team.is_personal
                && team.visibility == "public")
            || query
                .visibility
                .as_deref()
                .is_some_and(|v| !v.is_empty() && v != team.visibility)
        {
            continue;
        }
        let role = row.role.as_deref();
        let relation = if team.is_personal {
            "personal"
        } else if role == Some("owner") {
            "owner"
        } else if role.is_some() {
            "member"
        } else if team.visibility == "public" && team.is_active {
            "public"
        } else {
            ""
        };
        if !query.relationship.as_deref().is_none_or(|filter| {
            filter.is_empty() || filter == relation || filter == "owner" && role == Some("owner")
        }) {
            continue;
        }
        if !text.is_empty()
            && !team.name.to_lowercase().contains(&text)
            && !team.slug.to_lowercase().contains(&text)
            && (view == View::Ids
                || !team
                    .description
                    .as_deref()
                    .unwrap_or_default()
                    .to_lowercase()
                    .contains(&text))
        {
            continue;
        }
        output.push(if view == View::Search {
            team.directory_metadata()
        } else {
            let mut metadata = team.metadata();
            metadata["relationship"] = json!(relation);
            if relation == "public" {
                metadata["pending_join_request"] = json!(row.pending_request_id);
            }
            metadata
        });
    }
    Ok(output)
}

pub(in crate::local_auth) async fn row(
    accounts: &Accounts,
    principal: &Principal,
    team: Value,
) -> Result<Row, sqlx::Error> {
    let team_id = team["id"].as_str().expect("team metadata has an ID");
    let relationship = match team["relationship"].as_str() {
        Some("personal") => "Personal",
        Some("owner") => "Owner",
        Some("member") => "Member",
        Some("public") => "Public",
        _ => "",
    };
    let active = team["is_active"] == true;
    let owner_or_admin = relationship == "Owner" || principal.is_global_admin();
    let manageable = active && team["is_personal"] != true && owner_or_admin;
    let edit = manageable && allowed(accounts, principal, UPDATE, Some(team_id)).await?;
    let delete = manageable && allowed(accounts, principal, DELETE, Some(team_id)).await?;
    let members = active
        && (owner_or_admin || relationship == "Member" || relationship == "Personal")
        && allowed(accounts, principal, READ, Some(team_id)).await?;
    let joinable = active
        && relationship == "Public"
        && can_request_team(principal, team_id)
        && allowed(accounts, principal, JOIN, None).await?;
    let pending = team["pending_join_request"].is_string();
    let review = active
        && relationship == "Owner"
        && allowed(accounts, principal, MEMBERS, Some(team_id)).await?;
    let leave = active
        && matches!(relationship, "Owner" | "Member")
        && allowed(accounts, principal, JOIN, Some(team_id)).await?;
    Ok(Row {
        team,
        relationship,
        edit,
        delete,
        members,
        join: joinable && !pending && accounts.settings.teams.allow_join_requests,
        cancel_join: joinable && pending,
        review,
        leave,
    })
}

fn can_request_team(principal: &Principal, team: &str) -> bool {
    principal.can_discover_public_teams() || in_token_scope(principal, team)
}

pub(in crate::local_auth) async fn submit_join(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    message: &str,
) -> Result<(Value, bool), AccountError> {
    if !can_request_team(principal, id) {
        return Err(denied("Access denied"));
    }
    let result = membership::request_join(accounts, principal, id, Some(message), false).await;
    let (request, created) = result.map_err(|mut error| {
        if error.0 == StatusCode::FORBIDDEN && accounts.settings.teams.allow_join_requests {
            error.0 = StatusCode::BAD_REQUEST;
        }
        error
    })?;
    Ok((request.metadata(), created))
}

pub(in crate::local_auth) async fn cancel_join(
    accounts: &Accounts,
    principal: &Principal,
    team: &str,
    request: &str,
) -> Result<(), AccountError> {
    if !can_request_team(principal, team) {
        return Err(denied("Access denied"));
    }
    accounts
        .database
        .cancel_team_join_request(team, request, &principal.email)
        .await
}

pub(in crate::local_auth) async fn join_queue(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
) -> Result<(Value, Vec<Value>), AccountError> {
    let team = team(accounts, principal, id, MEMBERS, TeamAccess::Owner).await?;
    let records = accounts.database.team_join_requests(id).await?;
    let records = records
        .iter()
        .map(|record| {
            let mut metadata = record.metadata();
            metadata["expired"] = json!(record.expired());
            metadata
        })
        .collect();
    Ok((team.metadata(), records))
}

pub(in crate::local_auth) async fn review_join(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    request: &str,
    approve: bool,
) -> Result<(), AccountError> {
    team(accounts, principal, id, MEMBERS, TeamAccess::Owner).await?;
    accounts
        .database
        .review_team_membership(id, request, &principal.email, approve, &accounts.settings)
        .await?;
    Ok(())
}

pub(in crate::local_auth) async fn leave_team(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
) -> Result<(), AccountError> {
    let team = team(accounts, principal, id, JOIN, TeamAccess::Member).await?;
    if team.is_personal {
        return Err(AccountError::bad_request("Cannot leave your personal team"));
    }
    membership::leave_team(accounts, principal, id).await
}

pub(in crate::local_auth) async fn can_create(
    accounts: &Accounts,
    principal: &Principal,
) -> Result<bool, sqlx::Error> {
    Ok(
        (accounts.settings.teams.allow_creation || principal.is_global_admin())
            && allowed(accounts, principal, CREATE, None).await?,
    )
}

pub(in crate::local_auth) async fn create(
    accounts: &Arc<Accounts>,
    principal: &Principal,
    name: String,
    description: Option<String>,
    visibility: Option<String>,
    capacity: Option<i32>,
) -> Result<(), AccountError> {
    create_team(
        accounts,
        principal,
        TeamCreate {
            name,
            description,
            visibility,
            max_members: capacity,
            members: None,
        },
    )
    .await?;
    Ok(())
}

async fn team(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    permission: &str,
    access: TeamAccess,
) -> Result<storage::Team, AccountError> {
    if !allowed(accounts, principal, permission, Some(id)).await? {
        return Err(denied("Permission denied"));
    }
    scoped_team(accounts, principal, id, access).await
}

pub(in crate::local_auth) async fn editable(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
) -> Result<Value, AccountError> {
    let team = team(accounts, principal, id, UPDATE, TeamAccess::OwnerOrAdmin).await?;
    if team.is_personal {
        return Err(AccountError::bad_request(
            "Personal teams cannot be edited from this page",
        ));
    }
    Ok(team.metadata())
}

pub(in crate::local_auth) async fn update(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    name: String,
    description: Option<String>,
    visibility: Option<String>,
    capacity: Option<Option<i32>>,
) -> Result<(), AccountError> {
    editable(accounts, principal, id).await?;
    update_team(
        accounts,
        principal,
        id,
        TeamPatch {
            name: Some(name),
            description,
            visibility,
            max_members: capacity,
        },
    )
    .await?;
    Ok(())
}

pub(in crate::local_auth) async fn delete(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
) -> Result<(), AccountError> {
    let team = team(accounts, principal, id, DELETE, TeamAccess::OwnerOrAdmin).await?;
    if team.is_personal {
        return Err(AccountError::detail(
            StatusCode::CONFLICT,
            "Personal teams cannot be deleted",
        ));
    }
    accounts
        .database
        .delete_managed_team(id, TeamActor::from(principal))
        .await
}

pub(in crate::local_auth) async fn member_view(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    require_owner: bool,
) -> Result<Value, AccountError> {
    let (permission, access) = if require_owner {
        (MEMBERS, TeamAccess::Owner)
    } else {
        (READ, TeamAccess::MemberOrAdmin)
    };
    Ok(team(accounts, principal, id, permission, access)
        .await?
        .metadata())
}

#[derive(Serialize, sqlx::FromRow)]
pub(in crate::local_auth) struct DirectoryMember {
    pub(in crate::local_auth) email: String,
    full_name: Option<String>,
    role: Option<String>,
}

pub(in crate::local_auth) async fn members(
    accounts: &Accounts,
    id: &str,
    search: &str,
    current: bool,
) -> Result<Vec<DirectoryMember>, sqlx::Error> {
    accounts
        .database
        .team_member_directory(id, &search.to_lowercase(), current)
        .await
}

pub(in crate::local_auth) async fn can_manage_members(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
) -> Result<bool, sqlx::Error> {
    Ok(allowed(accounts, principal, MEMBERS, Some(id)).await?
        && accounts
            .database
            .managed_member(id, &principal.email)
            .await?
            .is_some_and(|member| member.role == "owner"))
}

#[derive(Clone, Copy)]
pub(in crate::local_auth) enum MemberAction<'a> {
    AddOrUpdate(&'a str),
    Role(&'a str),
    Remove,
}

pub(in crate::local_auth) enum MemberChange {
    Added,
    Updated,
    Removed,
    Unchanged,
}

pub(in crate::local_auth) async fn change_member(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    email: &str,
    action: MemberAction<'_>,
) -> Result<MemberChange, AccountError> {
    let email = email.trim().to_ascii_lowercase();
    if !valid_email(&email) {
        return Err(AccountError::bad_request("Invalid user email"));
    }
    let (mutation, change) = match action {
        MemberAction::AddOrUpdate(role) => {
            check_member_role(role)?;
            match accounts.database.managed_member(id, &email).await? {
                Some(member) if member.role == role => return Ok(MemberChange::Unchanged),
                Some(_) => (MemberMutation::Role(role), MemberChange::Updated),
                None => (MemberMutation::Add(role), MemberChange::Added),
            }
        }
        MemberAction::Role(role) => {
            check_member_role(role)?;
            (MemberMutation::Role(role), MemberChange::Updated)
        }
        MemberAction::Remove => (MemberMutation::Remove, MemberChange::Removed),
    };
    accounts
        .database
        .write_team_member(id, &email, &principal.email, mutation, &accounts.settings)
        .await?;
    Ok(change)
}
