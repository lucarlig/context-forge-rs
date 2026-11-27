// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(sqlx::FromRow)]
pub(super) struct Team {
    pub(super) id: String,
    pub(super) name: String,
    slug: String,
    description: Option<String>,
    created_by: String,
    pub(super) is_personal: bool,
    pub(super) visibility: String,
    max_members: Option<i32>,
    member_count: i64,
    created_at: String,
    updated_at: String,
    is_active: bool,
}

impl Team {
    pub(super) fn metadata(&self) -> Value {
        json!({
            "id":self.id, "name":self.name, "slug":self.slug, "description":self.description,
            "created_by":self.created_by,"is_personal":self.is_personal,"visibility":self.visibility,
            "max_members":self.max_members,"member_count":self.member_count,"is_active":self.is_active,
            "created_at":iso(&self.created_at),"updated_at":iso(&self.updated_at),
        })
    }

    pub(super) fn discovery_metadata(&self) -> Value {
        json!({"id":self.id,"name":self.name,"description":self.description,"member_count":self.member_count,
               "is_joinable":true,"created_at":iso(&self.created_at)})
    }
}

#[derive(sqlx::FromRow)]
pub(super) struct Member {
    pub(super) id: String,
    team_id: String,
    user_email: String,
    pub(super) role: String,
    joined_at: String,
    invited_by: Option<String>,
    is_active: bool,
    grant_source: Option<String>,
}

impl Member {
    pub(super) fn metadata(&self) -> Value {
        json!({
            "id":self.id,"team_id":self.team_id,"user_email":self.user_email,"role":self.role,
            "joined_at":iso(&self.joined_at),"invited_by":self.invited_by,"is_active":self.is_active,
            "grant_source":self.grant_source,
        })
    }
}

pub(super) struct TeamCreated {
    pub(super) team: Team,
    pub(super) members: Vec<Value>,
    pub(super) invites: Vec<Invitation>,
}

fn iso(value: &str) -> String {
    value.replacen(' ', "T", 1)
}

macro_rules! team_fields {
    () => {
        "t.id,t.name,t.slug,t.description,t.created_by,t.is_personal,t.visibility,t.max_members,
        (SELECT COUNT(*) FROM email_team_members m WHERE m.team_id=t.id AND m.is_active=TRUE) AS member_count,
        CAST(t.created_at AS TEXT) AS created_at,CAST(t.updated_at AS TEXT) AS updated_at,t.is_active"
    };
}

macro_rules! member_fields {
    () => {
        "id,team_id,user_email,role,CAST(joined_at AS TEXT) AS joined_at,invited_by,is_active,grant_source"
    };
}

const TEAM_DETAIL: &str = concat!(
    "SELECT ",
    team_fields!(),
    " FROM email_teams t WHERE t.id=$1 AND t.is_active=TRUE"
);
const MEMBER_ANY_STATE: &str = concat!(
    "SELECT ",
    member_fields!(),
    " FROM email_team_members WHERE team_id=$1 AND user_email=$2"
);

macro_rules! team_permission {
    ($tx:ident,$id:expr,$actor:expr,$allowed_admin:expr) => {
        if !$allowed_admin {
            let allowed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_team_members m
                JOIN email_users u ON u.email=m.user_email AND u.is_active=TRUE
                WHERE m.team_id=$1 AND m.user_email=$2 AND m.role='owner' AND m.is_active=TRUE)")
                .bind($id).bind($actor).fetch_one(&mut *$tx).await?;
            if !allowed {
                return Err(denied("Access denied"));
            }
        }
    };
}

macro_rules! sync_member_role {
    ($tx:ident,$member:expr,$actor:expr,$settings:expr,$active:expr) => {{
        let member=&$member;
        let owner=&$settings.provisioning.owner_role;
        let viewer=&$settings.teams.member_role;
        let selected=if member.role=="owner" { owner } else { viewer };
        sqlx::query("UPDATE user_roles SET is_active=FALSE WHERE user_email=$1
            AND scope='team' AND scope_id=$2 AND is_active=TRUE
            AND (NOT $5 OR role_id IN (SELECT id FROM roles WHERE scope='team' AND name IN ($3,$4)))")
            .bind(&member.user_email).bind(&member.team_id).bind(owner).bind(viewer).bind($active)
            .execute(&mut *$tx).await?;
        if $active {
            sqlx::query("INSERT INTO user_roles(id,user_email,role_id,scope,scope_id,granted_by,granted_at,is_active)
                SELECT $1,$2,r.id,'team',$3,$4,CURRENT_TIMESTAMP,TRUE FROM roles r
                WHERE r.name=$5 AND r.scope='team' AND r.is_active=TRUE ON CONFLICT DO NOTHING")
                .bind(Uuid::new_v4().to_string()).bind(&member.user_email).bind(&member.team_id).bind($actor).bind(selected)
                .execute(&mut *$tx).await?;
        }
    }};
}

macro_rules! log_member {
    ($tx:ident,$member:expr,$actor:expr,$action:expr) => {{
        let member = &$member;
        sqlx::query(
            "INSERT INTO email_team_member_history
            (id,team_member_id,team_id,user_email,role,action,action_by,action_timestamp)
            VALUES($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&member.id)
        .bind(&member.team_id)
        .bind(&member.user_email)
        .bind(&member.role)
        .bind($action)
        .bind($actor)
        .execute(&mut *$tx)
        .await?;
    }};
}

macro_rules! insert_member {
    ($tx:ident,$team:expr,$email:expr,$role:expr,$inviter:expr,$actor:expr,$settings:expr,$skip_limits:expr) => {{
        let team=&$team;
        let email=$email;
        let actor=$actor;
        let existing:Option<Member>=sqlx::query_as(MEMBER_ANY_STATE).bind(&team.id).bind(email)
            .fetch_optional(&mut *$tx).await?;
        if existing.as_ref().is_some_and(|member|member.is_active) {
            return Err(AccountError::detail(StatusCode::CONFLICT,"User is already a member of this team"));
        }
        let settings=$settings;
        let maximum=team.max_members.unwrap_or(settings.teams.max_members);
        let members:i64=sqlx::query_scalar("SELECT COUNT(*) FROM email_team_members WHERE team_id=$1 AND is_active=TRUE")
            .bind(&team.id).fetch_one(&mut *$tx).await?;
        if members>=i64::from(maximum) {
            return Err(AccountError::bad_request(format!("Team has reached its member limit of {maximum}")));
        }
        if !$skip_limits {
            let teams:i64=sqlx::query_scalar("SELECT COUNT(*) FROM email_team_members m
                JOIN email_teams t ON t.id=m.team_id AND t.is_active=TRUE
                WHERE m.user_email=$1 AND m.is_active=TRUE")
                .bind(email).fetch_one(&mut *$tx).await?;
            if teams>=settings.teams.max_teams {
                return Err(AccountError::bad_request(format!("User has reached the maximum team limit of {}",settings.teams.max_teams)));
            }
        }
        let member:Member=sqlx::query_as(concat!(
            "INSERT INTO email_team_members(id,team_id,user_email,role,invited_by,joined_at,is_active)
            VALUES($1,$2,$3,$4,$5,CURRENT_TIMESTAMP,TRUE)
            ON CONFLICT(team_id,user_email) DO UPDATE SET role=excluded.role,invited_by=excluded.invited_by,
                joined_at=excluded.joined_at,is_active=TRUE RETURNING ",member_fields!()))
            .bind(Uuid::new_v4().simple().to_string()).bind(&team.id).bind(email).bind($role).bind($inviter)
            .fetch_one(&mut *$tx).await?;
        sync_member_role!($tx,member,actor,settings,true);
        let action=if existing.is_some() {"reactivated"} else {"added"};
        log_member!($tx,member,actor,action);
        member
    }};
}

macro_rules! team_transaction {
    ($db:expr,$action:ident $(,$extra:expr)*) => {
        match $db {
            Database::Sqlite(pool) => {
                let mut tx=pool.begin_with("BEGIN IMMEDIATE").await?;
                $action!(tx, false $(,$extra)*)
            }
            Database::Postgres(pool) => {
                let mut tx=pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682073)").execute(&mut *tx).await?;
                $action!(tx, true $(,$extra)*)
            }
        }
    };
}

impl Database {
    pub(super) async fn managed_team(&self, id: &str) -> Result<Option<Team>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(TEAM_DETAIL)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(TEAM_DETAIL)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    pub(super) async fn managed_teams(
        &self,
        actor: TeamActor<'_>,
    ) -> Result<Vec<Team>, sqlx::Error> {
        macro_rules! list {
            ($pool:ident) => {
                sqlx::query_as(concat!("SELECT ",team_fields!()," FROM email_teams t WHERE t.is_active=TRUE AND (
                    ($2 AND (NOT t.is_personal OR t.created_by=$1)) OR (
                    NOT $2 AND EXISTS(SELECT 1 FROM email_team_members m WHERE m.team_id=t.id AND m.user_email=$1 AND m.is_active=TRUE)
                    )) ORDER BY t.created_at DESC,t.id DESC"))
                    .bind(actor.email).bind(actor.admin).fetch_all($pool).await
            };
        }
        match self {
            Self::Sqlite(pool) => list!(pool),
            Self::Postgres(pool) => list!(pool),
        }
    }

    pub(super) async fn discover_teams(
        &self,
        email: &str,
        limit: usize,
        skip: usize,
    ) -> Result<Vec<Team>, sqlx::Error> {
        macro_rules! list {
            ($pool:ident) => {
                sqlx::query_as(concat!("SELECT ",team_fields!()," FROM email_teams t
                    WHERE t.is_active=TRUE AND NOT t.is_personal AND t.visibility='public'
                    AND NOT EXISTS(SELECT 1 FROM email_team_members m WHERE m.team_id=t.id AND m.user_email=$1 AND m.is_active=TRUE)
                    ORDER BY t.created_at DESC,t.id DESC LIMIT $2 OFFSET $3"))
                    .bind(email).bind(i64::try_from(limit).unwrap_or(i64::MAX)).bind(i64::try_from(skip).unwrap_or(i64::MAX))
                    .fetch_all($pool).await
            };
        }
        match self {
            Self::Sqlite(pool) => list!(pool),
            Self::Postgres(pool) => list!(pool),
        }
    }

    pub(super) async fn managed_members(&self, id: &str) -> Result<Vec<Member>, sqlx::Error> {
        macro_rules! list {
            ($pool:ident) => {
                sqlx::query_as(concat!("SELECT ",member_fields!()," FROM email_team_members
                    WHERE team_id=$1 AND is_active=TRUE ORDER BY joined_at DESC,(invited_by IS NULL),id DESC"))
                    .bind(id).fetch_all($pool).await
            };
        }
        match self {
            Self::Sqlite(pool) => list!(pool),
            Self::Postgres(pool) => list!(pool),
        }
    }

    pub(super) async fn managed_member(
        &self,
        id: &str,
        email: &str,
    ) -> Result<Option<Member>, sqlx::Error> {
        const SQL: &str = concat!(
            "SELECT ",
            member_fields!(),
            " FROM email_team_members WHERE team_id=$1 AND user_email=$2 AND is_active=TRUE"
        );
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(SQL)
                    .bind(id)
                    .bind(email)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(SQL)
                    .bind(id)
                    .bind(email)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    pub(super) async fn create_managed_team(
        &self,
        input: &TeamCreate,
        actor: TeamActor<'_>,
        settings: &AccountSettings,
    ) -> Result<TeamCreated, AccountError> {
        let slug = slugify(&input.name);
        let description = input.description.as_deref();
        let visibility = input.visibility.as_deref().unwrap_or("private");
        macro_rules! create {
            ($tx:ident,$postgres:tt) => {{
                let existing:Option<Team>=sqlx::query_as(concat!("SELECT ",team_fields!()," FROM email_teams t WHERE t.slug=$1"))
                    .bind(&slug).fetch_optional(&mut *$tx).await?;
                let id=match existing {
                    Some(existing) if existing.is_active || existing.is_personal => {
                        return Err(if actor.admin {
                            AccountError::bad_request(format!("A team named '{}' already exists",input.name))
                        } else {
                            AccountError::detail(StatusCode::CONFLICT,"A team with the same name could not be created")
                        });
                    }
                    Some(existing) if actor.admin || existing.created_by==actor.email => {
                        sqlx::query("UPDATE email_teams SET name=$2,description=$3,visibility=$4,max_members=$5,
                            created_by=$6,updated_at=CURRENT_TIMESTAMP,is_active=TRUE WHERE id=$1")
                            .bind(&existing.id).bind(&input.name).bind(description).bind(visibility)
                            .bind(input.max_members).bind(actor.email).execute(&mut *$tx).await?;
                        existing.id
                    }
                    inactive => {
                        if let Some(existing)=inactive {
                            sqlx::query("UPDATE email_teams SET slug=$2 WHERE id=$1")
                                .bind(&existing.id).bind(format!("deleted-{}",existing.id)).execute(&mut *$tx).await?;
                        }
                        let id=Uuid::new_v4().simple().to_string();
                        sqlx::query("INSERT INTO email_teams(id,name,slug,description,created_by,is_personal,visibility,
                            max_members,created_at,updated_at,is_active)
                            VALUES($1,$2,$3,$4,$5,FALSE,$6,$7,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,TRUE)")
                            .bind(&id).bind(&input.name).bind(&slug).bind(description).bind(actor.email)
                            .bind(visibility).bind(input.max_members).execute(&mut *$tx).await?;
                        id
                    }
                };
                let team:Team=sqlx::query_as(TEAM_DETAIL).bind(&id).fetch_one(&mut *$tx).await?;
                insert_member!($tx,team,actor.email,"owner",None::<&str>,actor.email,settings,actor.admin);
                let mut members=Vec::new();
                let mut invites=Vec::new();
                for seed in input.members.as_deref().unwrap_or(&[]) {
                    let email=&seed.email;
                    let role=seed.role.as_deref().unwrap_or("member");
                    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_users WHERE email=$1 AND is_active=TRUE)")
                        .bind(email).fetch_one(&mut *$tx).await?;
                    if active {
                        insert_member!($tx,team,email,role,Some(actor.email),actor.email,settings,false);
                        members.push(json!({"email":email,"role":role}));
                    } else {
                        invites.push(insert_invite!($tx,$postgres,team,email,role,actor.email,settings));
                    }
                }
                let team:Team=sqlx::query_as(TEAM_DETAIL).bind(id).fetch_one(&mut *$tx).await?;
                $tx.commit().await?;
                Ok(TeamCreated{team,members,invites})
            }};
        }
        team_transaction!(self, create)
    }

    pub(super) async fn edit_managed_team(
        &self,
        id: &str,
        input: &TeamPatch,
        actor: TeamActor<'_>,
        settings: &TeamSettings,
    ) -> Result<Team, AccountError> {
        macro_rules! edit {
            ($tx:ident,$postgres:tt) => {{
                let before:Team=sqlx::query_as(TEAM_DETAIL).bind(id).fetch_optional(&mut *$tx).await?.ok_or_else(missing_team)?;
                team_permission!($tx,id,actor.email,actor.admin);
                if before.is_personal && (input.visibility.as_deref().is_some_and(|value|value!="private") || input.max_members.is_some()) {
                    return Err(AccountError::bad_request("Personal teams must remain private"));
                }
                let next_max=input.max_members.unwrap_or(before.max_members);
                if i64::from(next_max.unwrap_or(settings.max_members))<before.member_count {
                    return Err(AccountError::bad_request("Team member limit cannot be smaller than its current membership"));
                }
                sqlx::query("UPDATE email_teams SET name=COALESCE($2,name),description=COALESCE($3,description),
                    visibility=COALESCE($4,visibility),max_members=$5,updated_at=CURRENT_TIMESTAMP WHERE id=$1")
                    .bind(id).bind(input.name.as_deref()).bind(input.description.as_deref()).bind(input.visibility.as_deref())
                    .bind(next_max).execute(&mut *$tx).await?;
                let team=sqlx::query_as(TEAM_DETAIL).bind(id).fetch_one(&mut *$tx).await?;
                $tx.commit().await?;
                Ok(team)
            }};
        }
        team_transaction!(self, edit)
    }

    pub(super) async fn delete_managed_team(
        &self,
        id: &str,
        actor: TeamActor<'_>,
    ) -> Result<(), AccountError> {
        macro_rules! delete_team {
            ($tx:ident,$postgres:tt) => {{
                let team:Team=sqlx::query_as(TEAM_DETAIL).bind(id).fetch_optional(&mut *$tx).await?.ok_or_else(missing_team)?;
                team_permission!($tx,id,actor.email,actor.admin);
                if team.is_personal {
                    return Err(missing_team());
                }
                let members:Vec<Member>=sqlx::query_as(concat!("SELECT ",member_fields!()," FROM email_team_members
                    WHERE team_id=$1 AND is_active=TRUE")).bind(id).fetch_all(&mut *$tx).await?;
                for member in members {
                    log_member!($tx,member,actor.email,"team-deleted");
                }
                for command in [
                    "UPDATE email_teams SET is_active=FALSE,updated_at=CURRENT_TIMESTAMP WHERE id=$1",
                    "UPDATE email_team_members SET is_active=FALSE WHERE team_id=$1 AND is_active=TRUE",
                    "UPDATE user_roles SET is_active=FALSE WHERE scope='team' AND scope_id=$1 AND is_active=TRUE",
                    "UPDATE email_team_invitations SET is_active=FALSE WHERE team_id=$1 AND is_active=TRUE",
                ] {
                    sqlx::query(command).bind(id).execute(&mut *$tx).await?;
                }
                sqlx::query("UPDATE email_team_join_requests SET status='rejected',reviewed_by=$2,reviewed_at=CURRENT_TIMESTAMP
                    WHERE team_id=$1 AND status='pending'").bind(id).bind(actor.email).execute(&mut *$tx).await?;
                sqlx::query("INSERT INTO token_revocations(jti,revoked_at,revoked_by,reason,token_expiry)
                    SELECT jti,CURRENT_TIMESTAMP,$2,'team_deleted',expires_at FROM email_api_tokens WHERE team_id=$1
                    ON CONFLICT(jti) DO NOTHING")
                    .bind(id).bind(actor.email).execute(&mut *$tx).await?;
                sqlx::query("UPDATE email_api_tokens SET is_active=FALSE WHERE team_id=$1")
                    .bind(id).execute(&mut *$tx).await?;
                $tx.commit().await?;
                Ok(())
            }};
        }
        team_transaction!(self, delete_team)
    }
}

mod participation;
use participation::insert_invite;
pub(super) use participation::{Invitation, JoinRequest, MemberMutation};
