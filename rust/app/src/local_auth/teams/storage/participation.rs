// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use super::*;
use crate::database::observed;

struct MemberSettings<'a> {
    teams: &'a TeamSettings,
    provisioning: &'a UserProvisioning,
    sso_provider: Option<&'a str>,
}

pub(in crate::local_auth::teams) enum MemberMutation<'a> {
    Add(&'a str),
    Role(&'a str),
    Remove,
}

#[derive(sqlx::FromRow)]
pub(in crate::local_auth::teams) struct Invitation {
    id: String,
    pub(in crate::local_auth::teams) team_id: String,
    pub(in crate::local_auth::teams) team_name: String,
    pub(in crate::local_auth::teams) email: String,
    role: String,
    invited_by: String,
    invited_at: String,
    expires_at: String,
    pub(in crate::local_auth::teams) token: String,
    is_active: bool,
}

impl Invitation {
    fn expired(&self) -> bool {
        elapsed(&self.expires_at)
    }

    pub(in crate::local_auth::teams) fn metadata(&self) -> Value {
        json!({"id":self.id,"team_id":self.team_id,"team_name":self.team_name,"email":self.email,
            "role":self.role,"invited_by":self.invited_by,"invited_at":iso(&self.invited_at),
            "expires_at":iso(&self.expires_at),"token":self.token,"is_active":self.is_active,"is_expired":self.expired()})
    }

    pub(in crate::local_auth::teams) fn seed_metadata(&self) -> Value {
        json!({"email":self.email,"role":self.role,"invitation_id":self.id})
    }
}

#[derive(sqlx::FromRow)]
pub(in crate::local_auth::teams) struct JoinRequest {
    id: String,
    team_id: String,
    team_name: String,
    user_email: String,
    message: Option<String>,
    status: String,
    requested_at: String,
    expires_at: String,
}

impl JoinRequest {
    pub(in crate::local_auth::teams) fn expired(&self) -> bool {
        elapsed(&self.expires_at)
    }

    pub(in crate::local_auth::teams) fn metadata(&self) -> Value {
        json!({"id":self.id,"team_id":self.team_id,"team_name":self.team_name,"user_email":self.user_email,
               "message":self.message,"status":self.status,"requested_at":iso(&self.requested_at),"expires_at":iso(&self.expires_at)})
    }
}

macro_rules! invitation_fields {
    () => {
        "SELECT i.id,i.team_id,t.name AS team_name,i.email,i.role,i.invited_by,
            CAST(i.invited_at AS TEXT) AS invited_at,CAST(i.expires_at AS TEXT) AS expires_at,i.token,i.is_active
            FROM email_team_invitations i JOIN email_teams t ON t.id=i.team_id"
    };
}

macro_rules! join_fields {
    () => {
        "SELECT j.id,j.team_id,t.name AS team_name,j.user_email,j.message,j.status,
         CAST(j.requested_at AS TEXT) AS requested_at,CAST(j.expires_at AS TEXT) AS expires_at
         FROM email_team_join_requests j JOIN email_teams t ON t.id=j.team_id"
    };
}

pub(super) const INVITATION_BY_ID: &str =
    concat!(invitation_fields!(), " WHERE i.id=$1 AND t.is_active=TRUE");
const INVITATION_BY_TOKEN: &str = concat!(
    invitation_fields!(),
    " WHERE i.token=$1 AND i.is_active=TRUE AND t.is_active=TRUE"
);

macro_rules! insert_invite {
    ($tx:ident,$postgres:tt,$team:expr,$email:expr,$role:expr,$actor:expr,$settings:expr) => {{
        let team=&$team;
        let email=$email;
        let settings=$settings;
        if !settings.teams.allow_invitations {
            return Err(denied("Team invitations are currently disabled"));
        }
        if team.is_personal {
            return Err(AccountError::bad_request("Cannot send invitations to personal teams"));
        }
        let verified:Option<bool>=sqlx::query_scalar("SELECT email_verified_at IS NOT NULL FROM email_users WHERE email=$1")
            .bind(email).fetch_optional(observed(&mut *$tx)).await?;
        if settings.teams.verify_invite_email && verified==Some(false) {
            return Err(AccountError::bad_request("Invitee email address has not been verified"));
        }
        let member:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_team_members WHERE
            team_id=$1 AND user_email=$2 AND is_active=TRUE)")
            .bind(&team.id).bind(email).fetch_one(observed(&mut *$tx)).await?;
        if member {
            return Err(AccountError::bad_request(format!("User {email} is already a member of this team")));
        }
        let expire=if $postgres {
            "UPDATE email_team_invitations SET is_active=FALSE WHERE team_id=$1 AND is_active=TRUE AND expires_at<=CURRENT_TIMESTAMP"
        } else {
            "UPDATE email_team_invitations SET is_active=FALSE WHERE team_id=$1 AND is_active=TRUE AND julianday(expires_at)<=julianday(CURRENT_TIMESTAMP)"
        };
        sqlx::query(expire).bind(&team.id).execute(observed(&mut *$tx)).await?;
        let duplicate:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_team_invitations
            WHERE team_id=$1 AND email=$2 AND is_active=TRUE)")
            .bind(&team.id).bind(email).fetch_one(observed(&mut *$tx)).await?;
        if duplicate {
            return Err(AccountError::bad_request(format!("An active invitation already exists for {email}")));
        }
        let reserved:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM email_team_members m
            WHERE m.team_id=$1 AND m.is_active=TRUE) + (SELECT COUNT(*) FROM email_team_invitations i
            WHERE i.team_id=$1 AND i.is_active=TRUE)").bind(&team.id).fetch_one(observed(&mut *$tx)).await?;
        let maximum=team.max_members.unwrap_or(settings.teams.max_members);
        if reserved>=i64::from(maximum) {
            return Err(AccountError::bad_request(format!("Team has reached its member limit of {maximum}")));
        }
        let mut random=[0_u8;32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(),&mut random).map_err(|_|AccountError::unavailable())?;
        let token=base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        let id=Uuid::new_v4().simple().to_string();
        let insert=if $postgres {
            "INSERT INTO email_team_invitations(id,team_id,email,role,invited_by,invited_at,expires_at,token,is_active)
            VALUES($1,$2,$3,$4,$5,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+CAST($6 AS BIGINT)*INTERVAL '1 second',$7,TRUE)"
        } else {
            "INSERT INTO email_team_invitations(id,team_id,email,role,invited_by,invited_at,expires_at,token,is_active)
            VALUES($1,$2,$3,$4,$5,CURRENT_TIMESTAMP,datetime(CURRENT_TIMESTAMP,'+'||$6||' seconds'),$7,TRUE)"
        };
        sqlx::query(insert).bind(&id).bind(&team.id).bind(email).bind($role).bind($actor)
            .bind(settings.teams.expires_in_seconds).bind(token).execute(observed(&mut *$tx)).await?;
        sqlx::query_as::<_,Invitation>($crate::local_auth::teams::storage::participation::INVITATION_BY_ID).bind(id).fetch_one(observed(&mut *$tx)).await?
    }};
}

pub(super) use insert_invite;

fn elapsed(value: &str) -> bool {
    parse_timestamp(value).is_none_or(|date| date <= Timestamp::now())
}

fn missing_member() -> AccountError {
    AccountError::detail(StatusCode::NOT_FOUND, "Team member not found")
}

fn missing_invite() -> AccountError {
    AccountError::detail(StatusCode::NOT_FOUND, "Invitation not found")
}

fn missing_request() -> AccountError {
    AccountError::detail(
        StatusCode::NOT_FOUND,
        "Join request not found or already processed",
    )
}

impl Database {
    pub(in crate::local_auth::teams) async fn write_team_member(
        &self,
        id: &str,
        email: &str,
        actor: &str,
        operation: MemberMutation<'_>,
        settings: &AccountSettings,
    ) -> Result<Member, AccountError> {
        self.write_membership(
            id,
            email,
            actor,
            operation,
            &MemberSettings {
                teams: &settings.teams,
                provisioning: &settings.provisioning,
                sso_provider: None,
            },
        )
        .await
    }

    pub(in crate::local_auth) async fn sync_sso_memberships(
        &self,
        email: &str,
        provider: &str,
        desired: &BTreeMap<String, String>,
        teams: &TeamSettings,
        provisioning: &UserProvisioning,
    ) -> Result<(), sqlx::Error> {
        const SELECT: &str = "SELECT team_id FROM email_team_members WHERE user_email=$1
            AND is_active AND grant_source='sso' ORDER BY team_id";
        let existing: Vec<String> = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar(SELECT)
                    .bind(email)
                    .fetch_all(observed(pool))
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar(SELECT)
                    .bind(email)
                    .fetch_all(observed(pool))
                    .await?
            }
        };
        let options = MemberSettings {
            teams,
            provisioning,
            sso_provider: Some(provider),
        };
        for team in existing.iter().filter(|team| !desired.contains_key(*team)) {
            if let Err(error) = self
                .write_membership(team, email, email, MemberMutation::Remove, &options)
                .await
            {
                tracing::warn!(status=%error.0, "could not remove SSO team membership");
            }
        }
        for (team, role) in desired {
            if existing.contains(team) {
                continue;
            }
            if let Err(error) = self
                .write_membership(team, email, email, MemberMutation::Add(role), &options)
                .await
                && error.0 != StatusCode::CONFLICT
            {
                tracing::warn!(status=%error.0, "could not add SSO team membership");
            }
        }
        Ok(())
    }

    async fn write_membership(
        &self,
        id: &str,
        email: &str,
        actor: &str,
        operation: MemberMutation<'_>,
        settings: &MemberSettings<'_>,
    ) -> Result<Member, AccountError> {
        macro_rules! write {
            ($tx:ident,$postgres:tt) => {{
                let team:Team=sqlx::query_as(TEAM_DETAIL).bind(id).fetch_optional(observed(&mut *$tx)).await?.ok_or_else(missing_team)?;
                if let Some(provider) = settings.sso_provider {
                    let sql = if $postgres {
                        "SELECT id FROM email_users WHERE email=$1 AND auth_provider=$2 AND is_active FOR UPDATE"
                    } else {
                        "SELECT id FROM email_users WHERE email=$1 AND auth_provider=$2 AND is_active"
                    };
                    if sqlx::query_scalar::<_,String>(sql).bind(email).bind(provider)
                        .fetch_optional(observed(&mut *$tx)).await?.is_none() {
                        return Err(denied("SSO provider binding changed"));
                    }
                } else {
                    team_permission!($tx,id,actor, matches!(operation,MemberMutation::Remove) && actor==email);
                }
                if team.is_personal {
                    return Err(match operation {
                        MemberMutation::Add(_)=>AccountError::bad_request("Cannot add members to personal teams"),
                        _=>missing_member(),
                    });
                }
                let updated=match operation {
                    MemberMutation::Add(role)=>{
                        let user:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_users WHERE email=$1 AND is_active=TRUE)")
                            .bind(email).fetch_one(observed(&mut *$tx)).await?;
                        if !user {
                            return Err(AccountError::detail(StatusCode::NOT_FOUND,"User not found or inactive"));
                        }
                        let mut member = insert_member!($tx,team,email,role,Some(actor),actor,settings,false);
                        if settings.sso_provider.is_some() {
                            sqlx::query("UPDATE email_team_members SET grant_source='sso' WHERE id=$1")
                                .bind(&member.id).execute(observed(&mut *$tx)).await?;
                            member.grant_source = Some("sso".to_owned());
                        }
                        member
                    }
                    MemberMutation::Role(_) | MemberMutation::Remove=>{
                        let mut member:Member=sqlx::query_as(MEMBER_ANY_STATE).bind(id).bind(email)
                            .fetch_optional(observed(&mut *$tx)).await?.filter(|member:&Member|member.is_active).ok_or_else(missing_member)?;
                        if settings.sso_provider.is_some() && member.grant_source.as_deref()!=Some("sso") {
                            return Err(missing_member());
                        }
                        let role=match operation {MemberMutation::Role(role)=>Some(role),_=>None};
                        if member.role=="owner" && role!=Some("owner") {
                            let other_owner:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_team_members WHERE
                                team_id=$1 AND user_email<>$2 AND role='owner' AND is_active=TRUE)")
                                .bind(id).bind(email).fetch_one(observed(&mut *$tx)).await?;
                            if !other_owner {
                                return Err(AccountError::bad_request("Cannot remove the last owner from a team"));
                            }
                        }
                        if let Some(role)=role {
                            if member.role!=role {
                                sqlx::query("UPDATE email_team_members SET role=$2 WHERE id=$1")
                                    .bind(&member.id).bind(role).execute(observed(&mut *$tx)).await?;
                                role.clone_into(&mut member.role);
                                sync_member_role!($tx,member,actor,settings,true);
                                log_member!($tx,member,actor,"role-changed");
                            }
                        } else {
                            sqlx::query("UPDATE email_team_members SET is_active=FALSE WHERE id=$1")
                                .bind(&member.id).execute(observed(&mut *$tx)).await?;
                            member.is_active=false;
                            sync_member_role!($tx,member,actor,settings,false);
                            log_member!($tx,member,actor,"removed");
                            sqlx::query("INSERT INTO token_revocations(jti,revoked_at,revoked_by,reason,token_expiry)
                                SELECT jti,CURRENT_TIMESTAMP,$3,'team_membership_removed',expires_at
                                FROM email_api_tokens WHERE team_id=$1 AND user_email=$2 ON CONFLICT(jti) DO NOTHING")
                                .bind(id).bind(email).bind(actor).execute(observed(&mut *$tx)).await?;
                            sqlx::query("UPDATE email_api_tokens SET is_active=FALSE WHERE team_id=$1 AND user_email=$2")
                                .bind(id).bind(email).execute(observed(&mut *$tx)).await?;
                        }
                        member
                    }
                };
                $tx.commit().await?;
                Ok(updated)
            }};
        }
        team_transaction!(self, write)
    }

    pub(in crate::local_auth::teams) async fn managed_invitations(
        &self,
        id: &str,
    ) -> Result<Vec<Invitation>, sqlx::Error> {
        const SQL: &str = concat!(
            invitation_fields!(),
            " WHERE i.team_id=$1 AND i.is_active=TRUE AND t.is_active=TRUE ORDER BY i.invited_at DESC,i.id DESC"
        );
        match self {
            Self::Sqlite(pool) => sqlx::query_as(SQL).bind(id).fetch_all(observed(pool)).await,
            Self::Postgres(pool) => sqlx::query_as(SQL).bind(id).fetch_all(observed(pool)).await,
        }
    }

    pub(in crate::local_auth::teams) async fn managed_invitation(
        &self,
        id: &str,
    ) -> Result<Option<Invitation>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(INVITATION_BY_ID)
                    .bind(id)
                    .fetch_optional(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(INVITATION_BY_ID)
                    .bind(id)
                    .fetch_optional(observed(pool))
                    .await
            }
        }
    }

    pub(in crate::local_auth::teams) async fn create_team_invitation(
        &self,
        id: &str,
        email: &str,
        role: &str,
        actor: &str,
        settings: &AccountSettings,
    ) -> Result<Invitation, AccountError> {
        macro_rules! write {
            ($tx:ident,$postgres:tt) => {{
                let team: Team = sqlx::query_as(TEAM_DETAIL)
                    .bind(id)
                    .fetch_optional(observed(&mut *$tx))
                    .await?
                    .ok_or_else(missing_team)?;
                team_permission!($tx, id, actor, false);
                let invitation = insert_invite!($tx, $postgres, team, email, role, actor, settings);
                $tx.commit().await?;
                Ok(invitation)
            }};
        }
        team_transaction!(self, write)
    }

    pub(in crate::local_auth::teams) async fn accept_team_invitation(
        &self,
        token: &str,
        email: &str,
        settings: &AccountSettings,
    ) -> Result<Member, AccountError> {
        macro_rules! accept {
            ($tx:ident,$postgres:tt) => {{
                let invite:Invitation=sqlx::query_as(INVITATION_BY_TOKEN).bind(token).fetch_optional(observed(&mut *$tx)).await?
                    .filter(|invite:&Invitation|!invite.expired()).ok_or_else(||AccountError::bad_request("Invitation is invalid or expired"))?;
                if invite.email!=email {
                    return Err(AccountError::bad_request("Email address does not match invitation"));
                }
                let verified:Option<bool>=sqlx::query_scalar("SELECT email_verified_at IS NOT NULL FROM email_users WHERE email=$1 AND is_active=TRUE")
                    .bind(email).fetch_optional(observed(&mut *$tx)).await?;
                match verified {
                    None=>return Err(AccountError::bad_request("User account not found")),
                    Some(false) if settings.teams.verify_invite_email=>return Err(AccountError::bad_request("Email address has not been verified")),
                    Some(_)=>{}
                }
                let team:Team=sqlx::query_as(TEAM_DETAIL).bind(&invite.team_id).fetch_optional(observed(&mut *$tx)).await?.ok_or_else(missing_team)?;
                if team.is_personal {
                    return Err(AccountError::bad_request("Cannot join a personal team"));
                }
                let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_team_members
                    WHERE team_id=$1 AND user_email=$2 AND is_active=TRUE)")
                    .bind(&team.id).bind(email).fetch_one(observed(&mut *$tx)).await?;
                sqlx::query("UPDATE email_team_invitations SET is_active=FALSE WHERE id=$1")
                    .bind(&invite.id).execute(observed(&mut *$tx)).await?;
                if active {
                    $tx.commit().await?;
                    return Err(AccountError::bad_request("User is already a member of this team"));
                }
                let member=insert_member!($tx,team,email,&invite.role,Some(&invite.invited_by),&invite.invited_by,settings,false);
                $tx.commit().await?;
                Ok(member)
            }};
        }
        team_transaction!(self, accept)
    }

    pub(in crate::local_auth::teams) async fn decline_team_invitation(
        &self,
        token: &str,
        email: &str,
    ) -> Result<(), AccountError> {
        macro_rules! decline {
            ($tx:ident,$postgres:tt) => {{
                let invite: Invitation = sqlx::query_as(INVITATION_BY_TOKEN)
                    .bind(token)
                    .fetch_optional(observed(&mut *$tx))
                    .await?
                    .ok_or_else(missing_invite)?;
                if invite.email != email {
                    return Err(denied("Access denied"));
                }
                sqlx::query("UPDATE email_team_invitations SET is_active=FALSE WHERE id=$1")
                    .bind(invite.id)
                    .execute(observed(&mut *$tx))
                    .await?;
                $tx.commit().await?;
                Ok(())
            }};
        }
        team_transaction!(self, decline)
    }

    pub(in crate::local_auth::teams) async fn cancel_team_invitation(
        &self,
        id: &str,
        actor: &str,
    ) -> Result<(), AccountError> {
        macro_rules! cancel {
            ($tx:ident,$postgres:tt) => {{
                let invite: Invitation = sqlx::query_as(INVITATION_BY_ID)
                    .bind(id)
                    .fetch_optional(observed(&mut *$tx))
                    .await?
                    .filter(|invite: &Invitation| invite.is_active)
                    .ok_or_else(missing_invite)?;
                team_permission!($tx, &invite.team_id, actor, invite.invited_by == actor);
                sqlx::query("UPDATE email_team_invitations SET is_active=FALSE WHERE id=$1")
                    .bind(id)
                    .execute(observed(&mut *$tx))
                    .await?;
                $tx.commit().await?;
                Ok(())
            }};
        }
        team_transaction!(self, cancel)
    }

    pub(in crate::local_auth::teams) async fn request_team_membership(
        &self,
        id: &str,
        email: &str,
        message: Option<&str>,
        settings: &TeamSettings,
        reopen_expired: bool,
    ) -> Result<(JoinRequest, bool), AccountError> {
        macro_rules! request {
            ($tx:ident,$postgres:tt) => {{
                let team:Team=sqlx::query_as(TEAM_DETAIL).bind(id).fetch_optional(observed(&mut *$tx)).await?.ok_or_else(missing_team)?;
                if team.visibility!="public" || team.is_personal {
                    return Err(denied("Can only request to join public teams"));
                }
                let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_team_members m
                    WHERE m.team_id=$1 AND m.user_email=$2 AND m.is_active=TRUE)")
                    .bind(id).bind(email).fetch_one(observed(&mut *$tx)).await?;
                if active {
                    return Err(AccountError::bad_request("User is already a member of this team"));
                }
                let teams:i64=sqlx::query_scalar("SELECT COUNT(*) FROM email_team_members m JOIN email_teams t ON t.id=m.team_id
                    WHERE m.user_email=$1 AND m.is_active=TRUE AND t.is_active=TRUE")
                    .bind(email).fetch_one(observed(&mut *$tx)).await?;
                if teams>=settings.max_teams {
                    return Err(AccountError::bad_request(format!("User has reached the maximum team limit of {}",settings.max_teams)));
                }
                let prior:Option<JoinRequest>=sqlx::query_as(concat!(join_fields!(),
                    " WHERE j.team_id=$1 AND j.user_email=$2 AND j.status='pending'"))
                    .bind(id).bind(email).fetch_optional(observed(&mut *$tx)).await?;
                if let Some(prior) = prior && (!reopen_expired || !prior.expired()) {
                    $tx.commit().await?;
                    return Ok((prior, false));
                }
                let command=if $postgres {
                    "INSERT INTO email_team_join_requests(id,team_id,user_email,message,status,requested_at,expires_at)
                    VALUES($1,$2,$3,$4,'pending',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP+INTERVAL '7 days')
                    ON CONFLICT(team_id,user_email) DO UPDATE SET message=excluded.message,status='pending',requested_at=excluded.requested_at,
                        expires_at=excluded.expires_at,reviewed_at=NULL,reviewed_by=NULL,notes=NULL RETURNING id"
                } else {
                    "INSERT INTO email_team_join_requests(id,team_id,user_email,message,status,requested_at,expires_at)
                    VALUES($1,$2,$3,$4,'pending',CURRENT_TIMESTAMP,datetime(CURRENT_TIMESTAMP,'+7 days'))
                    ON CONFLICT(team_id,user_email) DO UPDATE SET message=excluded.message,status='pending',requested_at=excluded.requested_at,
                        expires_at=excluded.expires_at,reviewed_at=NULL,reviewed_by=NULL,notes=NULL RETURNING id"
                };
                let request:String=sqlx::query_scalar(command).bind(Uuid::new_v4().simple().to_string())
                    .bind(id).bind(email).bind(message).fetch_one(observed(&mut *$tx)).await?;
                let row=sqlx::query_as(concat!(join_fields!()," WHERE j.id=$1"))
                    .bind(request).fetch_one(observed(&mut *$tx)).await?;
                $tx.commit().await?;
                Ok((row, true))
            }};
        }
        team_transaction!(self, request)
    }

    pub(in crate::local_auth::teams) async fn cancel_team_join_request(
        &self,
        team: &str,
        request: &str,
        email: &str,
    ) -> Result<(), AccountError> {
        macro_rules! cancel {
            ($tx:ident,$postgres:tt) => {{
                let changed = sqlx::query(
                    "UPDATE email_team_join_requests
                    SET status='cancelled',reviewed_at=CURRENT_TIMESTAMP,reviewed_by=$3
                    WHERE id=$1 AND team_id=$2 AND user_email=$3 AND status='pending'",
                )
                .bind(request)
                .bind(team)
                .bind(email)
                .execute(observed(&mut *$tx))
                .await?
                .rows_affected();
                if changed == 0 {
                    return Err(AccountError::detail(
                        StatusCode::NOT_FOUND,
                        "Join request not found or unavailable",
                    ));
                }
                $tx.commit().await?;
                Ok(())
            }};
        }
        team_transaction!(self, cancel)
    }

    pub(in crate::local_auth::teams) async fn team_join_requests(
        &self,
        id: &str,
    ) -> Result<Vec<JoinRequest>, sqlx::Error> {
        const SQL: &str = concat!(
            join_fields!(),
            " WHERE j.team_id=$1 AND j.status='pending' AND t.is_active=TRUE
            ORDER BY j.requested_at DESC,j.id DESC"
        );
        match self {
            Self::Sqlite(pool) => sqlx::query_as(SQL).bind(id).fetch_all(observed(pool)).await,
            Self::Postgres(pool) => sqlx::query_as(SQL).bind(id).fetch_all(observed(pool)).await,
        }
    }

    pub(in crate::local_auth::teams) async fn review_team_membership(
        &self,
        id: &str,
        request: &str,
        actor: &str,
        approve: bool,
        settings: &AccountSettings,
    ) -> Result<Option<Member>, AccountError> {
        macro_rules! review {
            ($tx:ident,$postgres:tt) => {{
                let team:Team=sqlx::query_as(TEAM_DETAIL).bind(id).fetch_optional(observed(&mut *$tx)).await?.ok_or_else(missing_team)?;
                team_permission!($tx,id,actor,false);
                let row:JoinRequest=sqlx::query_as(concat!(join_fields!()," WHERE j.id=$1 AND j.team_id=$2 AND j.status='pending'"))
                    .bind(request).bind(id).fetch_optional(observed(&mut *$tx)).await?.ok_or_else(missing_request)?;
                if approve && row.expired() {
                    return Err(AccountError::bad_request("Join request has expired"));
                }
                let member=if approve {
                    let active:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_users WHERE email=$1 AND is_active=TRUE)")
                        .bind(&row.user_email).fetch_one(observed(&mut *$tx)).await?;
                    if !active {
                        return Err(AccountError::bad_request("User account not found"));
                    }
                    Some(insert_member!($tx,team,&row.user_email,"member",Some(actor),actor,settings,false))
                } else {
                    None
                };
                sqlx::query("UPDATE email_team_join_requests SET status=$2,reviewed_at=CURRENT_TIMESTAMP,reviewed_by=$3 WHERE id=$1")
                    .bind(request).bind(if approve {"approved"} else {"rejected"}).bind(actor).execute(observed(&mut *$tx)).await?;
                $tx.commit().await?;
                Ok(member)
            }};
        }
        team_transaction!(self, review)
    }
}
