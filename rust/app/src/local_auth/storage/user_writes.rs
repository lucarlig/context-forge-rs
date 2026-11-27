// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::local_auth::user_lifecycle::UserPatch;

pub(in crate::local_auth) struct CredentialChange<'a> {
    pub(in crate::local_auth) hash: &'a str,
    pub(in crate::local_auth) reason: &'static str,
    pub(in crate::local_auth) reset_token: Option<&'a str>,
}

const REVOKE_LOCAL_SESSIONS: &str = "INSERT INTO token_revocations
    (jti,revoked_at,revoked_by,reason,token_expiry)
    SELECT jti,CURRENT_TIMESTAMP,$2,$3,expires_at FROM cf_local_sessions WHERE user_email=$1
    ON CONFLICT(jti) DO NOTHING";

const REVOKE_LOCAL_API_TOKENS: &str = "INSERT INTO token_revocations
    (jti,revoked_at,revoked_by,reason,token_expiry)
    SELECT jti,CURRENT_TIMESTAMP,$2,$3,expires_at FROM email_api_tokens WHERE user_email=$1
    ON CONFLICT(jti) DO NOTHING";

macro_rules! revoke_credentials {
    ($tx:ident,$email:expr,$actor:expr,$reason:expr) => {{
        for statement in [REVOKE_LOCAL_SESSIONS, REVOKE_LOCAL_API_TOKENS] {
            sqlx::query(statement)
                .bind($email)
                .bind($actor)
                .bind($reason)
                .execute(&mut *$tx)
                .await?;
        }
        sqlx::query(
            "UPDATE email_api_tokens SET is_active=FALSE WHERE user_email=$1 AND is_active=TRUE",
        )
        .bind($email)
        .execute(&mut *$tx)
        .await?;
        sqlx::query("DELETE FROM cf_local_sessions WHERE user_email=$1")
            .bind($email)
            .execute(&mut *$tx)
            .await?;
    }};
}

impl Database {
    pub(in crate::local_auth) async fn local_password_history(
        &self,
        email: &str,
        count: u32,
    ) -> Result<Vec<String>, sqlx::Error> {
        macro_rules! select {
            ($pool:ident) => {
                sqlx::query_scalar(
                    "SELECT password_hash FROM password_history WHERE user_email=$1
                    ORDER BY changed_at DESC,id DESC LIMIT $2",
                )
                .bind(email)
                .bind(i64::from(count))
                .fetch_all($pool)
                .await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool),
            Self::Postgres(pool) => select!(pool),
        }
    }

    pub(in crate::local_auth) async fn edit_local_user(
        &self,
        before: &LocalUser,
        patch: &UserPatch,
        credential: Option<CredentialChange<'_>>,
        actor: &str,
        settings: &AccountSettings,
    ) -> Result<LocalUser, AccountError> {
        let email = &before.email;
        let new_hash = credential.as_ref().map(|credential| credential.hash);
        let reset_token = credential
            .as_ref()
            .and_then(|credential| credential.reset_token);
        let change = patch.password_change_required.or(new_hash.map(|_| false));
        macro_rules! edit {
            ($tx:ident,$lock:literal,$history_limit:literal,$not_expired:literal) => {{
                let current:LocalUser = sqlx::query_as(concat!(
                    "SELECT ",local_user_fields!()," FROM email_users WHERE email=$1 ",$lock))
                    .bind(email).fetch_optional(&mut *$tx).await?.ok_or_else(AccountError::missing)?;
                if let Some(hash)=reset_token {
                    let updated=sqlx::query(concat!("UPDATE password_reset_tokens SET used_at=CURRENT_TIMESTAMP
                        WHERE token_hash=$1 AND user_email=$2 AND used_at IS NULL AND ",$not_expired))
                        .bind(hash).bind(email).execute(&mut *$tx).await?;
                    if updated.rows_affected()==0 {
                        let expiry:Option<String>=sqlx::query_scalar("SELECT CAST(expires_at AS TEXT)
                            FROM password_reset_tokens WHERE token_hash=$1 AND user_email=$2 AND used_at IS NULL")
                            .bind(hash).bind(email).fetch_optional(&mut *$tx).await?;
                        return Err(if expiry.as_deref().and_then(parse_timestamp)
                            .is_some_and(|expires|expires<=Timestamp::now()) { password_reset::expired() } else { password_reset::invalid() });
                    }
                }
                if current.id!=before.id
                    || new_hash.is_some() && (before.password_hash!=current.password_hash
                        || before.is_admin!=current.is_admin || before.is_active!=current.is_active)
                {
                    return Err(AccountError::detail(StatusCode::CONFLICT,"Account changed during the request"));
                }
                let admin=patch.is_admin.unwrap_or(current.is_admin);
                let active=patch.is_active.unwrap_or(current.is_active);
                if current.is_active && current.is_admin && (!admin || !active) {
                    if email==actor {
                        return Err(AccountError::bad_request("Administrators cannot demote or deactivate their own account"));
                    }
                    let others:i64=sqlx::query_scalar("SELECT COUNT(*) FROM email_users
                        WHERE is_admin=TRUE AND is_active=TRUE AND email<>$1")
                        .bind(email).fetch_one(&mut *$tx).await?;
                    if others==0 {
                        return Err(AccountError::bad_request("Cannot demote or deactivate the last remaining active admin user"));
                    }
                }
                if let Some(prior_hash)=current.password_hash.as_deref().filter(|_|new_hash.is_some()) {
                    sqlx::query("INSERT INTO password_history(id,user_email,password_hash,changed_at)
                        VALUES($1,$2,$3,CURRENT_TIMESTAMP)")
                        .bind(Uuid::new_v4().to_string()).bind(email).bind(prior_hash)
                        .execute(&mut *$tx).await?;
                    sqlx::query(concat!("DELETE FROM password_history WHERE id IN
                        (SELECT id FROM password_history WHERE user_email=$1 ORDER BY changed_at DESC,id DESC ",
                        $history_limit," OFFSET $2)"))
                        .bind(email).bind(i64::from(settings.password_history)).execute(&mut *$tx).await?;
                }
                let updated:LocalUser=sqlx::query_as(concat!(
                    "UPDATE email_users SET full_name=COALESCE($2,full_name),is_admin=$3,is_active=$4,
                      email_verified_at=CASE WHEN $5 THEN CURRENT_TIMESTAMP WHEN NOT $5 THEN NULL ELSE email_verified_at END,
                      password_change_required=COALESCE($6,password_change_required),
                      password_hash=COALESCE($7,password_hash),
                      password_changed_at=CASE WHEN CAST($7 AS TEXT) IS NULL THEN password_changed_at ELSE CURRENT_TIMESTAMP END,
                      password_hash_type=CASE WHEN CAST($7 AS TEXT) IS NULL THEN password_hash_type ELSE 'argon2id' END,
                      locked_until=CASE WHEN $8 THEN NULL ELSE locked_until END,
                      failed_login_attempts=CASE WHEN $8 THEN 0 ELSE failed_login_attempts END,
                      admin_origin=CASE WHEN $3 AND NOT is_admin THEN 'api' WHEN NOT $3 THEN NULL ELSE admin_origin END,
                      updated_at=CURRENT_TIMESTAMP WHERE email=$1 RETURNING ",local_user_fields!()))
                    .bind(email).bind(patch.full_name.as_deref()).bind(admin).bind(active)
                    .bind(patch.email_verified).bind(change).bind(new_hash).bind(reset_token.is_some()).fetch_one(&mut *$tx).await?;
                if new_hash.is_some() || current.is_active && !active {
                    sqlx::query("UPDATE password_reset_tokens SET used_at=CURRENT_TIMESTAMP
                        WHERE user_email=$1 AND used_at IS NULL")
                        .bind(email).execute(&mut *$tx).await?;
                }
                let privilege_changed=current.is_admin!=admin;
                if privilege_changed {
                    let (old,new)=if admin {(&settings.user_role,&settings.admin_role)}
                        else {(&settings.admin_role,&settings.user_role)};
                    sqlx::query("UPDATE user_roles SET is_active=FALSE WHERE user_email=$1
                        AND scope='global' AND scope_id IS NULL AND role_id IN
                        (SELECT id FROM roles WHERE scope='global' AND name=$2)")
                        .bind(email).bind(old).execute(&mut *$tx).await?;
                    sqlx::query(USE_ROLE).bind(Uuid::new_v4().to_string()).bind(email)
                        .bind(None::<&str>).bind(actor).bind(new).bind("global")
                        .execute(&mut *$tx).await?;
                }
                let revoke=if privilege_changed {
                    Some("account_privileges_changed")
                } else if current.is_active && !active {
                    Some("account_disabled")
                } else {
                    credential.as_ref().filter(|_|settings.invalidate_sessions).map(|credential|credential.reason)
                };
                if let Some(reason)=revoke {
                    revoke_credentials!($tx,email,actor,reason);
                }
                $tx.commit().await?;
                Ok(updated)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                edit!(
                    tx,
                    "",
                    "LIMIT -1",
                    "julianday(expires_at)>julianday(CURRENT_TIMESTAMP)"
                )
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682073)")
                    .execute(&mut *tx)
                    .await?;
                edit!(tx, "FOR UPDATE", "", "expires_at>clock_timestamp()")
            }
        }
    }

    pub(in crate::local_auth) async fn unlock_local_user(
        &self,
        email: &str,
    ) -> Result<bool, AccountError> {
        macro_rules! unlock {
            ($tx:ident) => {{
                let changed = sqlx::query(
                    "UPDATE email_users SET failed_login_attempts=0,locked_until=NULL,
                    updated_at=CURRENT_TIMESTAMP WHERE email=$1",
                )
                .bind(email)
                .execute(&mut *$tx)
                .await?
                .rows_affected()
                    != 0;
                if changed {
                    sqlx::query(
                        "INSERT INTO email_auth_events(timestamp,user_email,event_type,success)
                       VALUES(CURRENT_TIMESTAMP,$1,'ACCOUNT_UNLOCKED',TRUE)",
                    )
                    .bind(email)
                    .execute(&mut *$tx)
                    .await?;
                }
                $tx.commit().await?;
                Ok(changed)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                unlock!(tx)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                unlock!(tx)
            }
        }
    }
}

impl Database {
    pub(in crate::local_auth) async fn delete_local_user(
        &self,
        email: &str,
        actor: &str,
        platform_admin: &str,
    ) -> Result<(), AccountError> {
        macro_rules! delete {
            ($tx:ident,$lock:literal) => {{
                let Some((admin,active))=sqlx::query_as::<_,(bool,bool)>(concat!(
                    "SELECT is_admin,is_active FROM email_users WHERE email=$1 ",$lock))
                    .bind(email).fetch_optional(&mut *$tx).await? else {
                    return Err(AccountError::detail(StatusCode::NOT_FOUND,format!("User {email} not found")));
                };
                if admin && active {
                    let others:i64=sqlx::query_scalar("SELECT COUNT(*) FROM email_users WHERE is_admin=TRUE
                        AND is_active=TRUE AND email<>$1").bind(email).fetch_one(&mut *$tx).await?;
                    if others==0 {
                        return Err(AccountError::bad_request("Cannot delete the last remaining admin user"));
                    }
                }
                let teams=sqlx::query_as::<_,(String,String)>(concat!(
                    "SELECT id,name FROM email_teams WHERE created_by=$1 ORDER BY id ",$lock))
                    .bind(email).fetch_all(&mut *$tx).await?;
                for (id,name) in teams {
                    let alternate:Option<String>=sqlx::query_scalar("SELECT m.user_email FROM email_team_members m
                        JOIN email_users u ON u.email=m.user_email AND u.is_active=TRUE
                        WHERE m.team_id=$1 AND m.user_email<>$2 AND m.is_active=TRUE AND m.role='owner'
                        ORDER BY m.user_email LIMIT 1").bind(&id).bind(email).fetch_optional(&mut *$tx).await?;
                    if let Some(owner)=alternate {
                        sqlx::query("UPDATE email_teams SET created_by=$2,updated_at=CURRENT_TIMESTAMP WHERE id=$1")
                            .bind(&id).bind(owner).execute(&mut *$tx).await?;
                        continue;
                    }
                    let members=sqlx::query_scalar::<_,String>("SELECT user_email FROM email_team_members WHERE team_id=$1")
                        .bind(&id).fetch_all(&mut *$tx).await?;
                    if !matches!(members.as_slice(),[owner] if owner==email) {
                        return Err(AccountError::detail(StatusCode::CONFLICT,format!(
                            "Cannot delete user {email}: owns team '{name}' with {} members but no other owners to transfer ownership to",
                            members.len())));
                    }
                    for command in [
                        "DELETE FROM email_team_member_history WHERE team_id=$1",
                        "DELETE FROM email_team_join_requests WHERE team_id=$1",
                        "DELETE FROM email_team_invitations WHERE team_id=$1",
                        "DELETE FROM email_team_members WHERE team_id=$1",
                        "DELETE FROM email_teams WHERE id=$1",
                    ] {
                        sqlx::query(command).bind(&id).execute(&mut *$tx).await?;
                    }
                }
                let gateways=sqlx::query_as::<_,(String,Option<String>,String)>(concat!(
                    "SELECT id,team_id,visibility FROM gateways WHERE owner_email=$1 ORDER BY id ",$lock))
                    .bind(email).fetch_all(&mut *$tx).await?;
                let fallback:Option<String>=sqlx::query_scalar("SELECT email FROM email_users
                    WHERE email=$1 AND is_active=TRUE AND email<>$2")
                    .bind(platform_admin.trim().to_ascii_lowercase()).bind(email).fetch_optional(&mut *$tx).await?;
                for (id,team,visibility) in gateways {
                    let mut replacement=fallback.clone();
                    if let Some(team)=team.filter(|_|visibility=="team") {
                        let member:Option<String>=sqlx::query_scalar("SELECT m.user_email FROM email_team_members m
                            JOIN email_users u ON u.email=m.user_email AND u.is_active=TRUE
                            WHERE m.team_id=$1 AND m.user_email<>$2 AND m.is_active=TRUE ORDER BY m.user_email LIMIT 1")
                            .bind(team).bind(email).fetch_optional(&mut *$tx).await?;
                        replacement=member.or(replacement);
                    }
                    let Some(owner)=replacement else {
                        return Err(AccountError::detail(StatusCode::CONFLICT,format!(
                            "Cannot delete user {email}: gateway {id} would become orphaned and no fallback owner is available")));
                    };
                    sqlx::query("UPDATE gateways SET owner_email=$2 WHERE id=$1")
                        .bind(&id).bind(&owner).execute(&mut *$tx).await?;
                    for command in [
                        "UPDATE tools SET owner_email=$3 WHERE gateway_id=$1 AND owner_email=$2",
                        "UPDATE resources SET owner_email=$3 WHERE gateway_id=$1 AND owner_email=$2",
                        "UPDATE prompts SET owner_email=$3 WHERE gateway_id=$1 AND owner_email=$2",
                    ] {
                        sqlx::query(command).bind(&id).bind(email).bind(&owner).execute(&mut *$tx).await?;
                    }
                }
                revoke_credentials!($tx,email,actor,"account_deleted");
                for command in [
                    "DELETE FROM email_team_member_history WHERE user_email=$1",
                    "UPDATE email_team_member_history SET action_by=NULL WHERE action_by=$1",
                    "UPDATE email_team_members SET invited_by=NULL WHERE invited_by=$1",
                    "DELETE FROM email_team_members WHERE user_email=$1",
                    "DELETE FROM email_team_join_requests WHERE user_email=$1",
                    "UPDATE email_team_join_requests SET reviewed_by=NULL WHERE reviewed_by=$1",
                    "DELETE FROM user_roles WHERE user_email=$1",
                    "DELETE FROM email_api_tokens WHERE user_email=$1",
                    "DELETE FROM password_history WHERE user_email=$1",
                    "DELETE FROM password_reset_tokens WHERE user_email=$1",
                    "DELETE FROM email_auth_events WHERE user_email=$1",
                ] {
                    sqlx::query(command).bind(email).execute(&mut *$tx).await?;
                }
                for command in [
                    "UPDATE email_team_invitations SET invited_by=$2 WHERE invited_by=$1",
                    "UPDATE roles SET created_by=$2 WHERE created_by=$1",
                    "UPDATE user_roles SET granted_by=$2 WHERE granted_by=$1",
                    "UPDATE token_revocations SET revoked_by=$2 WHERE revoked_by=$1",
                    "UPDATE tools SET owner_email=$2 WHERE owner_email=$1",
                    "UPDATE resources SET owner_email=$2 WHERE owner_email=$1",
                    "UPDATE prompts SET owner_email=$2 WHERE owner_email=$1",
                    "UPDATE servers SET owner_email=$2 WHERE owner_email=$1",
                ] {
                    sqlx::query(command).bind(email).bind(actor).execute(&mut *$tx).await?;
                }
                sqlx::query("DELETE FROM email_users WHERE email=$1").bind(email)
                    .execute(&mut *$tx).await.map_err(|error| {
                        if error.as_database_error().is_some_and(sqlx::error::DatabaseError::is_foreign_key_violation) {
                            AccountError::detail(StatusCode::CONFLICT,"Cannot delete user due to existing references")
                        } else {
                            error.into()
                        }
                    })?;
                $tx.commit().await?;
                Ok(())
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                delete!(tx, "")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682073)")
                    .execute(&mut *tx)
                    .await?;
                delete!(tx, "FOR UPDATE")
            }
        }
    }
}
