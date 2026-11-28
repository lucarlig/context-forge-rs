// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::database::observed;

#[derive(sqlx::FromRow)]
pub(super) struct Role {
    id: String,
    name: String,
    description: Option<String>,
    scope: String,
    permissions: String,
    inherits_from: Option<String>,
    created_by: String,
    is_system_role: bool,
    is_active: bool,
    created_at: String,
    updated_at: String,
}

impl Role {
    pub(super) fn metadata(&self) -> Value {
        let permissions =
            serde_json::from_str::<Value>(&self.permissions).unwrap_or_else(|_| json!([]));
        json!({
            "id":self.id, "name":self.name, "description":self.description, "scope":self.scope,
            "permissions":permissions, "inherits_from":self.inherits_from, "effective_permissions":null,
            "created_by":self.created_by, "is_system_role":self.is_system_role, "is_active":self.is_active,
            "created_at":self.created_at.replacen(' ',"T",1), "updated_at":self.updated_at.replacen(' ',"T",1),
        })
    }
}

#[derive(Serialize, sqlx::FromRow)]
pub(super) struct Assignment {
    id: String,
    user_email: String,
    role_id: String,
    role_name: Option<String>,
    scope: String,
    scope_id: Option<String>,
    granted_by: String,
    granted_at: String,
    expires_at: Option<String>,
    is_active: bool,
    grant_source: Option<String>,
}

impl Assignment {
    fn format_timestamps(mut self) -> Self {
        self.granted_at = self.granted_at.replacen(' ', "T", 1);
        self.expires_at = self.expires_at.map(|time| time.replacen(' ', "T", 1));
        self
    }
}

macro_rules! role_columns {
    () => {
        "id,name,description,scope,CAST(permissions AS TEXT) AS permissions,inherits_from,
         created_by,is_system_role,is_active, CAST(created_at AS TEXT) AS created_at,
         CAST(updated_at AS TEXT) AS updated_at"
    };
}

const ROLE_BY_ID: &str = concat!("SELECT ", role_columns!(), " FROM roles WHERE id=$1");

const ROLE_NAME_CONFLICT: &str = "SELECT EXISTS(SELECT 1 FROM roles WHERE scope=$1 AND name=$2
    AND id<>$3 AND is_active=TRUE)";

macro_rules! check_parent {
    ($tx:ident,$checking:expr,$parent:expr) => {
        if let Some(parent) = $parent {
            let (exists,cycle)=sqlx::query_as::<_,(bool,bool)>("WITH RECURSIVE parents(id,parent) AS (
                SELECT id,inherits_from FROM roles WHERE id=$1
                UNION
                SELECT r.id,r.inherits_from FROM roles r JOIN parents p ON r.id=p.parent
                ) SELECT EXISTS(SELECT 1 FROM parents), EXISTS(SELECT 1 FROM parents WHERE id=$2)")
                .bind(parent).bind($checking).fetch_one(observed(&mut *$tx)).await?;
            if !exists || cycle {
                return Err(invalid());
            }
        }
    };
}

impl Database {
    pub(super) async fn rbac_roles(
        &self,
        scope: Option<&str>,
        active: bool,
    ) -> Result<Vec<Role>, sqlx::Error> {
        macro_rules! select {
            ($pool:ident) => {
                sqlx::query_as(concat!("SELECT ",role_columns!()," FROM roles
                    WHERE (CAST($1 AS TEXT) IS NULL OR scope=$1) AND (NOT $2 OR is_active=TRUE)
                    ORDER BY scope,name,id")).bind(scope).bind(active).fetch_all(observed($pool)).await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool),
            Self::Postgres(pool) => select!(pool),
        }
    }

    pub(super) async fn rbac_role(&self, id: &str) -> Result<Option<Role>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(ROLE_BY_ID)
                    .bind(id)
                    .fetch_optional(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(ROLE_BY_ID)
                    .bind(id)
                    .fetch_optional(observed(pool))
                    .await
            }
        }
    }

    pub(super) async fn create_rbac_role(
        &self,
        input: &RoleCreate,
        actor: &str,
    ) -> Result<Role, AccountError> {
        let id = Uuid::new_v4().to_string();
        let parent = input.inherits_from.as_deref().filter(|id| !id.is_empty());
        let permissions = json!(input.permissions).to_string();
        macro_rules! create {
            ($tx:ident,$permissions:literal) => {{
                let conflict:bool=sqlx::query_scalar(ROLE_NAME_CONFLICT).bind(&input.scope).bind(&input.name)
                    .bind(&id).fetch_one(observed(&mut *$tx)).await?;
                if conflict {
                    return Err(invalid());
                }
                check_parent!($tx,&id,parent);
                let role = sqlx::query_as(concat!(
                    "INSERT INTO roles(id,name,description,scope,permissions,inherits_from,created_by,
                        is_system_role,is_active,created_at,updated_at)
                    VALUES($1,$2,$3,$4,",$permissions,",$6,$7,$8,TRUE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
                    RETURNING ",role_columns!()))
                    .bind(id).bind(&input.name).bind(input.description.as_deref()).bind(&input.scope)
                    .bind(permissions).bind(parent).bind(actor).bind(input.is_system_role)
                    .fetch_one(observed(&mut *$tx)).await.map_err(role_write_error)?;
                $tx.commit().await?;
                Ok(role)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                create!(tx, "json($5)")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682073)")
                    .execute(observed(&mut *tx))
                    .await?;
                create!(tx, "CAST(CAST($5 AS TEXT) AS JSON)")
            }
        }
    }

    pub(super) async fn change_rbac_role(
        &self,
        id: &str,
        input: &RoleEdit,
    ) -> Result<Role, AccountError> {
        macro_rules! edit {
            ($tx:ident,$permissions:literal,$lock:literal) => {{
                let before:Role=sqlx::query_as(concat!("SELECT ",role_columns!()," FROM roles WHERE id=$1 ",$lock))
                    .bind(id).fetch_optional(observed(&mut *$tx)).await?.ok_or_else(role_missing)?;
                if before.is_system_role {
                    return Err(invalid());
                }
                let name=input.name.as_deref().unwrap_or(&before.name);
                if let Some(permissions)=input.permissions.as_deref() {
                    validate_role(name,&before.scope,permissions)?;
                } else {
                    validate_role(name,&before.scope,&[])?;
                }
                if (before.name!=name || input.is_active==Some(true)) && sqlx::query_scalar::<_,bool>(ROLE_NAME_CONFLICT)
                    .bind(&before.scope).bind(name).bind(id).fetch_one(observed(&mut *$tx)).await?
                {
                    return Err(invalid());
                }
                let parent=input.inherits_from.as_deref().or(before.inherits_from.as_deref()).filter(|id|!id.is_empty());
                if input.inherits_from.is_some() {
                    check_parent!($tx,id,parent);
                }
                let permissions=input.permissions.as_ref().map(|values|json!(values).to_string());
                let role=sqlx::query_as(concat!(
                    "UPDATE roles SET name=$2,description=COALESCE($3,description),permissions=COALESCE(",$permissions,
                    ",permissions),inherits_from=$5,is_active=COALESCE($6,is_active),updated_at=CURRENT_TIMESTAMP WHERE id=$1
                    RETURNING ",role_columns!()))
                    .bind(id).bind(name).bind(input.description.as_deref()).bind(permissions)
                    .bind(parent).bind(input.is_active).fetch_one(observed(&mut *$tx)).await.map_err(role_write_error)?;
                $tx.commit().await?;
                Ok(role)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                edit!(tx, "json($4)", "")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682073)")
                    .execute(observed(&mut *tx))
                    .await?;
                edit!(tx, "CAST(CAST($4 AS TEXT) AS JSON)", "FOR UPDATE")
            }
        }
    }

    pub(super) async fn rbac_assignments(
        &self,
        user: &str,
        scope: Option<&str>,
        team: Option<&str>,
        include_expired: bool,
    ) -> Result<Vec<Assignment>, sqlx::Error> {
        macro_rules! select {
            ($pool:ident,$unexpired:literal) => {
                sqlx::query_as::<_,Assignment>(concat!(
                  "SELECT u.id,u.user_email,u.role_id,CAST(NULL AS TEXT) AS role_name,u.scope,u.scope_id,
                    u.granted_by,CAST(u.granted_at AS TEXT) AS granted_at,CAST(u.expires_at AS TEXT) AS expires_at,
                    u.is_active,u.grant_source FROM user_roles u JOIN roles r ON r.id=u.role_id
                    WHERE u.user_email=$1 AND u.is_active=TRUE AND r.is_active=TRUE
                      AND (CAST($2 AS TEXT) IS NULL OR u.scope=$2)
                      AND (CAST($3 AS TEXT) IS NULL OR u.scope_id=$3)
                      AND ($4 OR u.expires_at IS NULL OR ",$unexpired,") ORDER BY u.scope,u.granted_at,u.id"))
                    .bind(user).bind(scope).bind(team).bind(include_expired).fetch_all(observed($pool)).await?
            };
        }
        let data = match self {
            Self::Sqlite(pool) => {
                select!(pool, "julianday(u.expires_at)>julianday(CURRENT_TIMESTAMP)")
            }
            Self::Postgres(pool) => select!(pool, "u.expires_at>CURRENT_TIMESTAMP"),
        };
        Ok(data
            .into_iter()
            .map(Assignment::format_timestamps)
            .collect())
    }

    pub(super) async fn assign_rbac_role(
        &self,
        user: &str,
        input: &Assign,
        expiry: Option<Timestamp>,
        actor: &str,
    ) -> Result<Assignment, AccountError> {
        let scope = &input.scope;
        let team = input.scope_id.as_deref().filter(|team| !team.is_empty());
        if !matches!(scope.as_str(), "global" | "team" | "personal")
            || (scope == "team") != team.is_some()
        {
            return Err(invalid());
        }
        let expiry = expiry.map(|time| time.to_string());
        macro_rules! assign {
            ($tx:ident,$expired:literal,$expiry:literal) => {{
                let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roles
                    WHERE id=$1 AND scope=$2 AND is_active=TRUE) AND EXISTS(SELECT 1 FROM email_users WHERE email=$3)
                    AND (CAST($4 AS TEXT) IS NULL OR EXISTS(SELECT 1 FROM email_teams WHERE id=$4 AND is_active=TRUE))")
                    .bind(&input.role_id).bind(scope).bind(user).bind(team).fetch_one(observed(&mut *$tx)).await?;
                if !valid {
                    return Err(invalid());
                }
                sqlx::query(concat!("UPDATE user_roles SET is_active=FALSE WHERE user_email=$1 AND role_id=$2 AND scope=$3
                    AND scope_id IS NOT DISTINCT FROM $4 AND is_active=TRUE AND expires_at IS NOT NULL AND ",$expired))
                    .bind(user).bind(&input.role_id).bind(scope).bind(team).execute(observed(&mut *$tx)).await?;
                let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_email=$1 AND role_id=$2
                    AND scope=$3 AND scope_id IS NOT DISTINCT FROM $4 AND is_active=TRUE)")
                    .bind(user).bind(&input.role_id).bind(scope).bind(team).fetch_one(observed(&mut *$tx)).await?;
                if exists {
                    return Err(invalid());
                }
                let assignment:Assignment=sqlx::query_as(concat!(
                    "INSERT INTO user_roles(id,user_email,role_id,scope,scope_id,granted_by,granted_at,expires_at,is_active)
                    VALUES($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP,",$expiry,",TRUE)
                    RETURNING id,user_email,role_id,CAST(NULL AS TEXT) AS role_name,scope,scope_id,granted_by,
                        CAST(granted_at AS TEXT) AS granted_at,CAST(expires_at AS TEXT) AS expires_at,is_active,grant_source"))
                    .bind(Uuid::new_v4().to_string()).bind(user).bind(&input.role_id).bind(scope).bind(team)
                    .bind(actor).bind(expiry).fetch_one(observed(&mut *$tx)).await.map_err(role_write_error)?;
                $tx.commit().await?;
                Ok(assignment.format_timestamps())
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                assign!(
                    tx,
                    "julianday(expires_at)<=julianday(CURRENT_TIMESTAMP)",
                    "$7"
                )
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682073)")
                    .execute(observed(&mut *tx))
                    .await?;
                assign!(
                    tx,
                    "expires_at<=CURRENT_TIMESTAMP",
                    "CAST(CAST($7 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }

    pub(super) async fn revoke_rbac_role(
        &self,
        user: &str,
        id: &str,
        scope: Option<&str>,
        team: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        macro_rules! revoke {
            ($pool:ident) => {
                sqlx::query("UPDATE user_roles SET is_active=FALSE WHERE user_email=$1 AND role_id=$2
                    AND (CAST($3 AS TEXT) IS NULL OR scope=$3) AND scope_id IS NOT DISTINCT FROM $4 AND is_active=TRUE")
                    .bind(user).bind(id).bind(scope).bind(team).execute(observed($pool)).await?.rows_affected()!=0
            };
        }
        Ok(match self {
            Self::Sqlite(pool) => revoke!(pool),
            Self::Postgres(pool) => revoke!(pool),
        })
    }
}

fn role_write_error(error: sqlx::Error) -> AccountError {
    if error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation() || error.is_foreign_key_violation())
    {
        return invalid();
    }
    error.into()
}
