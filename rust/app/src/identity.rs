// SPDX-License-Identifier: Apache-2.0

use crate::{auth::TeamVisibility, database::Database};

const MIGRATION: &str = include_str!("../migrations/001_identity.sql");

const ACTIVE_MEMBERSHIPS: &str = "
    SELECT m.team_id FROM email_team_members m
    JOIN email_teams t ON t.id = m.team_id AND t.is_active = TRUE
    WHERE m.user_email = $1 AND m.is_active = TRUE ORDER BY m.id";

const ACTIVE_TEAM_OWNER: &str = "
    SELECT EXISTS (
        SELECT 1 FROM email_team_members m
        JOIN email_teams t ON t.id = m.team_id AND t.is_active = TRUE
        WHERE m.user_email = $1 AND m.team_id = $2
          AND m.is_active = TRUE AND m.role = 'owner'
    )";

type IdentityRow = (String, Option<String>, bool, Option<i64>);
type GrantRow = (String, Option<String>, bool, String);

#[derive(Debug)]
pub(crate) struct Identity {
    pub(crate) email: String,
    pub(crate) full_name: Option<String>,
    pub(crate) is_admin: bool,
    pub(crate) password_changed_at: Option<i64>,
}

#[derive(Debug)]
pub(crate) struct Grant {
    pub(crate) scope: String,
    pub(crate) team_id: Option<String>,
    pub(crate) is_personal_team: bool,
    pub(crate) permissions: Vec<String>,
}

impl Database {
    pub(crate) async fn team_owner(&self, email: &str, team_id: &str) -> Result<bool, sqlx::Error> {
        macro_rules! select {
            ($pool:expr) => {
                sqlx::query_scalar(ACTIVE_TEAM_OWNER)
                    .bind(email)
                    .bind(team_id)
                    .fetch_one($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool),
            Self::Postgres(pool) => select!(pool),
        }
    }

    /// Initialize the account, membership, role, and revocation tables.
    pub async fn migrate_identity(&self) -> Result<(), sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::raw_sql(MIGRATION).execute(&mut *transaction).await?;
                sqlx::raw_sql(crate::tokens::SQLITE_USAGE_MIGRATION)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query("SELECT pg_advisory_xact_lock(1128682066)")
                    .execute(&mut *transaction)
                    .await?;
                sqlx::raw_sql(MIGRATION).execute(&mut *transaction).await?;
                sqlx::raw_sql(crate::tokens::POSTGRES_USAGE_MIGRATION)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await
            }
        }
    }

    pub(crate) async fn active_identity(
        &self,
        address: Option<&str>,
        subject: Option<&str>,
        jti: Option<&str>,
    ) -> Result<Option<Identity>, sqlx::Error> {
        // A UUID subject is stable across email changes. The legacy subject is an email.
        macro_rules! query {
            ($changed_at:literal, $unlocked:literal) => {
                concat!(
                    "SELECT u.email, u.full_name, u.is_admin, ", $changed_at, "
                    FROM email_users u
                    WHERE ((CAST($1 AS TEXT) IS NOT NULL AND u.email = $1)
                        OR (CAST($1 AS TEXT) IS NULL AND u.id = $2))
                        AND u.is_active = TRUE
                        AND NOT EXISTS (SELECT 1 FROM token_revocations r WHERE r.jti = $3)
                        AND (u.locked_until IS NULL OR ", $unlocked, ")"
                )
            };
        }
        let row = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, IdentityRow>(query!(
                    "CAST(strftime('%s', u.password_changed_at) AS BIGINT)",
                    "julianday(u.locked_until) <= julianday('now')"
                ))
                .bind(address)
                .bind(subject)
                .bind(jti)
                .fetch_optional(pool)
                .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, IdentityRow>(query!(
                    "CAST(FLOOR(EXTRACT(EPOCH FROM u.password_changed_at)) AS BIGINT)",
                    "u.locked_until <= CURRENT_TIMESTAMP"
                ))
                .bind(address)
                .bind(subject)
                .bind(jti)
                .fetch_optional(pool)
                .await?
            }
        };
        Ok(row.map(
            |(email, full_name, is_admin, password_changed_at)| Identity {
                email,
                full_name,
                is_admin,
                password_changed_at,
            },
        ))
    }

    pub(crate) async fn memberships(&self, email: &str) -> Result<Vec<String>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar(ACTIVE_MEMBERSHIPS)
                    .bind(email)
                    .fetch_all(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar(ACTIVE_MEMBERSHIPS)
                    .bind(email)
                    .fetch_all(pool)
                    .await
            }
        }
    }

    pub(crate) async fn grants(&self, email: &str) -> Result<Vec<Grant>, sqlx::Error> {
        macro_rules! query {
            ($unexpired:literal) => {
                concat!(
                    "WITH RECURSIVE effective(scope, scope_id, personal, role_id) AS (
                        SELECT u.scope, u.scope_id, COALESCE(t.is_personal, FALSE), r.id
                        FROM user_roles u
                        JOIN roles r ON r.id = u.role_id AND r.is_active = TRUE
                        LEFT JOIN email_teams t ON u.scope = 'team' AND t.id = u.scope_id
                        WHERE u.user_email = $1 AND u.is_active = TRUE
                            AND (u.scope <> 'team' OR u.scope_id IS NULL OR t.is_active = TRUE)
                            AND (u.expires_at IS NULL OR ", $unexpired, ")
                        UNION
                        SELECT e.scope, e.scope_id, e.personal, parent.id
                        FROM effective e
                        JOIN roles role ON role.id = e.role_id
                        JOIN roles parent ON parent.id = role.inherits_from AND parent.is_active = TRUE
                    )
                    SELECT e.scope, e.scope_id, e.personal, CAST(r.permissions AS TEXT)
                    FROM effective e JOIN roles r ON r.id = e.role_id"
                )
            };
        }
        let rows = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, GrantRow>(query!("julianday(u.expires_at) > julianday('now')"))
                    .bind(email)
                    .fetch_all(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, GrantRow>(query!("u.expires_at > CURRENT_TIMESTAMP"))
                    .bind(email)
                    .fetch_all(pool)
                    .await?
            }
        };

        rows.into_iter()
            .map(|(scope, team_id, is_personal_team, permissions)| {
                Ok(Grant {
                    scope,
                    team_id,
                    is_personal_team,
                    permissions: serde_json::from_str(&permissions)
                        .map_err(|err| sqlx::Error::Decode(Box::new(err)))?,
                })
            })
            .collect()
    }
}

impl Identity {
    pub(crate) async fn session_visibility(
        &self,
        db: &Database,
    ) -> Result<TeamVisibility, sqlx::Error> {
        if self.is_admin {
            return Ok(TeamVisibility::Admin);
        }
        let teams = db.memberships(&self.email).await?;
        Ok(TeamVisibility::from_teams(teams))
    }
}
