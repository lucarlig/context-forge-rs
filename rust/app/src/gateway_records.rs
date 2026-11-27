// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::{
    auth::TeamVisibility,
    catalog::{CATALOG_LOCK, CatalogScope, managed_visibility, visible_team_ids},
    database::Database,
};

#[derive(Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GatewayRecord {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) slug: String,
    pub(crate) url: String,
    pub(crate) description: Option<String>,
    pub(crate) tool_validation_policy: Option<String>,
    pub(crate) transport: String,
    #[serde(skip)]
    pub(crate) capabilities: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) enabled: bool,
    pub(crate) last_seen: Option<String>,
    pub(crate) reachable: bool,
    pub(crate) status: String,
    pub(crate) status_message: Option<String>,
    pub(crate) registration_attempts: i32,
    pub(crate) next_retry_at: Option<String>,
    pub(crate) last_error: Option<String>,
    pub(crate) lifecycle_claimed_by: Option<String>,
    pub(crate) lifecycle_claimed_at: Option<String>,
    pub(crate) lifecycle_claim_expires_at: Option<String>,
    pub(crate) auth_type: Option<String>,
    #[serde(skip)]
    pub(crate) auth_value: Option<String>,
    #[serde(skip)]
    pub(crate) auth_query_params: Option<String>,
    #[serde(skip)]
    pub(crate) oauth_config: Option<String>,
    #[serde(skip)]
    pub(crate) sigv4_config: Option<String>,
    #[serde(skip)]
    pub(crate) passthrough_headers: Option<String>,
    #[serde(skip)]
    pub(crate) tags: String,
    pub(crate) created_by: Option<String>,
    pub(crate) created_from_ip: Option<String>,
    pub(crate) created_via: Option<String>,
    pub(crate) created_user_agent: Option<String>,
    pub(crate) modified_by: Option<String>,
    pub(crate) modified_from_ip: Option<String>,
    pub(crate) modified_via: Option<String>,
    pub(crate) modified_user_agent: Option<String>,
    pub(crate) import_batch_id: Option<String>,
    pub(crate) federation_source: Option<String>,
    pub(crate) version: i32,
    pub(crate) team_id: Option<String>,
    pub(crate) team: Option<String>,
    pub(crate) owner_email: Option<String>,
    pub(crate) visibility: String,
    pub(crate) ca_certificate: Option<String>,
    pub(crate) ca_certificate_sig: Option<String>,
    pub(crate) signing_algorithm: Option<String>,
    pub(crate) client_cert: Option<String>,
    #[serde(skip)]
    pub(crate) has_client_key: bool,
    pub(crate) refresh_interval_seconds: Option<i32>,
    pub(crate) last_refresh_at: Option<String>,
    pub(crate) gateway_mode: String,
    #[serde(skip)]
    pub(crate) identity_propagation: Option<String>,
    pub(crate) tool_count: i64,
    pub(crate) resource_count: i64,
    pub(crate) prompt_count: i64,
}

pub(crate) struct GatewayList<'a> {
    pub(crate) include_inactive: bool,
    pub(crate) visibility: Option<&'a str>,
    pub(crate) team: Option<&'a str>,
    pub(crate) after: Option<(&'a str, &'a str)>,
    pub(crate) limit: i64,
    pub(crate) offset: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub(crate) struct ImpactServer {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(skip)]
    visibility: String,
    #[serde(skip)]
    team_id: Option<String>,
    #[serde(skip)]
    owner_email: Option<String>,
}

macro_rules! gateway_select {
    () => {
        "SELECT g.id, g.name, g.slug, g.url, g.description, g.tool_validation_policy, g.transport,
           CAST(g.capabilities AS TEXT) AS capabilities, CAST(g.created_at AS TEXT) AS created_at,
           CAST(g.updated_at AS TEXT) AS updated_at, g.enabled, CAST(g.last_seen AS TEXT) AS last_seen,
           g.reachable, g.status, g.status_message, g.registration_attempts,
           CAST(g.next_retry_at AS TEXT) AS next_retry_at, g.last_error, g.lifecycle_claimed_by,
           CAST(g.lifecycle_claimed_at AS TEXT) AS lifecycle_claimed_at,
           CAST(g.lifecycle_claim_expires_at AS TEXT) AS lifecycle_claim_expires_at, g.auth_type,
           CAST(g.auth_value AS TEXT) AS auth_value, CAST(g.auth_query_params AS TEXT) AS auth_query_params,
           CAST(g.oauth_config AS TEXT) AS oauth_config, CAST(g.sigv4_config AS TEXT) AS sigv4_config,
           CAST(g.passthrough_headers AS TEXT) AS passthrough_headers, CAST(g.tags AS TEXT) AS tags,
           g.created_by, g.created_from_ip, g.created_via, g.created_user_agent, g.modified_by,
           g.modified_from_ip, g.modified_via, g.modified_user_agent, g.import_batch_id, g.federation_source,
           g.version, g.team_id, (SELECT name FROM email_teams WHERE id = g.team_id) AS team, g.owner_email,
           g.visibility, g.ca_certificate, g.ca_certificate_sig, g.signing_algorithm, g.client_cert,
           (COALESCE(g.client_key, '') <> '') AS has_client_key,
           g.refresh_interval_seconds, CAST(g.last_refresh_at AS TEXT) AS last_refresh_at,
           g.gateway_mode, CAST(g.identity_propagation AS TEXT) AS identity_propagation,
           (SELECT COUNT(*) FROM tools t WHERE t.gateway_id = g.id) AS tool_count,
           (SELECT COUNT(*) FROM resources r WHERE r.gateway_id = g.id) AS resource_count,
           (SELECT COUNT(*) FROM prompts p WHERE p.gateway_id = g.id) AS prompt_count
         FROM gateways g"
    };
}

macro_rules! list_gateways_query {
    ($teams:literal, $date:literal) => {
        concat!(
            "WITH visible_team_ids(id) AS (",
            $teams,
            ") ",
            gateway_select!(),
            " WHERE ($1 OR g.enabled)
                AND (CAST($2 AS TEXT) IS NULL OR g.visibility = $2)
                AND (CAST($3 AS TEXT) IS NULL OR g.team_id = $3)
                AND (CAST($4 AS TEXT) IS NULL OR g.created_at < ",
            $date,
            " OR (g.created_at = ",
            $date,
            " AND g.id < $5))
                AND ",
            managed_visibility!("g", "$8", "$9", "$7", "visible_team_ids"),
            "
              ORDER BY g.created_at DESC, g.id DESC LIMIT $6 OFFSET $11"
        )
    };
}

const GATEWAY_LOOKUP_QUERY: &str = concat!(
    gateway_select!(),
    " WHERE g.id = $1 OR ((g.name = $1 OR g.slug = $1)
           AND NOT EXISTS (SELECT 1 FROM gateways exact WHERE exact.id = $1))
      ORDER BY g.id"
);

const GATEWAY_HEALTH_QUERY: &str = concat!(
    gateway_select!(),
    " WHERE g.status = 'active' AND (CAST($1 AS TEXT) IS NULL OR g.id > $1)
      ORDER BY g.id LIMIT $2"
);

const GATEWAY_IMPACT_QUERY: &str = "
    SELECT s.id, s.name, s.visibility, s.team_id, s.owner_email
    FROM servers s
    WHERE s.id IN (
        SELECT a.server_id FROM server_tool_association a
        JOIN tools t ON t.id = a.tool_id WHERE t.gateway_id = $1
        UNION
        SELECT a.server_id FROM server_resource_association a
        JOIN resources r ON r.id = a.resource_id WHERE r.gateway_id = $1
        UNION
        SELECT a.server_id FROM server_prompt_association a
        JOIN prompts p ON p.id = a.prompt_id WHERE p.gateway_id = $1
    )
    ORDER BY s.name, s.id";

macro_rules! locked_gateway_query {
    ($lock:literal) => {
        concat!(
            "SELECT id FROM gateways WHERE id = $1 AND version = $2
               AND CAST(updated_at AS TEXT) = $3 AND visibility = $4
               AND owner_email IS NOT DISTINCT FROM $5 AND team_id IS NOT DISTINCT FROM $6
               AND status = $7 AND enabled = $8 AND reachable = $9
               AND lifecycle_claimed_by IS NOT DISTINCT FROM $10",
            $lock
        )
    };
}

macro_rules! lock_gateway {
    ($transaction:ident, $expected:expr, $lock:literal) => {
        sqlx::query_scalar::<_, String>(locked_gateway_query!($lock))
            .bind(&$expected.id)
            .bind($expected.version)
            .bind(&$expected.updated_at)
            .bind(&$expected.visibility)
            .bind($expected.owner_email.as_deref())
            .bind($expected.team_id.as_deref())
            .bind(&$expected.status)
            .bind($expected.enabled)
            .bind($expected.reachable)
            .bind($expected.lifecycle_claimed_by.as_deref())
            .fetch_optional(&mut *$transaction)
            .await?
    };
}

macro_rules! set_gateway_state {
    ($transaction:ident, $id:expr, $enabled:expr, $now:expr, $date:literal) => {{
        let statements = [
            concat!("UPDATE gateways SET enabled = $2, reachable = TRUE, updated_at = ", $date, " WHERE id = $1"),
            concat!("UPDATE tools SET enabled = ($2 AND validation_refusal IS NULL), reachable = TRUE,
                updated_at = ", $date, " WHERE gateway_id = $1
                AND (enabled <> ($2 AND validation_refusal IS NULL) OR reachable <> TRUE)"),
            concat!("UPDATE resources SET enabled = $2, updated_at = ", $date, " WHERE gateway_id = $1 AND enabled IS DISTINCT FROM $2"),
            concat!("UPDATE prompts SET enabled = $2, updated_at = ", $date, " WHERE gateway_id = $1 AND enabled IS DISTINCT FROM $2"),
        ];
        for statement in statements {
            sqlx::query(statement)
                .bind($id)
                .bind($enabled)
                .bind($now)
                .execute(&mut *$transaction)
                .await?;
        }
    }};
}

macro_rules! write_gateway_health {
    ($transaction:ident, $id:expr, $reachable:expr, $now:expr, $error:expr, $date:literal) => {{
        sqlx::query(concat!(
            "UPDATE gateways SET
            reachable = CASE WHEN enabled THEN $2 ELSE reachable END,
            last_seen = CASE WHEN $2 THEN ",
            $date,
            " ELSE last_seen END,
            updated_at = CASE WHEN enabled AND reachable <> $2 THEN ",
            $date,
            " ELSE updated_at END,
            last_error = CASE WHEN enabled THEN $4 ELSE last_error END WHERE id = $1"
        ))
        .bind($id)
        .bind($reachable)
        .bind($now)
        .bind($error)
        .execute(&mut *$transaction)
        .await?;
        sqlx::query(concat!(
            "UPDATE tools SET reachable = $2, updated_at = ",
            $date,
            " WHERE gateway_id = $1 AND reachable <> $2
              AND EXISTS (SELECT 1 FROM gateways WHERE id = $1 AND enabled)"
        ))
        .bind($id)
        .bind($reachable)
        .bind($now)
        .execute(&mut *$transaction)
        .await?;
    }};
}

macro_rules! finish_gateway_initialization {
    ($tx:ident, $gateway:ident, $now:expr, $date:literal) => {{
        sqlx::query(concat!("UPDATE gateways SET status = $2, status_message = NULL,
            reachable = TRUE, registration_attempts = 0, next_retry_at = NULL, last_error = NULL,
            lifecycle_claimed_by = NULL, lifecycle_claimed_at = NULL, lifecycle_claim_expires_at = NULL,
            last_seen = ", $date, ", updated_at = ", $date, " WHERE id = $1"))
            .bind(&$gateway.id).bind("active").bind($now).execute(&mut *$tx).await?;
        if $gateway.enabled {
            write_gateway_health!($tx, &$gateway.id, true, $now, None::<&str>, $date);
        } else {
            set_gateway_state!($tx, &$gateway.id, false, $now, $date);
        }
    }};
}

macro_rules! delete_catalog_rows {
    ($transaction:ident, $value:expr, $table_exists:literal, $optional:expr, $required:expr) => {{
        for (table, statement) in $optional {
            if sqlx::query_scalar::<_, bool>($table_exists)
                .bind(table)
                .fetch_one(&mut *$transaction)
                .await?
            {
                sqlx::query(*statement)
                    .bind($value)
                    .execute(&mut *$transaction)
                    .await?;
            }
        }
        for statement in $required {
            sqlx::query(*statement)
                .bind($value)
                .execute(&mut *$transaction)
                .await?;
        }
    }};
}

mod lifecycle;
mod refresh;
pub(crate) use refresh::{CatalogChanges, CatalogRefreshCompletion, CatalogRefreshInput};

const OPTIONAL_GATEWAY_DELETES: &[(&str, &str)] = &[
    (
        "tool_metrics",
        "DELETE FROM tool_metrics WHERE tool_id IN (SELECT id FROM tools WHERE gateway_id = $1)",
    ),
    (
        "resource_metrics",
        "DELETE FROM resource_metrics WHERE resource_id IN (SELECT id FROM resources WHERE gateway_id = $1)",
    ),
    (
        "prompt_metrics",
        "DELETE FROM prompt_metrics WHERE prompt_id IN (SELECT id FROM prompts WHERE gateway_id = $1)",
    ),
    (
        "resource_subscriptions",
        "DELETE FROM resource_subscriptions WHERE resource_id IN (SELECT id FROM resources WHERE gateway_id = $1)",
    ),
];

const GATEWAY_DELETES: &[&str] = &[
    "DELETE FROM server_tool_association WHERE tool_id IN (SELECT id FROM tools WHERE gateway_id = $1)",
    "DELETE FROM server_resource_association WHERE resource_id IN (SELECT id FROM resources WHERE gateway_id = $1)",
    "DELETE FROM server_prompt_association WHERE prompt_id IN (SELECT id FROM prompts WHERE gateway_id = $1)",
    "DELETE FROM tools WHERE gateway_id = $1",
    "DELETE FROM resources WHERE gateway_id = $1",
    "DELETE FROM prompts WHERE gateway_id = $1",
    "DELETE FROM gateways WHERE id = $1",
];

impl Database {
    pub(crate) async fn gateways_for_health(
        &self,
        after_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<GatewayRecord>, sqlx::Error> {
        macro_rules! select {
            ($pool:ident) => {
                sqlx::query_as::<_, GatewayRecord>(GATEWAY_HEALTH_QUERY)
                    .bind(after_id)
                    .bind(limit)
                    .fetch_all($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool),
            Self::Postgres(pool) => select!(pool),
        }
    }

    pub(crate) async fn set_gateway_health(
        &self,
        expected: &GatewayRecord,
        error: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let now = jiff::Timestamp::now().to_string();
        let reachable = error.is_none();
        macro_rules! change {
            ($transaction:ident, $lock:literal, $date:literal) => {{
                let Some(id) = lock_gateway!($transaction, expected, $lock) else {
                    return Ok(false);
                };
                write_gateway_health!($transaction, &id, reachable, &now, error, $date);
                $transaction.commit().await?;
                Ok(true)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
                change!(transaction, "", "$3")
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *transaction).await?;
                change!(
                    transaction,
                    " FOR UPDATE",
                    "CAST(CAST($3 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }

    pub(crate) async fn listed_gateways(
        &self,
        scope: CatalogScope<'_>,
        list: GatewayList<'_>,
    ) -> Result<Vec<GatewayRecord>, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        let (after_date, after_id) = list.after.unzip();
        macro_rules! select {
            ($pool:expr, $teams:literal, $date:literal) => {
                sqlx::query_as::<_, GatewayRecord>(list_gateways_query!($teams, $date))
                    .bind(list.include_inactive)
                    .bind(list.visibility)
                    .bind(list.team)
                    .bind(after_date)
                    .bind(after_id)
                    .bind(list.limit)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(teams)
                    .bind(list.offset)
                    .fetch_all($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool, "SELECT value FROM json_each($10)", "$4"),
            Self::Postgres(pool) => select!(
                pool,
                "SELECT json_array_elements_text(CAST($10 AS JSON))",
                "CAST(CAST($4 AS TEXT) AS TIMESTAMPTZ)"
            ),
        }
    }

    pub(crate) async fn gateway_records(
        &self,
        key: &str,
    ) -> Result<Vec<GatewayRecord>, sqlx::Error> {
        macro_rules! select {
            ($pool:expr) => {
                sqlx::query_as::<_, GatewayRecord>(GATEWAY_LOOKUP_QUERY)
                    .bind(key)
                    .fetch_all($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => select!(pool),
            Self::Postgres(pool) => select!(pool),
        }
    }

    pub(crate) async fn gateway_impact(
        &self,
        gateway_id: &str,
        scope: CatalogScope<'_>,
    ) -> Result<Vec<ImpactServer>, sqlx::Error> {
        macro_rules! select {
            ($pool:expr) => {
                sqlx::query_as::<_, ImpactServer>(GATEWAY_IMPACT_QUERY)
                    .bind(gateway_id)
                    .fetch_all($pool)
                    .await?
            };
        }
        let mut servers = match self {
            Self::Sqlite(pool) => select!(pool),
            Self::Postgres(pool) => select!(pool),
        };
        servers.retain(|server| {
            scope.visible(
                &server.visibility,
                server.team_id.as_deref(),
                server.owner_email.as_deref(),
            )
        });
        Ok(servers)
    }

    pub(crate) async fn delete_gateway(
        &self,
        expected: &GatewayRecord,
    ) -> Result<bool, sqlx::Error> {
        macro_rules! delete {
            ($transaction:ident, $lock:literal, $table_exists:literal) => {{
                let id = lock_gateway!($transaction, expected, $lock);
                let Some(id) = id else {
                    return Ok(false);
                };
                delete_catalog_rows!(
                    $transaction,
                    &id,
                    $table_exists,
                    OPTIONAL_GATEWAY_DELETES,
                    GATEWAY_DELETES
                );
                $transaction.commit().await?;
                Ok(true)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
                delete!(
                    transaction,
                    "",
                    "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = $1)"
                )
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *transaction).await?;
                delete!(
                    transaction,
                    " FOR UPDATE",
                    "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL"
                )
            }
        }
    }

    pub(crate) async fn set_gateway_state(
        &self,
        expected: &GatewayRecord,
        enabled: bool,
    ) -> Result<bool, sqlx::Error> {
        let now = jiff::Timestamp::now().to_string();
        macro_rules! change {
            ($transaction:ident, $lock:literal, $date:literal) => {{
                let Some(id) = lock_gateway!($transaction, expected, $lock) else {
                    return Ok(false);
                };
                set_gateway_state!($transaction, &id, enabled, &now, $date);
                $transaction.commit().await?;
                Ok(true)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
                change!(transaction, "", "$3")
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *transaction).await?;
                change!(
                    transaction,
                    " FOR UPDATE",
                    "CAST(CAST($3 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }
}
