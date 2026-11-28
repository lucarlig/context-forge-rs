// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use uuid::Uuid;

use super::*;
use crate::database::observed;

#[derive(Default)]
pub(crate) struct ServerLinkUpdate {
    pub(crate) tools: Option<Vec<String>>,
    pub(crate) resources: Option<Vec<String>>,
    pub(crate) prompts: Option<Vec<String>>,
    pub(crate) agents: Option<Vec<String>>,
    pub(crate) interfaces: Option<Vec<ServerInterfaceInput>>,
}

pub(crate) struct ServerInterfaceInput {
    pub(crate) protocol: String,
    pub(crate) binding: String,
    pub(crate) version: Option<String>,
    pub(crate) tenant: Option<String>,
    pub(crate) enabled: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ServerWriteError {
    #[error("server name is already registered")]
    Duplicate { id: String, enabled: bool },
    #[error("server identifier is already registered")]
    DuplicateId,
    #[error("server changed concurrently")]
    Changed,
    #[error("some associated {kind} are unavailable")]
    MissingLinks {
        kind: &'static str,
        ids: Vec<String>,
    },
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

const SERVER_CONFLICT: &str = "
    SELECT id,enabled FROM servers WHERE id<>$1 AND name=$2 AND visibility=$3
      AND ($3='public' OR ($3='team' AND team_id=$4) OR ($3='private' AND owner_email=$5))
    ORDER BY id LIMIT 1";

macro_rules! check_revision {
    ($tx:ident, $expected:ident, $lock:literal) => {
        sqlx::query_scalar::<_, String>(concat!(
            "SELECT id FROM servers WHERE id=$1 AND version IS NOT DISTINCT FROM $2
                AND CAST(updated_at AS TEXT)=$3 AND COALESCE(enabled,FALSE)=$4
                AND visibility=$5 AND team_id IS NOT DISTINCT FROM $6 AND owner_email IS NOT DISTINCT FROM $7",
            $lock
        ))
        .bind(&$expected.id).bind($expected.version).bind(&$expected.updated_at).bind($expected.enabled)
        .bind(&$expected.visibility).bind($expected.team_id.as_deref()).bind($expected.owner_email.as_deref())
        .fetch_optional(observed(&mut *$tx))
        .await?
        .ok_or(ServerWriteError::Changed)?
    };
}

macro_rules! insert_server {
    ($tags:literal,$oauth:literal) => {
        concat!(
            "INSERT INTO servers (id,name,description,icon,team_id,owner_email,visibility,tags,
                oauth_enabled,oauth_config,oauth_config_approved,oauth_config_generation,instructions,
                created_by,created_from_ip,created_user_agent,created_via,import_batch_id,federation_source,
                created_at,updated_at,enabled,version)
            VALUES ($1,$2,$3,$4,$5,$6,$7,", $tags, ",$9,", $oauth, ",$11,$12,$13,$14,$15,$16,
                $17,$18,$19,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,TRUE,1)"
        )
    };
}

macro_rules! update_server {
    ($tags:literal,$oauth:literal) => {
        concat!(
            "UPDATE servers SET id=$1,name=$2,description=$3,icon=$4,team_id=$5,owner_email=$6,visibility=$7,tags=",
            $tags,",oauth_enabled=$9,oauth_config=",$oauth,",oauth_config_approved=$11,
                oauth_config_generation=$12,instructions=$13,modified_by=$14,modified_from_ip=$15,modified_user_agent=$16,
                modified_via=$17,updated_at=CURRENT_TIMESTAMP,version=COALESCE(version,0)+1 WHERE id=$18"
        )
    };
}

macro_rules! replace_links {
    ($tx:ident, $server:ident, $scope:ident, $ids:expr, $kind:literal, $table:literal,
     $association:literal, $column:literal, $decode:literal) => {{
        if let Some(ids) = $ids.as_ref() {
            let encoded =
                serde_json::to_string(ids).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
            let existing =
                sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(concat!(
                    "SELECT id,visibility,team_id,owner_email FROM ",
                    $table,
                    " WHERE id IN (",
                    $decode,
                    ")"
                ))
                .bind(&encoded)
                .fetch_all(observed(&mut *$tx))
                .await?;
            let visible = existing
                .iter()
                .filter(|(_, visibility, team, owner)| {
                    $scope.visible(visibility, team.as_deref(), owner.as_deref())
                })
                .map(|(id, _, _, _)| id.as_str())
                .collect::<BTreeSet<_>>();
            let missing = ids
                .iter()
                .map(String::as_str)
                .filter(|id| !visible.contains(id))
                .collect::<BTreeSet<_>>();
            if !missing.is_empty() {
                return Err(ServerWriteError::MissingLinks {
                    kind: $kind,
                    ids: missing.into_iter().map(str::to_owned).collect(),
                });
            }
            sqlx::query(concat!("DELETE FROM ", $association, " WHERE server_id=$1"))
                .bind(&$server.id)
                .execute(observed(&mut *$tx))
                .await?;
            sqlx::query(concat!(
                "INSERT INTO ",
                $association,
                " (server_id,",
                $column,
                ") SELECT $2,id FROM ",
                $table,
                " WHERE id IN (",
                $decode,
                ")"
            ))
            .bind(encoded)
            .bind(&$server.id)
            .execute(observed(&mut *$tx))
            .await?;
        }
    }};
}

impl Database {
    pub(crate) async fn save_managed_server(
        &self,
        previous: Option<&ServerRecord>,
        server: &ServerRecord,
        links: &ServerLinkUpdate,
        scope: CatalogScope<'_>,
    ) -> Result<ServerRecord, ServerWriteError> {
        let changed_scope = previous.is_none_or(|previous| {
            previous.name != server.name
                || previous.visibility != server.visibility
                || previous.team_id != server.team_id
                || previous.owner_email != server.owner_email
        });
        macro_rules! save {
            ($tx:ident,$lock:literal,$tags:literal,$oauth:literal,$decode:literal,$exists:literal) => {{
                let old_id = if let Some(previous) = previous {
                    Some(check_revision!($tx, previous, $lock))
                } else {
                    None
                };
                if old_id.as_deref() != Some(server.id.as_str())
                    && sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM servers WHERE id=$1)")
                        .bind(&server.id).fetch_one(observed(&mut *$tx)).await?
                {
                    return Err(ServerWriteError::DuplicateId);
                }
                if changed_scope && let Some((id,enabled)) = sqlx::query_as(SERVER_CONFLICT)
                    .bind(old_id.as_deref().unwrap_or(&server.id)).bind(&server.name).bind(&server.visibility)
                    .bind(server.team_id.as_deref()).bind(server.owner_email.as_deref()).fetch_optional(observed(&mut *$tx)).await?
                {
                    return Err(ServerWriteError::Duplicate {id,enabled});
                }
                let (statement, actor, ip, agent) = if previous.is_some() {
                    (update_server!($tags,$oauth),&server.modified_by,&server.modified_from_ip,&server.modified_user_agent)
                } else {
                    (insert_server!($tags,$oauth),&server.created_by,&server.created_from_ip,&server.created_user_agent)
                };
                let statement = sqlx::query(statement)
                    .bind(&server.id).bind(&server.name).bind(server.description.as_deref()).bind(server.icon.as_deref())
                    .bind(server.team_id.as_deref()).bind(server.owner_email.as_deref()).bind(&server.visibility)
                    .bind(&server.tags).bind(server.oauth_enabled).bind(server.oauth_config.as_deref())
                    .bind(server.oauth_config_approved).bind(server.oauth_config_generation.as_deref()).bind(server.instructions.as_deref())
                    .bind(actor.as_deref()).bind(ip.as_deref()).bind(agent.as_deref());
                if let Some(old_id) = old_id.as_deref() {
                    statement.bind(server.modified_via.as_deref().unwrap_or("api")).bind(old_id)
                        .execute(observed(&mut *$tx)).await?;
                } else {
                    statement.bind(server.created_via.as_deref().unwrap_or("api"))
                        .bind(server.import_batch_id.as_deref()).bind(server.federation_source.as_deref())
                        .execute(observed(&mut *$tx)).await?;
                }
                replace_links!($tx, server, scope, links.tools, "Tools", "tools", "server_tool_association", "tool_id", $decode);
                replace_links!($tx, server, scope, links.resources, "Resources", "resources", "server_resource_association", "resource_id", $decode);
                replace_links!($tx, server, scope, links.prompts, "Prompts", "prompts", "server_prompt_association", "prompt_id", $decode);
                if let Some(ids) = links.agents.as_ref() {
                    if sqlx::query_scalar::<_, bool>($exists).bind("server_a2a_association").fetch_one(observed(&mut *$tx)).await? {
                        replace_links!($tx, server, scope, links.agents, "A2A agents", "a2a_agents", "server_a2a_association", "a2a_agent_id", $decode);
                    } else if !ids.is_empty() {
                        return Err(ServerWriteError::MissingLinks {kind:"A2A agents",ids:ids.clone()});
                    }
                }
                if let Some(interfaces) = links.interfaces.as_ref() {
                    // Keep the records and any persisted configuration on unchanged bindings.
                    let existing = sqlx::query_as::<_, (String,String,String)>(
                        "SELECT id,protocol,binding FROM server_interfaces WHERE server_id=$1"
                    ).bind(&server.id).fetch_all(observed(&mut *$tx)).await?;
                    for (id,protocol,binding) in existing {
                        if !interfaces.iter().any(|interface|interface.protocol==protocol && interface.binding==binding) {
                            sqlx::query("DELETE FROM server_interfaces WHERE id=$1").bind(id).execute(observed(&mut *$tx)).await?;
                        }
                    }
                    for interface in interfaces {
                        sqlx::query("INSERT INTO server_interfaces (id,server_id,protocol,binding,version,tenant,enabled,created_at,updated_at)
                            VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
                            ON CONFLICT (server_id,protocol,binding) DO UPDATE SET version=EXCLUDED.version,
                                tenant=EXCLUDED.tenant,enabled=EXCLUDED.enabled,updated_at=CURRENT_TIMESTAMP")
                            .bind(Uuid::new_v4().hyphenated().to_string()).bind(&server.id).bind(&interface.protocol)
                            .bind(&interface.binding).bind(interface.version.as_deref()).bind(interface.tenant.as_deref())
                            .bind(interface.enabled).execute(observed(&mut *$tx)).await?;
                    }
                }
                let updated = sqlx::query_as(SERVER_BY_ID).bind(&server.id).fetch_one(observed(&mut *$tx)).await?;
                $tx.commit().await?;
                Ok(updated)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                save!(
                    tx,
                    "",
                    "json($8)",
                    "json($10)",
                    "SELECT value FROM json_each($1)",
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=$1)"
                )
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK)
                    .execute(observed(&mut *tx))
                    .await?;
                save!(
                    tx,
                    " FOR UPDATE",
                    "CAST($8 AS JSON)",
                    "CAST($10 AS JSON)",
                    "SELECT json_array_elements_text(CAST($1 AS JSON))",
                    "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL"
                )
            }
        }
    }

    pub(crate) async fn set_managed_server_state(
        &self,
        expected: &ServerRecord,
        enabled: bool,
    ) -> Result<ServerRecord, ServerWriteError> {
        macro_rules! change {
            ($tx:ident,$lock:literal,$date:literal) => {{
                let id = check_revision!($tx, expected, $lock);
                if expected.enabled != enabled {
                    sqlx::query(concat!(
                        "UPDATE servers SET enabled=$2,updated_at=",
                        $date,
                        " WHERE id=$1"
                    ))
                    .bind(&id)
                    .bind(enabled)
                    .bind(jiff::Timestamp::now().to_string())
                    .execute(observed(&mut *$tx))
                    .await?;
                }
                let updated = sqlx::query_as(SERVER_BY_ID)
                    .bind(id)
                    .fetch_one(observed(&mut *$tx))
                    .await?;
                $tx.commit().await?;
                Ok(updated)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                change!(tx, "", "$3")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK)
                    .execute(observed(&mut *tx))
                    .await?;
                change!(tx, " FOR UPDATE", "CAST(CAST($3 AS TEXT) AS TIMESTAMPTZ)")
            }
        }
    }

    pub(crate) async fn approve_managed_server_oauth(
        &self,
        expected: &ServerRecord,
        generation: &str,
    ) -> Result<i32, ServerWriteError> {
        macro_rules! approve {
            ($tx:ident,$lock:literal) => {{
                let id = check_revision!($tx, expected, $lock);
                let version = sqlx::query_scalar("UPDATE servers SET oauth_config_approved=TRUE,
                    oauth_config_generation=$2,version=COALESCE(version,0)+1 WHERE id=$1 RETURNING version")
                    .bind(id).bind(generation).fetch_one(observed(&mut *$tx)).await?;
                $tx.commit().await?;
                Ok(version)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                approve!(tx, "")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK)
                    .execute(observed(&mut *tx))
                    .await?;
                approve!(tx, " FOR UPDATE")
            }
        }
    }

    pub(crate) async fn delete_managed_server(
        &self,
        expected: &ServerRecord,
        purge_metrics: bool,
    ) -> Result<(), ServerWriteError> {
        macro_rules! delete {
            ($tx:ident,$lock:literal,$exists:literal) => {{
                let id = check_revision!($tx, expected, $lock);
                for (table, statement) in [
                    (
                        "server_metrics",
                        "DELETE FROM server_metrics WHERE server_id=$1",
                    ),
                    (
                        "server_metrics_hourly",
                        "DELETE FROM server_metrics_hourly WHERE server_id=$1",
                    ),
                    (
                        "server_a2a_association",
                        "DELETE FROM server_a2a_association WHERE server_id=$1",
                    ),
                ] {
                    if (table != "server_metrics_hourly" || purge_metrics)
                        && sqlx::query_scalar::<_, bool>($exists)
                            .bind(table)
                            .fetch_one(observed(&mut *$tx))
                            .await?
                    {
                        sqlx::query(statement)
                            .bind(&id)
                            .execute(observed(&mut *$tx))
                            .await?;
                    }
                }
                for statement in [
                    "DELETE FROM server_tool_association WHERE server_id=$1",
                    "DELETE FROM server_resource_association WHERE server_id=$1",
                    "DELETE FROM server_prompt_association WHERE server_id=$1",
                    "DELETE FROM server_interfaces WHERE server_id=$1",
                    "DELETE FROM servers WHERE id=$1",
                ] {
                    sqlx::query(statement)
                        .bind(&id)
                        .execute(observed(&mut *$tx))
                        .await?;
                }
                $tx.commit().await?;
                Ok(())
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                delete!(
                    tx,
                    "",
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=$1)"
                )
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK)
                    .execute(observed(&mut *tx))
                    .await?;
                delete!(
                    tx,
                    " FOR UPDATE",
                    "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL"
                )
            }
        }
    }
}
