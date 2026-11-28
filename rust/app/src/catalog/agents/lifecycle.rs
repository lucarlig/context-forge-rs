// SPDX-License-Identifier: Apache-2.0

use super::*;

macro_rules! locked_tool {
    ($tx:ident, $agent:ident, $lock:literal) => {{
        sqlx::query_scalar::<_, Option<String>>(concat!(
            "SELECT tool_id FROM a2a_agents WHERE id=$1 AND version=$2
                AND owner_email IS NOT DISTINCT FROM $3 AND visibility=$4
                AND team_id IS NOT DISTINCT FROM $5",
            $lock
        ))
        .bind(&$agent.id)
        .bind($agent.version)
        .bind(&$agent.owner_email)
        .bind(&$agent.visibility)
        .bind(&$agent.team_id)
        .fetch_optional(&mut *$tx)
        .await?
        .ok_or(AgentWriteError::Changed)?
    }};
}

macro_rules! agent_transaction {
    ($database:expr, $operation:ident) => {
        match $database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                $operation!(
                    tx,
                    "",
                    "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE name=$1 AND type='table')"
                )
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                $operation!(
                    tx,
                    " FOR UPDATE",
                    "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL"
                )
            }
        }
    };
}

const UPDATE_AGENT: &str = "
    UPDATE a2a_agents SET name=$2, slug=$3, description=$4, endpoint_url=$5,
        agent_type=$6, protocol_binding=$7, protocol_version=$8, capabilities=$9, skills=$10,
        config=$11, passthrough_headers=$12, tags=$13, auth_type=$14, auth_value=$15,
        auth_query_params=$16, team_id=$17, visibility=$18,
        modified_by=$19, modified_from_ip=$20, modified_via=$27, modified_user_agent=$21,
        oauth_config=$22, uaid=$23, uaid_registry=$24, uaid_proto=$25, uaid_native_id=$26,
        version=version+1, updated_at=CURRENT_TIMESTAMP WHERE id=$1";

const UPDATE_TOOL: &str = "
    UPDATE tools SET name=$2, custom_name_slug=$2, custom_name=$3, url=$4,
        description=$5, tags=$6, display_name=$7,
        modified_by=$8, modified_from_ip=$9, modified_via=$13, modified_user_agent=$10,
        auth_type=CASE WHEN auth_type IS NOT DISTINCT FROM $11 THEN $12 ELSE auth_type END,
        auth_value=CASE WHEN auth_type IS NOT DISTINCT FROM $11 THEN NULL ELSE auth_value END,
        version=COALESCE(version, 0)+1, updated_at=CURRENT_TIMESTAMP
    WHERE id=$1 AND integration_type='A2A'";

const TOOL_CONFLICT: &str = "
    SELECT EXISTS(
        SELECT 1 FROM tools own JOIN tools other
            ON other.id <> own.id AND other.name=$2 AND other.visibility=own.visibility
        WHERE own.id=$1 AND own.name <> $2 AND (
            own.visibility='public'
            OR (own.visibility='team' AND other.team_id=own.team_id)
            OR (own.visibility='private' AND other.owner_email=own.owner_email)
        )
    )";

impl Database {
    pub(crate) async fn update_agent(
        &self,
        previous: &AgentRecord,
        agent: &AgentRecord,
    ) -> Result<AgentRecord, AgentWriteError> {
        let query = agent
            .auth_query_params
            .as_deref()
            .map(serde_json::from_str::<Value>)
            .transpose()
            .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
        let tool_custom_name = format!("a2a_{}", agent.slug);
        let tool_name = slugify(&tool_custom_name);
        let display_name = display_name(&agent.name);
        let description = tool_description(agent);
        let tags = tool_tags(agent);
        macro_rules! save {
            ($tx:ident, $lock:literal, $exists:literal) => {{
                let tool_id = locked_tool!($tx, previous, $lock);
                if (agent.slug != previous.slug
                    || agent.visibility != previous.visibility
                    || agent.team_id != previous.team_id)
                    && let Some((id, enabled)) = sqlx::query_as::<_, (String, bool)>(DUPLICATE)
                        .bind(&agent.slug)
                        .bind(&agent.visibility)
                        .bind(&agent.team_id)
                        .bind(&agent.owner_email)
                        .bind(&agent.id)
                        .fetch_optional(&mut *$tx)
                        .await?
                {
                    return Err(AgentWriteError::Duplicate { id, enabled });
                }
                if let Some(tool) = tool_id.as_deref() {
                    if tool_custom_name.chars().count() > 255
                        || sqlx::query_scalar::<_, bool>(TOOL_CONFLICT)
                            .bind(tool)
                            .bind(&tool_name)
                            .fetch_one(&mut *$tx)
                            .await?
                    {
                        return Err(AgentWriteError::ToolConflict);
                    }
                    sqlx::query(UPDATE_TOOL)
                        .bind(tool)
                        .bind(&tool_name)
                        .bind(&tool_custom_name)
                        .bind(&agent.endpoint_url)
                        .bind(&description)
                        .bind(DbJson(&tags))
                        .bind(&display_name)
                        .bind(&agent.modified_by)
                        .bind(&agent.modified_from_ip)
                        .bind(&agent.modified_user_agent)
                        .bind(&previous.auth_type)
                        .bind(&agent.auth_type)
                        .bind(agent.modified_via.as_deref().unwrap_or("api"))
                        .execute(&mut *$tx)
                        .await?;
                }
                sqlx::query(UPDATE_AGENT)
                    .bind(&agent.id)
                    .bind(&agent.name)
                    .bind(&agent.slug)
                    .bind(&agent.description)
                    .bind(&agent.endpoint_url)
                    .bind(&agent.agent_type)
                    .bind(&agent.protocol_binding)
                    .bind(&agent.protocol_version)
                    .bind(&agent.capabilities)
                    .bind(&agent.skills)
                    .bind(&agent.config)
                    .bind(&agent.passthrough_headers)
                    .bind(&agent.tags)
                    .bind(&agent.auth_type)
                    .bind(&agent.auth_value)
                    .bind(query.as_ref().map(DbJson))
                    .bind(&agent.team_id)
                    .bind(&agent.visibility)
                    .bind(&agent.modified_by)
                    .bind(&agent.modified_from_ip)
                    .bind(&agent.modified_user_agent)
                    .bind(&agent.oauth_config)
                    .bind(&agent.uaid)
                    .bind(&agent.uaid_registry)
                    .bind(&agent.uaid_proto)
                    .bind(&agent.uaid_native_id)
                    .bind(agent.modified_via.as_deref().unwrap_or("api"))
                    .execute(&mut *$tx)
                    .await?;
                let row = sqlx::query_as(BY_ID)
                    .bind(&agent.id)
                    .fetch_one(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(row)
            }};
        }
        agent_transaction!(self, save)
    }

    pub(crate) async fn set_agent_state(
        &self,
        agent: &AgentRecord,
        enabled: bool,
    ) -> Result<AgentRecord, AgentWriteError> {
        macro_rules! set_state {
            ($tx:ident, $lock:literal, $exists:literal) => {{
                let tool = locked_tool!($tx, agent, $lock);
                let stamp = jiff::Timestamp::now().strftime("%F %T%.6f").to_string();
                let state_sql = if $lock.is_empty() {
                    "UPDATE a2a_agents SET enabled=$2, updated_at=$3 WHERE id=$1 AND enabled <> $2"
                } else {
                    "UPDATE a2a_agents SET enabled=$2, updated_at=CAST((CAST($3 AS TEXT) || '+00:00') AS TIMESTAMPTZ)
                        WHERE id=$1 AND enabled <> $2"
                };
                sqlx::query(state_sql)
                    .bind(&agent.id)
                    .bind(enabled)
                    .bind(&stamp)
                    .execute(&mut *$tx)
                    .await?;
                if let Some(tool) = tool {
                    sqlx::query(
                        "UPDATE tools SET enabled=($2 AND validation_refusal IS NULL),
                        updated_at=CURRENT_TIMESTAMP
                        WHERE id=$1 AND integration_type='A2A'
                            AND enabled <> ($2 AND validation_refusal IS NULL)",
                    )
                    .bind(tool)
                    .bind(enabled)
                    .execute(&mut *$tx)
                    .await?;
                }
                let row = sqlx::query_as(BY_ID)
                    .bind(&agent.id)
                    .fetch_one(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(row)
            }};
        }
        agent_transaction!(self, set_state)
    }

    pub(crate) async fn delete_agent(
        &self,
        agent: &AgentRecord,
        purge_metrics: bool,
    ) -> Result<(), AgentWriteError> {
        macro_rules! delete {
            ($tx:ident, $lock:literal, $exists:literal) => {{
                let tool = locked_tool!($tx, agent, $lock);
                for (table, statement) in [
                    (
                        "a2a_agent_metrics",
                        "DELETE FROM a2a_agent_metrics WHERE a2a_agent_id=$1",
                    ),
                    (
                        "a2a_agent_metrics_hourly",
                        "DELETE FROM a2a_agent_metrics_hourly WHERE a2a_agent_id=$1",
                    ),
                ] {
                    if (table == "a2a_agent_metrics" || purge_metrics)
                        && sqlx::query_scalar::<_, bool>($exists)
                            .bind(table)
                            .fetch_one(&mut *$tx)
                            .await?
                    {
                        sqlx::query(statement)
                            .bind(&agent.id)
                            .execute(&mut *$tx)
                            .await?;
                    }
                }
                sqlx::query("DELETE FROM server_a2a_association WHERE a2a_agent_id=$1")
                    .bind(&agent.id)
                    .execute(&mut *$tx)
                    .await?;
                sqlx::query("DELETE FROM a2a_agents WHERE id=$1")
                    .bind(&agent.id)
                    .execute(&mut *$tx)
                    .await?;
                if let Some(tool) = tool {
                    let derived: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM tools WHERE id=$1 AND integration_type='A2A'
                        AND NOT EXISTS(SELECT 1 FROM a2a_agents WHERE tool_id=$1))",
                    )
                    .bind(&tool)
                    .fetch_one(&mut *$tx)
                    .await?;
                    if derived {
                        delete_tool_dependencies!($tx, &tool, purge_metrics, $exists);
                        sqlx::query("DELETE FROM tools WHERE id=$1")
                            .bind(&tool)
                            .execute(&mut *$tx)
                            .await?;
                    }
                }
                $tx.commit().await?;
                Ok(())
            }};
        }
        agent_transaction!(self, delete)
    }
}
