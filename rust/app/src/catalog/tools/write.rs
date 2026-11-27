// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ToolWriteError {
    #[error("tool name is already registered")]
    Duplicate { id: String, enabled: bool },
    #[error("tool changed concurrently")]
    Changed,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

const CONFLICT: &str = "
    SELECT id,enabled FROM tools
    WHERE id <> $1 AND name = $2 AND visibility = $3
      AND ($3 = 'public' OR ($3 = 'team' AND team_id = $4)
           OR ($3 = 'private' AND owner_email = $5))
    ORDER BY id LIMIT 1";

macro_rules! check_revision {
    ($tx:ident, $tool:ident, $lock:literal) => {
        sqlx::query_scalar::<_, String>(concat!(
            "SELECT id FROM tools WHERE id=$1 AND version IS NOT DISTINCT FROM $2
                AND CAST(updated_at AS TEXT)=$3 AND owner_email IS NOT DISTINCT FROM $4
                AND visibility=$5 AND team_id IS NOT DISTINCT FROM $6 AND enabled=$7 AND reachable=$8",
            $lock
        ))
        .bind(&$tool.id)
        .bind($tool.version)
        .bind(&$tool.updated_at)
        .bind($tool.owner_email.as_deref())
        .bind(&$tool.visibility)
        .bind($tool.team_id.as_deref())
        .bind($tool.enabled)
        .bind($tool.reachable)
        .fetch_optional(&mut *$tx)
        .await?
        .ok_or(ToolWriteError::Changed)?
    };
}

macro_rules! insert_tool {
    ($open:literal, $close:literal) => {
        concat!(
            "INSERT INTO tools (id,name,original_name,original_description,custom_name,custom_name_slug,
                display_name,title,url,description,integration_type,request_type,jsonpath_filter,
                gateway_id,team_id,owner_email,visibility,deprecated,base_url,path_template,timeout_ms,
                expose_passthrough,tool_validation_policy,auth_type,auth_value,headers,input_schema,output_schema,
                annotations,extension_metadata,tags,query_mapping,header_mapping,allowlist,plugin_chain_pre,
                plugin_chain_post,sigv4_config,created_by,created_from_ip,created_user_agent,created_via,
                import_batch_id,federation_source,created_at,updated_at,version,enabled,reachable)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,",
                $open,"$26",$close,",", $open,"$27",$close,",", $open,"$28",$close,",", $open,"$29",$close,",",
                $open,"$30",$close,",", $open,"$31",$close,",", $open,"$32",$close,",", $open,"$33",$close,",",
                $open,"$34",$close,",", $open,"$35",$close,",", $open,"$36",$close,",", $open,"$37",$close,",",
                "$38,$39,$40,$41,$42,$43,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1,TRUE,TRUE)"
        )
    };
}

macro_rules! update_tool {
    ($open:literal, $close:literal) => {
        concat!(
            "UPDATE tools SET name=$2,original_name=$3,original_description=$4,custom_name=$5,custom_name_slug=$6,
                display_name=$7,title=$8,url=$9,description=$10,integration_type=$11,request_type=$12,jsonpath_filter=$13,
                gateway_id=$14,team_id=$15,owner_email=$16,visibility=$17,deprecated=$18,base_url=$19,path_template=$20,
                timeout_ms=$21,expose_passthrough=$22,tool_validation_policy=$23,auth_type=$24,auth_value=$25,
                headers=", $open,"$26",$close,", input_schema=", $open,"$27",$close,", output_schema=", $open,"$28",$close,",",
                "annotations=", $open,"$29",$close,", extension_metadata=", $open,"$30",$close,", tags=", $open,"$31",$close,",",
                "query_mapping=", $open,"$32",$close,", header_mapping=", $open,"$33",$close,", allowlist=", $open,"$34",$close,",",
                "plugin_chain_pre=", $open,"$35",$close,", plugin_chain_post=", $open,"$36",$close,", sigv4_config=", $open,"$37",$close,",",
                "modified_by=$38,modified_from_ip=$39,modified_user_agent=$40,modified_via=$41,updated_at=CURRENT_TIMESTAMP,
                version=COALESCE(version,0)+1 WHERE id=$1"
        )
    };
}

impl Database {
    pub(crate) async fn save_managed_tool(
        &self,
        previous: Option<&ToolRecord>,
        tool: &ToolRecord,
    ) -> Result<ToolRecord, ToolWriteError> {
        let scope_changed = previous.is_none_or(|previous| {
            previous.name != tool.name
                || previous.visibility != tool.visibility
                || previous.team_id != tool.team_id
                || previous.owner_email != tool.owner_email
        });
        macro_rules! save {
            ($tx:ident, $lock:literal, $open:literal, $close:literal) => {{
                if let Some(previous) = previous {
                    let _ = check_revision!($tx, previous, $lock);
                }
                if let Some(gateway) = tool.gateway_id.as_deref() {
                    let slug: Option<String> =
                        sqlx::query_scalar(concat!("SELECT slug FROM gateways WHERE id=$1", $lock))
                            .bind(gateway)
                            .fetch_optional(&mut *$tx)
                            .await?;
                    if slug.as_deref() != Some(tool.gateway_slug.as_str()) {
                        return Err(ToolWriteError::Changed);
                    }
                }
                if scope_changed
                    && let Some((id, enabled)) = sqlx::query_as(CONFLICT)
                        .bind(&tool.id)
                        .bind(&tool.name)
                        .bind(&tool.visibility)
                        .bind(tool.team_id.as_deref())
                        .bind(tool.owner_email.as_deref())
                        .fetch_optional(&mut *$tx)
                        .await?
                {
                    return Err(ToolWriteError::Duplicate { id, enabled });
                }
                let (statement, actor, ip, agent) = if previous.is_some() {
                    (
                        update_tool!($open, $close),
                        &tool.modified_by,
                        &tool.modified_from_ip,
                        &tool.modified_user_agent,
                    )
                } else {
                    (
                        insert_tool!($open, $close),
                        &tool.created_by,
                        &tool.created_from_ip,
                        &tool.created_user_agent,
                    )
                };
                let query = sqlx::query(statement)
                    .bind(&tool.id)
                    .bind(&tool.name)
                    .bind(&tool.original_name)
                    .bind(tool.original_description.as_deref())
                    .bind(&tool.custom_name)
                    .bind(&tool.custom_name_slug)
                    .bind(tool.display_name.as_deref())
                    .bind(tool.title.as_deref())
                    .bind(tool.url.as_deref())
                    .bind(tool.description.as_deref())
                    .bind(&tool.integration_type)
                    .bind(&tool.request_type)
                    .bind(&tool.jsonpath_filter)
                    .bind(tool.gateway_id.as_deref())
                    .bind(tool.team_id.as_deref())
                    .bind(tool.owner_email.as_deref())
                    .bind(&tool.visibility)
                    .bind(tool.deprecated)
                    .bind(tool.base_url.as_deref())
                    .bind(tool.path_template.as_deref())
                    .bind(tool.timeout_ms)
                    .bind(tool.expose_passthrough)
                    .bind(tool.tool_validation_policy.as_deref())
                    .bind(tool.auth_type.as_deref())
                    .bind(tool.auth_value.as_deref())
                    .bind(tool.headers.as_deref())
                    .bind(&tool.input_schema)
                    .bind(tool.output_schema.as_deref())
                    .bind(tool.annotations.as_deref())
                    .bind(tool.extension_metadata.as_deref())
                    .bind(&tool.tags)
                    .bind(tool.query_mapping.as_deref())
                    .bind(tool.header_mapping.as_deref())
                    .bind(tool.allowlist.as_deref())
                    .bind(tool.plugin_chain_pre.as_deref())
                    .bind(tool.plugin_chain_post.as_deref())
                    .bind(tool.sigv4_config.as_deref())
                    .bind(actor.as_deref())
                    .bind(ip.as_deref())
                    .bind(agent.as_deref());
                if previous.is_some() {
                    query
                        .bind(tool.modified_via.as_deref().unwrap_or("api"))
                        .execute(&mut *$tx)
                        .await?;
                } else {
                    query
                        .bind(tool.created_via.as_deref().unwrap_or("api"))
                        .bind(tool.import_batch_id.as_deref())
                        .bind(tool.federation_source.as_deref())
                        .execute(&mut *$tx)
                        .await?;
                }
                let updated = sqlx::query_as(TOOL_BY_ID)
                    .bind(&tool.id)
                    .fetch_one(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(updated)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                save!(tx, "", "json(", ")")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                save!(tx, " FOR UPDATE", "CAST(", " AS JSON)")
            }
        }
    }

    pub(crate) async fn set_managed_tool_state(
        &self,
        expected: &ToolRecord,
        enabled: bool,
        reachable: bool,
    ) -> Result<ToolRecord, ToolWriteError> {
        macro_rules! change {
            ($tx:ident, $lock:literal, $date:literal) => {{
                let id = check_revision!($tx, expected, $lock);
                if expected.enabled != enabled || expected.reachable != reachable {
                    sqlx::query(concat!(
                        "UPDATE tools SET enabled=$2, reachable=$3, updated_at=",
                        $date,
                        " WHERE id=$1"
                    ))
                    .bind(&id)
                    .bind(enabled)
                    .bind(reachable)
                    .bind(jiff::Timestamp::now().to_string())
                    .execute(&mut *$tx)
                    .await?;
                }
                let updated = sqlx::query_as(TOOL_BY_ID)
                    .bind(id)
                    .fetch_one(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(updated)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                change!(tx, "", "$4")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                change!(tx, " FOR UPDATE", "CAST(CAST($4 AS TEXT) AS TIMESTAMPTZ)")
            }
        }
    }

    pub(crate) async fn delete_managed_tool(
        &self,
        expected: &ToolRecord,
        purge_metrics: bool,
    ) -> Result<(), ToolWriteError> {
        macro_rules! delete {
            ($tx:ident, $lock:literal, $exists:literal) => {{
                let id = check_revision!($tx, expected, $lock);
                for (table, statement) in [
                    ("tool_metrics", "DELETE FROM tool_metrics WHERE tool_id=$1"),
                    (
                        "tool_metrics_hourly",
                        "DELETE FROM tool_metrics_hourly WHERE tool_id=$1",
                    ),
                ] {
                    if (table == "tool_metrics" || purge_metrics)
                        && sqlx::query_scalar::<_, bool>($exists)
                            .bind(table)
                            .fetch_one(&mut *$tx)
                            .await?
                    {
                        sqlx::query(statement).bind(&id).execute(&mut *$tx).await?;
                    }
                }
                sqlx::query("DELETE FROM server_tool_association WHERE tool_id=$1")
                    .bind(&id)
                    .execute(&mut *$tx)
                    .await?;
                sqlx::query("DELETE FROM tools WHERE id=$1")
                    .bind(id)
                    .execute(&mut *$tx)
                    .await?;
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
                    "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE name=$1 AND type='table')"
                )
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                delete!(
                    tx,
                    " FOR UPDATE",
                    "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL"
                )
            }
        }
    }
}
