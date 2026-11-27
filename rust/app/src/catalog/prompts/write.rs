// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PromptWriteError {
    #[error("prompt name is already registered")]
    Duplicate { id: String, enabled: bool },
    #[error("prompt changed concurrently")]
    Changed,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

const PROMPT_BY_ID: &str = concat!(prompt_select!(), " WHERE r.id = $1");

const CONFLICT: &str = "
    SELECT id, COALESCE(enabled,FALSE) FROM prompts
    WHERE id <> $1 AND name = $2 AND visibility = $3
      AND gateway_id IS NOT DISTINCT FROM $4
      AND ($3 = 'public' OR ($3 = 'team' AND team_id = $5)
           OR ($3 = 'private' AND owner_email = $6))
    ORDER BY id LIMIT 1";

macro_rules! check_revision {
    ($tx:ident, $prompt:ident, $lock:literal) => {
        sqlx::query_scalar::<_, String>(concat!(
            "SELECT id FROM prompts WHERE id = $1 AND version IS NOT DISTINCT FROM $2
                AND CAST(updated_at AS TEXT) = $3 AND owner_email IS NOT DISTINCT FROM $4
                AND visibility = $5 AND team_id IS NOT DISTINCT FROM $6 AND COALESCE(enabled,FALSE) = $7",
            $lock
        ))
        .bind(&$prompt.id)
        .bind($prompt.version)
        .bind(&$prompt.updated_at)
        .bind($prompt.owner_email.as_deref())
        .bind(&$prompt.visibility)
        .bind($prompt.team_id.as_deref())
        .bind($prompt.enabled)
        .fetch_optional(&mut *$tx)
        .await?
        .ok_or(PromptWriteError::Changed)?
    };
}

macro_rules! insert_prompt {
    ($schema:literal, $tags:literal) => {
        concat!(
            "INSERT INTO prompts (id,name,original_name,custom_name,custom_name_slug,display_name,
                title,description,template,argument_schema,tags,gateway_id,team_id,owner_email,visibility,
                created_by,created_from_ip,created_user_agent,created_via,created_at,updated_at,enabled,version)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,", $schema, ",", $tags, ",$12,$13,$14,$15,
                $16,$17,$18,'api',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,TRUE,1)"
        )
    };
}

macro_rules! update_prompt {
    ($schema:literal, $tags:literal) => {
        concat!(
            "UPDATE prompts SET name=$2,original_name=$3,custom_name=$4,custom_name_slug=$5,
                display_name=$6,title=$7,description=$8,template=$9,argument_schema=", $schema, ",tags=", $tags, ",
                gateway_id=$12,team_id=$13,owner_email=$14,visibility=$15,modified_by=$16,
                modified_from_ip=$17,modified_user_agent=$18,modified_via='api',updated_at=CURRENT_TIMESTAMP,
                version=COALESCE(version,0)+1 WHERE id=$1"
        )
    };
}

impl Database {
    pub(crate) async fn managed_prompt(
        &self,
        id: &str,
    ) -> Result<Option<PromptRecord>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(PROMPT_BY_ID)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(PROMPT_BY_ID)
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    pub(crate) async fn save_managed_prompt(
        &self,
        previous: Option<&PromptRecord>,
        prompt: &PromptRecord,
    ) -> Result<PromptRecord, PromptWriteError> {
        let scope_changed = previous.is_none_or(|previous| {
            previous.name != prompt.name
                || previous.visibility != prompt.visibility
                || previous.team_id != prompt.team_id
                || previous.owner_email != prompt.owner_email
        });
        macro_rules! save {
            ($tx:ident, $lock:literal, $schema:literal, $tags:literal) => {{
                if let Some(previous) = previous {
                    let _ = check_revision!($tx, previous, $lock);
                }
                if let Some(gateway) = prompt.gateway_id.as_deref() {
                    let slug: Option<String> = sqlx::query_scalar(concat!(
                        "SELECT slug FROM gateways WHERE id = $1",
                        $lock
                    ))
                    .bind(gateway)
                    .fetch_optional(&mut *$tx)
                    .await?;
                    if slug.as_deref() != prompt.gateway_slug.as_deref() {
                        return Err(PromptWriteError::Changed);
                    }
                }
                if scope_changed
                    && let Some((id, enabled)) = sqlx::query_as(CONFLICT)
                        .bind(&prompt.id)
                        .bind(&prompt.name)
                        .bind(&prompt.visibility)
                        .bind(prompt.gateway_id.as_deref())
                        .bind(prompt.team_id.as_deref())
                        .bind(prompt.owner_email.as_deref())
                        .fetch_optional(&mut *$tx)
                        .await?
                {
                    return Err(PromptWriteError::Duplicate { id, enabled });
                }
                let (statement, actor, ip, agent) = if previous.is_some() {
                    (
                        update_prompt!($schema, $tags),
                        &prompt.modified_by,
                        &prompt.modified_from_ip,
                        &prompt.modified_user_agent,
                    )
                } else {
                    (
                        insert_prompt!($schema, $tags),
                        &prompt.created_by,
                        &prompt.created_from_ip,
                        &prompt.created_user_agent,
                    )
                };
                sqlx::query(statement)
                    .bind(&prompt.id)
                    .bind(&prompt.name)
                    .bind(&prompt.original_name)
                    .bind(&prompt.custom_name)
                    .bind(&prompt.custom_name_slug)
                    .bind(prompt.display_name.as_deref())
                    .bind(prompt.title.as_deref())
                    .bind(prompt.description.as_deref())
                    .bind(prompt.template.as_deref())
                    .bind(prompt.argument_schema.as_deref())
                    .bind(&prompt.tags)
                    .bind(prompt.gateway_id.as_deref())
                    .bind(prompt.team_id.as_deref())
                    .bind(prompt.owner_email.as_deref())
                    .bind(&prompt.visibility)
                    .bind(actor.as_deref())
                    .bind(ip.as_deref())
                    .bind(agent.as_deref())
                    .execute(&mut *$tx)
                    .await?;
                let updated = sqlx::query_as(PROMPT_BY_ID)
                    .bind(&prompt.id)
                    .fetch_one(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(updated)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                save!(tx, "", "json($10)", "json($11)")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                save!(tx, " FOR UPDATE", "CAST($10 AS JSON)", "CAST($11 AS JSON)")
            }
        }
    }

    pub(crate) async fn set_managed_prompt_state(
        &self,
        expected: &PromptRecord,
        enabled: bool,
    ) -> Result<PromptRecord, PromptWriteError> {
        macro_rules! change {
            ($tx:ident, $lock:literal, $date:literal) => {{
                let id = check_revision!($tx, expected, $lock);
                if expected.enabled != enabled {
                    sqlx::query(concat!(
                        "UPDATE prompts SET enabled=$2, updated_at=",
                        $date,
                        " WHERE id=$1"
                    ))
                    .bind(&id)
                    .bind(enabled)
                    .bind(jiff::Timestamp::now().to_string())
                    .execute(&mut *$tx)
                    .await?;
                }
                let updated = sqlx::query_as(PROMPT_BY_ID)
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
                change!(tx, "", "$3")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                change!(tx, " FOR UPDATE", "CAST(CAST($3 AS TEXT) AS TIMESTAMPTZ)")
            }
        }
    }

    pub(crate) async fn delete_managed_prompt(
        &self,
        expected: &PromptRecord,
        purge_metrics: bool,
    ) -> Result<(), PromptWriteError> {
        macro_rules! delete {
            ($tx:ident, $lock:literal, $exists:literal) => {{
                let id = check_revision!($tx, expected, $lock);
                for (table, statement) in [
                    (
                        "prompt_metrics",
                        "DELETE FROM prompt_metrics WHERE prompt_id = $1",
                    ),
                    (
                        "prompt_metrics_hourly",
                        "DELETE FROM prompt_metrics_hourly WHERE prompt_id = $1",
                    ),
                ] {
                    if (table == "prompt_metrics" || purge_metrics)
                        && sqlx::query_scalar::<_, bool>($exists)
                            .bind(table)
                            .fetch_one(&mut *$tx)
                            .await?
                    {
                        sqlx::query(statement).bind(&id).execute(&mut *$tx).await?;
                    }
                }
                sqlx::query("DELETE FROM server_prompt_association WHERE prompt_id=$1")
                    .bind(&id)
                    .execute(&mut *$tx)
                    .await?;
                sqlx::query("DELETE FROM prompts WHERE id=$1")
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
                    "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type='table' AND name=$1)"
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
