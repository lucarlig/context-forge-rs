// SPDX-License-Identifier: Apache-2.0

use super::{entry_filters::fetch_catalog_entries, *};

#[derive(Debug, thiserror::Error)]
pub(crate) enum ResourceWriteError {
    #[error("resource URI is already registered")]
    Duplicate { id: String, enabled: bool },
    #[error("resource changed concurrently")]
    Changed,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

const RESOURCE_CONFLICT: &str = "
    SELECT id, COALESCE(enabled, FALSE) FROM resources
    WHERE id <> $1 AND uri = $2 AND visibility = $3
      AND gateway_id IS NOT DISTINCT FROM $4
      AND ($3 = 'public' OR ($3 = 'team' AND team_id = $5)
           OR ($3 = 'private' AND owner_email = $6 AND team_id IS NOT DISTINCT FROM $5))
    ORDER BY id LIMIT 1";

macro_rules! lock_resource {
    ($tx:ident, $expected:ident, $lock:literal) => {
        sqlx::query_scalar::<_, String>(concat!(
            "SELECT id FROM resources WHERE id = $1 AND version IS NOT DISTINCT FROM $2
               AND CAST(updated_at AS TEXT) = $3 AND owner_email IS NOT DISTINCT FROM $4
               AND visibility = $5 AND team_id IS NOT DISTINCT FROM $6 AND COALESCE(enabled, FALSE) = $7",
            $lock
        )).bind(&$expected.id).bind($expected.version).bind(&$expected.updated_at)
            .bind($expected.owner_email.as_deref()).bind(&$expected.visibility)
            .bind($expected.team_id.as_deref()).bind($expected.enabled)
            .fetch_optional(&mut *$tx).await?.ok_or(ResourceWriteError::Changed)?
    };
}

macro_rules! resource_insert {
    ($tags:literal, $extension:literal) => {
        concat!(
            "INSERT INTO resources (id, uri, name, original_name, custom_name_slug, description, title,
                mime_type, uri_template, gateway_id, size, text_content, binary_content, tags,
                extension_metadata, owner_email, team_id, visibility, created_by,
                created_from_ip, created_user_agent, created_via, import_batch_id, federation_source,
                enabled, created_at, updated_at, version)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,", $tags, ",", $extension, ",
                $16,$17,$18,$19,$20,$21,$22,$23,$24,TRUE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)"
        )
    };
}

macro_rules! resource_update {
    ($tags:literal, $extension:literal) => {
        concat!(
            "UPDATE resources SET uri=$2, name=$3, original_name=$4, custom_name_slug=$5,
                description=$6, title=$7, mime_type=$8, uri_template=$9, gateway_id=$10, size=$11,
                text_content=COALESCE($12,text_content), binary_content=COALESCE($13,binary_content),
                tags=", $tags, ", extension_metadata=", $extension, ",
                owner_email=$16, team_id=$17, visibility=$18, modified_by=$19,
                modified_from_ip=$20, modified_user_agent=$21, modified_via=$22,
                updated_at=CURRENT_TIMESTAMP, version=COALESCE(version,0)+1 WHERE id=$1"
        )
    };
}

impl Database {
    pub(crate) async fn import_resource_candidates(
        &self,
        scope: CatalogScope<'_>,
        uri: &str,
    ) -> Result<Vec<ResourceRecord>, sqlx::Error> {
        fetch_catalog_entries!(
            self,
            ResourceRecord,
            scope,
            CatalogEntryFilters::associated(true),
            resource_select!(),
            "r.gateway_id IS NULL AND r.uri = $14",
            uri
        )
    }

    pub(crate) async fn save_managed_resource(
        &self,
        previous: Option<&ResourceRecord>,
        resource: &ResourceRecord,
        text: Option<&str>,
    ) -> Result<ResourceRecord, ResourceWriteError> {
        let scope_changed = previous.is_none_or(|previous| {
            previous.uri != resource.uri
                || previous.visibility != resource.visibility
                || previous.owner_email != resource.owner_email
                || previous.team_id != resource.team_id
                || previous.gateway_id != resource.gateway_id
        });
        macro_rules! save {
            ($tx:ident, $lock:literal, $tags:literal, $extension:literal) => {{
                if let Some(previous) = previous {
                    let _ = lock_resource!($tx, previous, $lock);
                }
                if scope_changed
                    && let Some((id, enabled)) =
                        sqlx::query_as::<_, (String, bool)>(RESOURCE_CONFLICT)
                            .bind(&resource.id)
                            .bind(&resource.uri)
                            .bind(&resource.visibility)
                            .bind(resource.gateway_id.as_deref())
                            .bind(resource.team_id.as_deref())
                            .bind(resource.owner_email.as_deref())
                            .fetch_optional(&mut *$tx)
                            .await?
                {
                    return Err(ResourceWriteError::Duplicate { id, enabled });
                }
                let (statement, actor, ip, agent, via) = if previous.is_some() {
                    (
                        resource_update!($tags, $extension),
                        &resource.modified_by,
                        &resource.modified_from_ip,
                        &resource.modified_user_agent,
                        &resource.modified_via,
                    )
                } else {
                    (
                        resource_insert!($tags, $extension),
                        &resource.created_by,
                        &resource.created_from_ip,
                        &resource.created_user_agent,
                        &resource.created_via,
                    )
                };
                let query = sqlx::query(statement)
                    .bind(&resource.id)
                    .bind(&resource.uri)
                    .bind(&resource.name)
                    .bind(resource.original_name.as_deref())
                    .bind(resource.custom_name_slug.as_deref())
                    .bind(resource.description.as_deref())
                    .bind(resource.title.as_deref())
                    .bind(resource.mime_type.as_deref())
                    .bind(resource.uri_template.as_deref())
                    .bind(resource.gateway_id.as_deref())
                    .bind(resource.size)
                    .bind(text)
                    .bind(text.map(str::as_bytes))
                    .bind(&resource.tags)
                    .bind(resource.extension_metadata.as_deref())
                    .bind(resource.owner_email.as_deref())
                    .bind(resource.team_id.as_deref())
                    .bind(&resource.visibility)
                    .bind(actor.as_deref())
                    .bind(ip.as_deref())
                    .bind(agent.as_deref())
                    .bind(via.as_deref().unwrap_or("api"));
                let query = if previous.is_none() {
                    query
                        .bind(resource.import_batch_id.as_deref())
                        .bind(resource.federation_source.as_deref())
                } else {
                    query
                };
                query.execute(&mut *$tx).await?;
                let updated = sqlx::query_as::<_, ResourceRecord>(RESOURCE_BY_ID)
                    .bind(&resource.id)
                    .fetch_one(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(updated)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                save!(tx, "", "json($14)", "json($15)")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                save!(tx, " FOR UPDATE", "CAST($14 AS JSON)", "CAST($15 AS JSON)")
            }
        }
    }

    pub(crate) async fn set_managed_resource_state(
        &self,
        expected: &ResourceRecord,
        enabled: bool,
    ) -> Result<ResourceRecord, ResourceWriteError> {
        macro_rules! change {
            ($tx:ident, $lock:literal, $date:literal) => {{
                let id = lock_resource!($tx, expected, $lock);
                if expected.enabled != enabled {
                    let now = jiff::Timestamp::now().to_string();
                    sqlx::query(concat!(
                        "UPDATE resources SET enabled = $2, updated_at = ",
                        $date,
                        " WHERE id = $1"
                    ))
                    .bind(&id)
                    .bind(enabled)
                    .bind(now)
                    .execute(&mut *$tx)
                    .await?;
                }
                let updated = sqlx::query_as::<_, ResourceRecord>(RESOURCE_BY_ID)
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

    pub(crate) async fn delete_managed_resource(
        &self,
        expected: &ResourceRecord,
        purge_metrics: bool,
    ) -> Result<(), ResourceWriteError> {
        const OPTIONAL_DEPENDENCIES: &[(&str, &str)] = &[
            (
                "resource_metrics",
                "DELETE FROM resource_metrics WHERE resource_id = $1",
            ),
            (
                "resource_metrics_hourly",
                "DELETE FROM resource_metrics_hourly WHERE resource_id = $1",
            ),
            (
                "resource_subscriptions",
                "DELETE FROM resource_subscriptions WHERE resource_id = $1",
            ),
        ];
        macro_rules! delete {
            ($tx:ident, $lock:literal, $exists:literal) => {{
                let id = lock_resource!($tx, expected, $lock);
                for (table, statement) in OPTIONAL_DEPENDENCIES {
                    if *table == "resource_metrics_hourly" && !purge_metrics {
                        continue;
                    }
                    if sqlx::query_scalar::<_, bool>($exists)
                        .bind(table)
                        .fetch_one(&mut *$tx)
                        .await?
                    {
                        sqlx::query(*statement).bind(&id).execute(&mut *$tx).await?;
                    }
                }
                sqlx::query("DELETE FROM server_resource_association WHERE resource_id = $1")
                    .bind(&id)
                    .execute(&mut *$tx)
                    .await?;
                sqlx::query("DELETE FROM resources WHERE id = $1")
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
                    "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = $1)"
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
