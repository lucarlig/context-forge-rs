// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    catalog::{CATALOG_LOCK, CatalogScope, delete_tool_dependencies, visible_team_ids},
    grpc::ReflectedMethod,
};

#[derive(Debug, thiserror::Error)]
pub(super) enum ServiceWriteError {
    #[error("gRPC service has changed")]
    Changed,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub(super) enum ServiceChange<'a> {
    Config {
        config: &'a ServiceConfig,
        modified_by: &'a str,
        client_ip: Option<&'a str>,
        user_agent: Option<&'a str>,
    },
    State(bool),
    Reflection(Option<&'a Discovery>),
    Delete,
}

macro_rules! select_service {
    () => {
        "SELECT s.id, s.name, s.slug, s.description, s.target, s.reflection_enabled, s.tls_enabled,
           s.tls_cert_path, s.tls_key_path, COALESCE(s.grpc_metadata, '{}') AS grpc_metadata,
           s.enabled, s.reachable, s.service_count, s.method_count,
           COALESCE(s.discovered_services, '{}') AS discovered_services,
           REPLACE(CAST(s.last_reflection AS TEXT), ' ', 'T') AS last_reflection, s.tags,
           REPLACE(CAST(s.created_at AS TEXT), ' ', 'T') AS created_at,
           REPLACE(CAST(s.updated_at AS TEXT), ' ', 'T') AS updated_at, s.version,
           s.team_id, t.name AS team, s.owner_email, s.visibility
         FROM grpc_services s
         LEFT JOIN email_teams t ON t.id = s.team_id AND t.is_active = TRUE"
    };
}

const SELECT_ONE: &str = concat!(select_service!(), " WHERE s.id = $1");
const SELECT_NAMED: &str = concat!(select_service!(), " WHERE s.name = $1");

macro_rules! scoped_services {
    ($teams:literal, $select:expr, $suffix:literal) => {
        concat!(
            "WITH visible_teams(id) AS (", $teams, ") ", $select,
            " WHERE ($1 OR s.enabled)
                 AND (CAST($2 AS TEXT) IS NULL OR s.team_id = $2)
                 AND (s.visibility = 'public'
                      OR (s.visibility = 'team' AND ($4 OR s.team_id IN (SELECT id FROM visible_teams)))
                      OR (s.visibility = 'private' AND $5 AND s.owner_email = $3))",
            $suffix
        )
    };
}

macro_rules! insert_service_sql {
    ($now:literal) => {
        concat!(
            "INSERT INTO grpc_services (
                id, slug, name, target, description, reflection_enabled, tls_enabled, tls_cert_path,
                tls_key_path, grpc_metadata, tags, team_id, owner_email, visibility, enabled,
                reachable, service_count, method_count, discovered_services,
                created_at, updated_at, created_by, created_from_ip, created_via, created_user_agent, version
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, TRUE,
                FALSE, 0, 0, '{}', ", $now, ", ", $now, ", $13, $15, 'api', $16, 1)"
        )
    };
}

const INSERT_TOOL: &str = "
    INSERT INTO tools (id, name, original_name, custom_name, custom_name_slug, url, description,
        original_description, integration_type, grpc_service_id, input_schema, annotations,
        request_type, enabled, reachable, deprecated, expose_passthrough, jsonpath_filter,
        tags, created_at, updated_at, created_by, created_via, federation_source, version,
        team_id, owner_email, visibility)
    VALUES ($1, $2, $3, $3, $2, $4, $5, $5, 'gRPC', $6, $7, '{}',
        'SSE', TRUE, TRUE, FALSE, TRUE, '', '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
        'system', 'grpc-reflection', $8, 1, $9, $10, $11)";

const UPDATE_DISCOVERED_TOOL: &str = "
    UPDATE tools SET url = $2,
        description = CASE WHEN description IS NOT DISTINCT FROM original_description
            THEN $3 ELSE description END,
        original_description = $3, input_schema = $4,
        team_id = $5, owner_email = $6, visibility = $7
    WHERE id = $1";

macro_rules! service_write {
    ($db:expr, $operation:ident) => {
        match $db {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                $operation!(
                    tx,
                    "STRFTIME('%Y-%m-%d %H:%M:%f', 'now')",
                    "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE name = $1 AND type = 'table')"
                )
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(CATALOG_LOCK).execute(&mut *tx).await?;
                $operation!(
                    tx,
                    "CURRENT_TIMESTAMP",
                    "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL"
                )
            }
        }
    };
}

macro_rules! remove_tool {
    ($tx:ident, $tool:expr, $table_exists:literal) => {{
        let tool = $tool;
        delete_tool_dependencies!($tx, tool, true, $table_exists);
        sqlx::query("DELETE FROM tools WHERE id = $1")
            .bind(tool)
            .execute(&mut *$tx)
            .await?;
    }};
}

macro_rules! save_discovery {
    ($tx:ident, $now:literal, $exists:literal, $service:expr, $config:expr, $owner:expr, $discovery:expr) => {{
        let id = $service;
        let config = $config;
        let owner = $owner;
        let discovery = $discovery;
        let service_count = discovery.services.len() as i32;
        let method_count: i32 = discovery
            .services
            .values()
            .map(|service| service.methods.len() as i32)
            .sum();
        let mut tools = sqlx::query_as::<_, (String, String)>(
            "SELECT original_name, id FROM tools WHERE grpc_service_id = $1 ORDER BY id",
        )
        .bind(id)
        .fetch_all(&mut *$tx)
        .await?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
        for (service, details) in &discovery.services {
            for method in &details.methods {
                let full_name = format!("{service}.{}", method.name);
                if full_name.len() > 255 {
                    continue;
                }
                let description = format!("gRPC method {full_name}");
                let input_schema = DbJson(method_schema(method));
                if let Some(tool_id) = tools.remove(&full_name) {
                    sqlx::query(UPDATE_DISCOVERED_TOOL)
                        .bind(tool_id)
                        .bind(&config.target)
                        .bind(description)
                        .bind(input_schema)
                        .bind(&config.team_id)
                        .bind(owner)
                        .bind(&config.visibility)
                        .execute(&mut *$tx)
                        .await?;
                } else {
                    sqlx::query(INSERT_TOOL)
                        .bind(Uuid::new_v4().simple().to_string())
                        .bind(slugify(&full_name))
                        .bind(full_name)
                        .bind(&config.target)
                        .bind(description)
                        .bind(id)
                        .bind(input_schema)
                        .bind(&config.name)
                        .bind(&config.team_id)
                        .bind(owner)
                        .bind(&config.visibility)
                        .execute(&mut *$tx)
                        .await?;
                }
            }
        }
        for id in tools.values() {
            remove_tool!($tx, id, $exists);
        }
        sqlx::query(concat!(
            "UPDATE grpc_services SET reachable = TRUE, service_count = $2, method_count = $3,
                discovered_services = $4, last_reflection = ",
            $now,
            ", updated_at = ",
            $now,
            " WHERE id = $1"
        ))
        .bind(id)
        .bind(service_count)
        .bind(method_count)
        .bind(DbJson(discovery.stored()))
        .execute(&mut *$tx)
        .await?;
    }};
}

impl Database {
    pub(super) async fn load_grpc_service(
        &self,
        id: &str,
    ) -> Result<Option<ServiceRecord>, sqlx::Error> {
        self.select_grpc_service(SELECT_ONE, id).await
    }

    pub(super) async fn grpc_service_named(
        &self,
        name: &str,
    ) -> Result<Option<ServiceRecord>, sqlx::Error> {
        self.select_grpc_service(SELECT_NAMED, name).await
    }

    async fn select_grpc_service(
        &self,
        query: &'static str,
        value: &str,
    ) -> Result<Option<ServiceRecord>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => sqlx::query_as(query).bind(value).fetch_optional(pool).await,
            Self::Postgres(pool) => sqlx::query_as(query).bind(value).fetch_optional(pool).await,
        }
    }

    pub(super) async fn list_grpc_services(
        &self,
        scope: CatalogScope<'_>,
        (include_inactive, team): (bool, Option<&str>),
        (page, per_page, max_offset): (i64, i64, i64),
    ) -> Result<(Vec<ServiceRecord>, PaginationMeta), sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        macro_rules! scoped {
            ($stmt:expr) => {
                $stmt
                    .bind(include_inactive)
                    .bind(team)
                    .bind(scope.email)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(&teams)
            };
        }
        macro_rules! fetch {
            ($tx:ident, $team_ids:literal) => {{
                let total_items = scoped!(sqlx::query_scalar::<_, i64>(scoped_services!(
                    $team_ids,
                    "SELECT COUNT(*) FROM grpc_services s",
                    ""
                )))
                .fetch_one(&mut *$tx)
                .await?;
                let meta = PaginationMeta::new(page, per_page, total_items);
                let offset = meta.offset(max_offset);
                let records = scoped!(sqlx::query_as(scoped_services!(
                    $team_ids,
                    select_service!(),
                    " ORDER BY s.created_at DESC, s.id DESC LIMIT $7 OFFSET $8"
                )))
                .bind(per_page)
                .bind(offset)
                .fetch_all(&mut *$tx)
                .await?;
                $tx.commit().await?;
                Ok((records, meta))
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                fetch!(tx, "SELECT value FROM json_each($6)")
            }
            Self::Postgres(pool) => {
                let mut tx = pool
                    .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    .await?;
                fetch!(tx, "SELECT json_array_elements_text(CAST($6 AS JSON))")
            }
        }
    }

    pub(super) async fn insert_grpc_service(
        &self,
        id: &str,
        slug: &str,
        config: &ServiceConfig,
        owner: &str,
        (client_ip, user_agent): (Option<&str>, Option<&str>),
        discovery: Option<&Discovery>,
    ) -> Result<ServiceRecord, sqlx::Error> {
        macro_rules! insert {
            ($tx:ident, $now:literal, $exists:literal) => {{
                sqlx::query(insert_service_sql!($now))
                    .bind(id)
                    .bind(slug)
                    .bind(&config.name)
                    .bind(&config.target)
                    .bind(&config.description)
                    .bind(config.reflection_enabled)
                    .bind(config.tls_enabled)
                    .bind(&config.tls_cert_path)
                    .bind(&config.tls_key_path)
                    .bind(&config.grpc_metadata)
                    .bind(&config.tags)
                    .bind(&config.team_id)
                    .bind(owner)
                    .bind(&config.visibility)
                    .bind(client_ip)
                    .bind(user_agent)
                    .execute(&mut *$tx)
                    .await?;
                if let Some(discovery) = discovery {
                    save_discovery!($tx, $now, $exists, id, config, Some(owner), discovery);
                }
                let record = sqlx::query_as(SELECT_ONE)
                    .bind(id)
                    .fetch_one(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(record)
            }};
        }
        service_write!(self, insert)
    }

    pub(super) async fn change_grpc_service(
        &self,
        prior: &ServiceRecord,
        change: ServiceChange<'_>,
    ) -> Result<Option<ServiceRecord>, ServiceWriteError> {
        let id = &prior.id;
        macro_rules! mutate {
            ($tx:ident, $now:literal, $exists:literal) => {{
                let touched = sqlx::query(concat!(
                    "UPDATE grpc_services SET version = version + 1, updated_at = ", $now,
                    " WHERE id = $1 AND version = $2"
                ))
                .bind(id)
                .bind(prior.version)
                .execute(&mut *$tx)
                .await?
                .rows_affected();
                if touched != 1 {
                    return Err(ServiceWriteError::Changed);
                }
                match change {
                    ServiceChange::Config { config, modified_by, client_ip, user_agent } => {
                        sqlx::query(
                            "UPDATE grpc_services SET name = $2, target = $3, description = $4,
                                reflection_enabled = $5, tls_enabled = $6, tls_cert_path = $7,
                                tls_key_path = $8, grpc_metadata = $9, tags = $10, visibility = $11,
                                modified_by = $12, modified_from_ip = $13,
                                modified_via = 'api', modified_user_agent = $14 WHERE id = $1",
                        ).bind(id)
                            .bind(&config.name)
                            .bind(&config.target)
                            .bind(&config.description)
                            .bind(config.reflection_enabled)
                            .bind(config.tls_enabled)
                            .bind(&config.tls_cert_path)
                            .bind(&config.tls_key_path)
                            .bind(&config.grpc_metadata)
                            .bind(&config.tags)
                            .bind(&config.visibility)
                            .bind(modified_by)
                            .bind(client_ip)
                            .bind(user_agent)
                            .execute(&mut *$tx)
                            .await?;
                        if config.visibility != prior.config.visibility {
                            sqlx::query("UPDATE tools SET visibility = $2 WHERE grpc_service_id = $1")
                                .bind(id)
                                .bind(&config.visibility)
                                .execute(&mut *$tx)
                                .await?;
                        }
                    }
                    ServiceChange::State(enabled) => {
                        sqlx::query("UPDATE grpc_services SET enabled = $2 WHERE id = $1")
                            .bind(id).bind(enabled).execute(&mut *$tx).await?;
                    }
                    ServiceChange::Reflection(Some(discovery)) => {
                        save_discovery!($tx, $now, $exists, id, &prior.config, prior.owner_email.as_deref(), discovery);
                    }
                    ServiceChange::Reflection(None) => {
                        sqlx::query("UPDATE grpc_services SET reachable = FALSE WHERE id = $1")
                            .bind(id).execute(&mut *$tx).await?;
                    }
                    ServiceChange::Delete => {
                        let tools = sqlx::query_scalar::<_, String>(
                            "SELECT id FROM tools WHERE grpc_service_id = $1",
                        ).bind(id).fetch_all(&mut *$tx).await?;
                        for tool_id in &tools {
                            remove_tool!($tx, tool_id, $exists);
                        }
                        sqlx::query("DELETE FROM grpc_services WHERE id = $1")
                            .bind(id).execute(&mut *$tx).await?;
                        $tx.commit().await?;
                        return Ok(None);
                    }
                }
                let record = sqlx::query_as(SELECT_ONE).bind(id).fetch_one(&mut *$tx).await?;
                $tx.commit().await?;
                Ok(Some(record))
            }};
        }
        service_write!(self, mutate)
    }
}

fn method_schema(method: &ReflectedMethod) -> Value {
    json!({
        "type": "object",
        "properties": {},
        "x-grpc-input-type": method.input_type,
        "x-grpc-output-type": method.output_type,
        "x-grpc-client-streaming": method.client_streaming,
        "x-grpc-server-streaming": method.server_streaming,
    })
}
