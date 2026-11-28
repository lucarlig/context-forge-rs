// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};

use jiff::Timestamp;
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    catalog::{
        INSERT_RESOURCE, POSTGRES_TOOL_INSERT, RegistrationError, SQLITE_TOOL_INSERT,
        ToolDefinition, display_name, prompt_argument_schema, resource_registrations, slugify,
    },
    credentials::{CredentialCipher, decode_headers, decode_query},
    database::observed,
    oauth_client::OAuthConfig,
    upstream::DiscoveredMetadata,
};

use super::*;

pub(crate) struct CatalogRefreshInput<'a> {
    pub(crate) tools: &'a [ToolDefinition],
    pub(crate) capabilities: &'a Value,
    pub(crate) metadata: &'a DiscoveredMetadata,
    pub(crate) include_resources: bool,
    pub(crate) include_prompts: bool,
    pub(crate) completion: CatalogRefreshCompletion,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatalogRefreshCompletion {
    Refresh,
    Automatic,
    Activate,
    Recover,
    Initialize,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CatalogChanges {
    pub(crate) tools_added: usize,
    pub(crate) tools_updated: usize,
    pub(crate) tools_removed: usize,
    pub(crate) resources_added: usize,
    pub(crate) resources_updated: usize,
    pub(crate) resources_removed: usize,
    pub(crate) prompts_added: usize,
    pub(crate) prompts_updated: usize,
    pub(crate) prompts_removed: usize,
}

impl CatalogChanges {
    pub(crate) fn changed(&self) -> bool {
        [
            self.tools_added,
            self.tools_updated,
            self.tools_removed,
            self.resources_added,
            self.resources_updated,
            self.resources_removed,
            self.prompts_added,
            self.prompts_updated,
            self.prompts_removed,
        ]
        .into_iter()
        .any(|count| count > 0)
    }
}

#[derive(sqlx::FromRow)]
struct StoredTool {
    id: String,
    original_name: String,
    original_description: Option<String>,
    display_name: Option<String>,
    title: Option<String>,
    input_schema: String,
    output_schema: Option<String>,
    annotations: Option<String>,
}

#[derive(sqlx::FromRow)]
struct StoredResource {
    id: String,
    uri: String,
    uri_template: Option<String>,
    original_name: Option<String>,
    title: Option<String>,
    description: Option<String>,
    mime_type: Option<String>,
    size: Option<i32>,
}

#[derive(sqlx::FromRow)]
struct StoredPrompt {
    id: String,
    original_name: String,
    title: Option<String>,
    description: Option<String>,
    argument_schema: Option<String>,
}

const STORED_TOOLS: &str = "
    SELECT id, original_name, original_description, display_name, title,
        CAST(input_schema AS TEXT) AS input_schema, CAST(output_schema AS TEXT) AS output_schema,
        CAST(annotations AS TEXT) AS annotations
    FROM tools WHERE gateway_id = $1 AND integration_type = 'MCP'";
const STORED_RESOURCES: &str = "
    SELECT id, uri, uri_template, original_name, title, description, mime_type, size
    FROM resources WHERE gateway_id = $1";
const STORED_PROMPTS: &str = "
    SELECT id, original_name, title, description, CAST(argument_schema AS TEXT) AS argument_schema
    FROM prompts WHERE gateway_id = $1";

const TOOL_CONFLICT: &str = "
    SELECT EXISTS (
        SELECT 1 FROM tools WHERE name = $1 AND visibility = $2
        AND ($2 = 'public' OR ($2 = 'team' AND team_id = $3)
             OR ($2 = 'private' AND owner_email = $4))
    )";
const TOOL_DEPENDENCIES: &[(&str, &str)] = &[(
    "tool_metrics",
    "DELETE FROM tool_metrics WHERE tool_id = $1",
)];
const TOOL_REMOVAL: &[&str] = &[
    "DELETE FROM server_tool_association WHERE tool_id = $1",
    "DELETE FROM tools WHERE id = $1",
];
const RESOURCE_DEPENDENCIES: &[(&str, &str)] = &[
    (
        "resource_metrics",
        "DELETE FROM resource_metrics WHERE resource_id = $1",
    ),
    (
        "resource_subscriptions",
        "DELETE FROM resource_subscriptions WHERE resource_id = $1",
    ),
];
const RESOURCE_REMOVAL: &[&str] = &[
    "DELETE FROM server_resource_association WHERE resource_id = $1",
    "DELETE FROM resources WHERE id = $1",
];
const PROMPT_DEPENDENCIES: &[(&str, &str)] = &[(
    "prompt_metrics",
    "DELETE FROM prompt_metrics WHERE prompt_id = $1",
)];
const PROMPT_REMOVAL: &[&str] = &[
    "DELETE FROM server_prompt_association WHERE prompt_id = $1",
    "DELETE FROM prompts WHERE id = $1",
];

const GATEWAY_NAME_CONFLICT: &str = "
    SELECT EXISTS (
        SELECT 1 FROM gateways WHERE id <> $1 AND slug = $2 AND visibility = $3
        AND ($3 = 'public' OR ($3 = 'team' AND team_id = $4)
             OR ($3 = 'private' AND owner_email = $5))
    )";
const GATEWAY_URL_CANDIDATES: &str = "
    SELECT auth_type, CAST(auth_value AS TEXT), CAST(auth_query_params AS TEXT),
        CAST(sigv4_config AS TEXT), CAST(oauth_config AS TEXT)
    FROM gateways WHERE id <> $1 AND url = $2 AND visibility = $3
    AND ($3 = 'public' OR ($3 = 'team' AND team_id = $4)
         OR ($3 = 'private' AND owner_email = $5))";
type AuthCandidate = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);
const GATEWAY_TOOL_NAME_CONFLICT: &str = "
    SELECT EXISTS (
        SELECT 1 FROM tools changed JOIN tools existing ON
            changed.id <> existing.id AND changed.name = existing.name AND changed.visibility = existing.visibility
        WHERE changed.gateway_id = $1 AND
            (changed.visibility = 'public' OR
             (changed.visibility = 'team' AND changed.team_id = existing.team_id) OR
             (changed.visibility = 'private' AND changed.owner_email = existing.owner_email))
    )";
const RENAMED_CATALOG_ITEMS: &[&str] = &[
    "UPDATE tools SET name = $2 || '-' || custom_name_slug WHERE gateway_id = $1 AND name = $3 || '-' || custom_name_slug",
    "UPDATE resources SET name = $2 || '-' || custom_name_slug WHERE gateway_id = $1 AND name = $3 || '-' || custom_name_slug",
    "UPDATE prompts SET name = $2 || '-' || custom_name_slug WHERE gateway_id = $1 AND name = $3 || '-' || custom_name_slug",
];
const SCOPED_CATALOG_ITEMS: &[&str] = &[
    "UPDATE tools SET visibility = CASE WHEN visibility = $2 THEN $3 ELSE visibility END,
        team_id = CASE WHEN team_id IS NOT DISTINCT FROM $4 THEN $5 ELSE team_id END WHERE gateway_id = $1",
    "UPDATE resources SET visibility = CASE WHEN visibility = $2 THEN $3 ELSE visibility END,
        team_id = CASE WHEN team_id IS NOT DISTINCT FROM $4 THEN $5 ELSE team_id END WHERE gateway_id = $1",
    "UPDATE prompts SET visibility = CASE WHEN visibility = $2 THEN $3 ELSE visibility END,
        team_id = CASE WHEN team_id IS NOT DISTINCT FROM $4 THEN $5 ELSE team_id END WHERE gateway_id = $1",
];

fn stored_json(raw: Option<&str>) -> Option<Value> {
    raw.and_then(|raw| serde_json::from_str(raw).ok())
        .filter(|value: &Value| !value.is_null())
}

fn nonempty_stored_headers(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !matches!(value.trim(), "" | "null" | "{}" | "\"\""))
}

fn same_gateway_auth(
    gateway: &GatewayRecord,
    candidate: &AuthCandidate,
    cipher: Option<&CredentialCipher>,
) -> bool {
    let (kind, headers, query, sigv4, oauth) = candidate;
    match (gateway.auth_type.as_deref(), kind.as_deref()) {
        (Some("oauth"), Some("oauth")) => gateway
            .oauth_config
            .as_deref()
            .zip(oauth.as_deref())
            .is_some_and(|(left, right)| OAuthConfig::matches_stored(left, right)),
        (Some("sigv4"), Some("sigv4")) => {
            let config =
                stored_json(gateway.sigv4_config.as_deref()).zip(stored_json(sigv4.as_deref()));
            config.is_some_and(|(left, right)| {
                ["access_key_id", "region", "service"]
                    .into_iter()
                    .all(|key| left[key].is_string() && left[key] == right[key])
            })
        }
        (Some("query_param"), Some("query_param")) => gateway
            .auth_query_params
            .as_deref()
            .zip(query.as_deref())
            .is_some_and(|(left, right)| {
                decode_query(cipher, left)
                    .is_ok_and(|left| decode_query(cipher, right).is_ok_and(|right| left == right))
            }),
        (Some("oauth" | "sigv4" | "query_param"), _)
        | (_, Some("oauth" | "sigv4" | "query_param")) => false,
        _ => {
            match (
                nonempty_stored_headers(gateway.auth_value.as_deref()),
                nonempty_stored_headers(headers.as_deref()),
            ) {
                (None, None) => true,
                (Some(left), Some(right)) => decode_headers(cipher, left).is_ok_and(|left| {
                    decode_headers(cipher, right).is_ok_and(|right| left == right)
                }),
                _ => false,
            }
        }
    }
}

macro_rules! json_parameter {
    (sqlite, $parameter:literal) => {
        concat!("json(", $parameter, ")")
    };
    (postgres, $parameter:literal) => {
        concat!("CAST(", $parameter, " AS JSON)")
    };
}

macro_rules! apply_gateway_metadata {
    ($tx:ident, $dialect:ident, $before:ident, $after:ident, $cipher:ident, $client_key:ident) => {{
        let renamed = $before.slug != $after.slug;
        let scope_changed = $before.visibility != $after.visibility || $before.team_id != $after.team_id;
        if (renamed || scope_changed)
            && sqlx::query_scalar::<_, bool>(GATEWAY_NAME_CONFLICT)
                .bind(&$after.id).bind(&$after.slug).bind(&$after.visibility)
                .bind($after.team_id.as_deref()).bind($after.owner_email.as_deref())
                .fetch_one(observed(&mut *$tx)).await?
        {
            return Err(RegistrationError::NameConflict);
        }
        let auth_changed = $after.auth_type != $before.auth_type
            || $after.auth_value != $before.auth_value
            || $after.auth_query_params != $before.auth_query_params
            || $after.sigv4_config != $before.sigv4_config
            || $after.oauth_config != $before.oauth_config;
        if scope_changed || $after.url != $before.url || auth_changed {
            let candidates = sqlx::query_as::<_, AuthCandidate>(GATEWAY_URL_CANDIDATES)
                .bind(&$after.id).bind(&$after.url).bind(&$after.visibility)
                .bind($after.team_id.as_deref()).bind($after.owner_email.as_deref())
                .fetch_all(observed(&mut *$tx)).await?;
            if $after.auth_type.as_deref() != Some("one_time_auth")
                && candidates.iter().any(|candidate| same_gateway_auth($after, candidate, $cipher))
            {
                return Err(RegistrationError::UrlConflict);
            }
        }
        sqlx::query(concat!("UPDATE gateways SET name = $2, slug = $3, description = $4,
            visibility = $5, team_id = $6, tags = ", json_parameter!($dialect, "$7"),
            ", passthrough_headers = ", json_parameter!($dialect, "$8"),
            ", identity_propagation = ", json_parameter!($dialect, "$9"),
            ", refresh_interval_seconds = $10, gateway_mode = $11,
            modified_by = $12, modified_from_ip = $13, modified_via = $30, modified_user_agent = $14,
            url = $15, transport = $16, reachable = $17, auth_type = $18,
            auth_value = ", json_parameter!($dialect, "$19"),
            ", auth_query_params = ", json_parameter!($dialect, "$20"),
            ", sigv4_config = ", json_parameter!($dialect, "$21"),
            ", oauth_config = ", json_parameter!($dialect, "$22"), ",
            ca_certificate = $23, ca_certificate_sig = $24, signing_algorithm = $25,
            client_cert = $26, client_key = CASE WHEN $27 THEN $28 ELSE client_key END,
            status = $29,
            status_message = CASE WHEN $29 = 'pending' THEN 'Gateway update accepted and pending initialization' ELSE status_message END,
            registration_attempts = CASE WHEN $29 = 'pending' THEN 0 ELSE registration_attempts END,
            next_retry_at = CASE WHEN $29 = 'pending' THEN NULL ELSE next_retry_at END,
            last_error = CASE WHEN $29 = 'pending' THEN NULL ELSE last_error END,
            updated_at = CURRENT_TIMESTAMP, version = version + 1 WHERE id = $1"))
            .bind(&$after.id).bind(&$after.name).bind(&$after.slug).bind($after.description.as_deref())
            .bind(&$after.visibility).bind($after.team_id.as_deref()).bind(&$after.tags)
            .bind($after.passthrough_headers.as_deref()).bind($after.identity_propagation.as_deref())
            .bind($after.refresh_interval_seconds).bind(&$after.gateway_mode).bind($after.modified_by.as_deref())
            .bind($after.modified_from_ip.as_deref()).bind($after.modified_user_agent.as_deref())
            .bind(&$after.url).bind(&$after.transport).bind($after.reachable)
            .bind($after.auth_type.as_deref()).bind($after.auth_value.as_deref())
            .bind($after.auth_query_params.as_deref()).bind($after.sigv4_config.as_deref())
            .bind($after.oauth_config.as_deref())
            .bind($after.ca_certificate.as_deref()).bind($after.ca_certificate_sig.as_deref())
            .bind($after.signing_algorithm.as_deref()).bind($after.client_cert.as_deref())
            .bind($client_key.is_some()).bind($client_key.flatten())
            .bind(&$after.status)
            .bind($after.modified_via.as_deref())
            .execute(observed(&mut *$tx)).await?;
        if ($after.url != $before.url || $after.auth_type != $before.auth_type
            || $after.oauth_config != $before.oauth_config)
            && ($after.oauth_config.is_some() || $before.oauth_config.is_some())
        {
            for statement in [
                "DELETE FROM oauth_states WHERE gateway_id = $1",
                "DELETE FROM oauth_tokens WHERE gateway_id = $1",
            ] {
                sqlx::query(statement).bind(&$after.id).execute(observed(&mut *$tx)).await?;
            }
        }
        if renamed {
            for statement in RENAMED_CATALOG_ITEMS {
                sqlx::query(*statement).bind(&$after.id).bind(&$after.slug).bind(&$before.slug)
                    .execute(observed(&mut *$tx)).await?;
            }
        }
        if scope_changed {
            for statement in SCOPED_CATALOG_ITEMS {
                sqlx::query(*statement).bind(&$after.id).bind(&$before.visibility).bind(&$after.visibility)
                    .bind($before.team_id.as_deref()).bind($after.team_id.as_deref())
                    .execute(observed(&mut *$tx)).await?;
            }
        }
        if $after.url != $before.url || $after.transport != $before.transport {
            sqlx::query("UPDATE tools SET url = $2, request_type = $3
                WHERE gateway_id = $1 AND integration_type = 'MCP'")
                .bind(&$after.id).bind(&$after.url).bind(&$after.transport)
                .execute(observed(&mut *$tx)).await?;
        }
        if (renamed || scope_changed) && sqlx::query_scalar::<_, bool>(GATEWAY_TOOL_NAME_CONFLICT)
            .bind(&$after.id).fetch_one(observed(&mut *$tx)).await?
        {
            return Err(RegistrationError::ToolNameConflict);
        }
    }};
}

macro_rules! refresh_metadata {
    ($tx:ident, $exists:literal, $dialect:ident, $gateway:ident, $input:ident, $changes:ident) => {{
        if $input.include_resources {
            let mut existing: HashMap<_, _> = sqlx::query_as::<_, StoredResource>(STORED_RESOURCES)
                .bind(&$gateway.id).fetch_all(observed(&mut *$tx)).await?
                .into_iter().map(|row| ((row.uri.clone(), row.uri_template.is_some()), row)).collect();
            let mut seen = HashSet::new();
            for item in resource_registrations($input.metadata) {
                if !seen.insert((item.uri, item.template.is_some())) {
                    continue;
                }
                let slug = slugify(item.name);
                let name = format!("{}-{slug}", $gateway.slug);
                if slug.is_empty() || name.len() > 255 || item.uri.is_empty() || item.uri.len() > 767 {
                    return Err(RegistrationError::Invalid("Invalid upstream resource"));
                }
                if let Some(previous) = existing.remove(&(item.uri.to_owned(), item.template.is_some())) {
                    if previous.original_name.as_deref() != Some(item.name)
                        || previous.title.as_deref() != item.title
                        || previous.description.as_deref() != item.description
                        || previous.mime_type.as_deref() != Some(item.mime)
                        || previous.size != item.size
                    {
                        sqlx::query("UPDATE resources SET original_name = $2, title = $3,
                            description = $4, mime_type = $5, size = $6, updated_at = CURRENT_TIMESTAMP WHERE id = $1")
                            .bind(previous.id).bind(item.name).bind(item.title).bind(item.description)
                            .bind(item.mime).bind(item.size).execute(observed(&mut *$tx)).await?;
                        $changes.resources_updated += 1;
                    }
                } else {
                    sqlx::query(INSERT_RESOURCE)
                        .bind(Uuid::new_v4().simple().to_string())
                        .bind(item.uri).bind(item.template).bind(name).bind(item.name).bind(slug)
                        .bind(item.title).bind(item.description).bind(item.mime).bind(item.size)
                        .bind(&$gateway.id).bind($gateway.owner_email.as_deref())
                        .bind($gateway.team_id.as_deref()).bind(&$gateway.visibility)
                        .execute(observed(&mut *$tx)).await?;
                    $changes.resources_added += 1;
                }
            }
            for previous in existing.into_values() {
                delete_catalog_rows!($tx, &previous.id, $exists, RESOURCE_DEPENDENCIES, RESOURCE_REMOVAL);
                $changes.resources_removed += 1;
            }
        }

        if $input.include_prompts {
            let mut existing: HashMap<_, _> = sqlx::query_as::<_, StoredPrompt>(STORED_PROMPTS)
                .bind(&$gateway.id).fetch_all(observed(&mut *$tx)).await?
                .into_iter().map(|row| (row.original_name.clone(), row)).collect();
            let mut seen = HashSet::new();
            for item in &$input.metadata.prompts {
                if !seen.insert(item.name.as_str()) {
                    continue;
                }
                let slug = slugify(&item.name);
                let name = format!("{}-{slug}", $gateway.slug);
                if slug.is_empty() || name.len() > 255 || item.name.len() > 255 {
                    return Err(RegistrationError::Invalid("Invalid upstream prompt"));
                }
                let arguments = prompt_argument_schema(item);
                if let Some(previous) = existing.remove(&item.name) {
                    if previous.title != item.title || previous.description != item.description
                        || stored_json(previous.argument_schema.as_deref()).as_ref() != Some(&arguments)
                    {
                        sqlx::query(concat!("UPDATE prompts SET title = $2, description = $3,
                            argument_schema = ", json_parameter!($dialect, "$4"),
                            ", updated_at = CURRENT_TIMESTAMP WHERE id = $1"))
                            .bind(previous.id).bind(&item.title).bind(&item.description)
                            .bind(arguments.to_string()).execute(observed(&mut *$tx)).await?;
                        $changes.prompts_updated += 1;
                    }
                } else {
                    sqlx::query(concat!("INSERT INTO prompts (id, name, original_name, custom_name,
                        custom_name_slug, title, description, argument_schema, gateway_id, owner_email,
                        team_id, visibility, enabled, tags, created_at, updated_at)
                        VALUES ($1,$2,$3,$3,$4,$5,$6,", json_parameter!($dialect, "$7"), ",$8,$9,$10,$11,
                            TRUE,'[]',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
                        .bind(Uuid::new_v4().simple().to_string()).bind(name).bind(&item.name)
                        .bind(slug).bind(&item.title).bind(&item.description).bind(arguments.to_string())
                        .bind(&$gateway.id).bind($gateway.owner_email.as_deref())
                        .bind($gateway.team_id.as_deref()).bind(&$gateway.visibility)
                        .execute(observed(&mut *$tx)).await?;
                    $changes.prompts_added += 1;
                }
            }
            for previous in existing.into_values() {
                delete_catalog_rows!($tx, &previous.id, $exists, PROMPT_DEPENDENCIES, PROMPT_REMOVAL);
                $changes.prompts_removed += 1;
            }
        }
    }};
}

impl Database {
    pub(crate) async fn refresh_catalog(
        &self,
        gateway: &GatewayRecord,
        input: CatalogRefreshInput<'_>,
    ) -> Result<Option<CatalogChanges>, RegistrationError> {
        self.write_gateway_catalog(gateway, gateway, Some(input), false, None, None)
            .await
    }

    pub(crate) async fn update_gateway_metadata(
        &self,
        expected: &GatewayRecord,
        gateway: &GatewayRecord,
        input: Option<CatalogRefreshInput<'_>>,
        cipher: Option<&CredentialCipher>,
        client_key: Option<Option<&str>>,
    ) -> Result<Option<CatalogChanges>, RegistrationError> {
        self.write_gateway_catalog(expected, gateway, input, true, cipher, client_key)
            .await
    }

    async fn write_gateway_catalog(
        &self,
        expected: &GatewayRecord,
        gateway: &GatewayRecord,
        input: Option<CatalogRefreshInput<'_>>,
        updating: bool,
        cipher: Option<&CredentialCipher>,
        client_key: Option<Option<&str>>,
    ) -> Result<Option<CatalogChanges>, RegistrationError> {
        let mut names = HashSet::new();
        for tool in input.as_ref().into_iter().flat_map(|input| input.tools) {
            let slug = slugify(&tool.name);
            if slug.is_empty() || slug.len() + gateway.slug.len() >= 255 || tool.name.len() > 255 {
                return Err(RegistrationError::Invalid("Invalid upstream tool name"));
            }
            if !names.insert(slug) {
                return Err(RegistrationError::ToolNameConflict);
            }
        }
        let mut changes = CatalogChanges::default();
        macro_rules! sync {
            ($transaction:ident, $lock:literal, $exists:literal, $insert_tool:expr,
             $dialect:ident, $now:literal) => {{
                let id = lock_gateway!($transaction, expected, $lock);
                if id.is_none() {
                    return Ok(None);
                }
                if updating {
                    apply_gateway_metadata!($transaction, $dialect, expected, gateway, cipher, client_key);
                }
                let Some(input) = input else {
                    $transaction.commit().await?;
                    return Ok(Some(changes));
                };
                let mut stored_tools: HashMap<_, _> = sqlx::query_as::<_, StoredTool>(STORED_TOOLS)
                    .bind(&gateway.id).fetch_all(observed(&mut *$transaction)).await?
                    .into_iter().map(|tool| (tool.original_name.clone(), tool)).collect();
                let incoming: HashSet<&str> = input.tools.iter().map(|tool| tool.name.as_str()).collect();
                for (_, stale) in stored_tools.extract_if(|name, _| !incoming.contains(name.as_str())) {
                    delete_catalog_rows!($transaction, &stale.id, $exists, TOOL_DEPENDENCIES, TOOL_REMOVAL);
                    changes.tools_removed += 1;
                }
                for tool in input.tools {
                    let annotations = tool.annotations.clone().unwrap_or_else(|| json!({}));
                    if let Some(previous) = stored_tools.remove(&tool.name) {
                        let description = (!tool.description.is_empty()).then_some(tool.description.as_str());
                        if previous.display_name.is_none()
                            || previous.original_description.as_deref().filter(|text| !text.is_empty()) != description
                            || previous.title != tool.title
                            || stored_json(Some(&previous.input_schema)).as_ref() != Some(&tool.input_schema)
                            || stored_json(previous.output_schema.as_deref()) != tool.output_schema
                            || stored_json(previous.annotations.as_deref()).unwrap_or_else(|| json!({})) != annotations
                        {
                            sqlx::query(concat!("UPDATE tools SET
                                description = CASE WHEN COALESCE(description, '') = COALESCE(original_description, '') THEN $2 ELSE description END,
                                original_description = $2, title = $3, input_schema = ", json_parameter!($dialect, "$4"), ",
                                output_schema = ", json_parameter!($dialect, "$5"), ", annotations = ", json_parameter!($dialect, "$6"), ",
                                display_name = COALESCE(display_name, $7),
                                updated_at = CURRENT_TIMESTAMP WHERE id = $1"))
                                .bind(previous.id).bind(&tool.description).bind(&tool.title)
                                .bind(tool.input_schema.to_string()).bind(tool.output_schema.as_ref().map(Value::to_string))
                                .bind(annotations.to_string()).bind(display_name(&tool.name))
                                .execute(observed(&mut *$transaction)).await?;
                            changes.tools_updated += 1;
                        }
                    } else {
                        let slug = slugify(&tool.name);
                        let name = format!("{}-{slug}", gateway.slug);
                        if sqlx::query_scalar::<_,bool>(TOOL_CONFLICT)
                            .bind(&name).bind(&gateway.visibility).bind(gateway.team_id.as_deref())
                            .bind(gateway.owner_email.as_deref()).fetch_one(observed(&mut *$transaction)).await?
                        {
                            return Err(RegistrationError::ToolNameConflict);
                        }
                        sqlx::query($insert_tool)
                            .bind(Uuid::new_v4().simple().to_string()).bind(&gateway.id)
                            .bind(name).bind(&tool.name).bind(slug).bind(&tool.description).bind(&tool.title)
                            .bind(tool.input_schema.to_string()).bind(tool.output_schema.as_ref().map(Value::to_string))
                            .bind(annotations.to_string()).bind(&gateway.url).bind(gateway.owner_email.as_deref())
                            .bind(gateway.team_id.as_deref()).bind(&gateway.visibility).bind(&gateway.transport)
                            .bind(display_name(&tool.name))
                            .execute(observed(&mut *$transaction)).await?;
                        changes.tools_added += 1;
                    }
                }
                refresh_metadata!($transaction, $exists, $dialect, gateway, input, changes);
                let now = Timestamp::now().to_string();
                let stamp_seen = updating || matches!(input.completion, CatalogRefreshCompletion::Activate | CatalogRefreshCompletion::Initialize);
                let stamp_refresh = !updating && matches!(input.completion, CatalogRefreshCompletion::Refresh | CatalogRefreshCompletion::Automatic);
                sqlx::query(concat!("UPDATE gateways SET capabilities = ", json_parameter!($dialect, "$2"),
                    ", last_refresh_at = CASE WHEN $5 THEN ", $now, " ELSE last_refresh_at END,
                    last_seen = CASE WHEN $4 THEN ", $now, " ELSE last_seen END,
                    updated_at = ", $now, " WHERE id = $1"))
                    .bind(&gateway.id).bind(input.capabilities.to_string()).bind(&now).bind(stamp_seen)
                    .bind(stamp_refresh)
                    .execute(observed(&mut *$transaction)).await?;
                match input.completion {
                    CatalogRefreshCompletion::Activate => set_gateway_state!($transaction, &gateway.id, true, &now, $now),
                    CatalogRefreshCompletion::Automatic | CatalogRefreshCompletion::Recover =>
                        write_gateway_health!($transaction, &gateway.id, true, &now, None::<&str>, $now),
                    CatalogRefreshCompletion::Refresh if updating =>
                        write_gateway_health!($transaction, &gateway.id, true, &now, None::<&str>, $now),
                    CatalogRefreshCompletion::Initialize =>
                        finish_gateway_initialization!($transaction, gateway, &now, $now),
                    CatalogRefreshCompletion::Refresh => {}
                }
                $transaction.commit().await?;
                Ok(Some(changes))
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
                sync!(
                    transaction,
                    "",
                    "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = $1)",
                    SQLITE_TOOL_INSERT,
                    sqlite,
                    "$3"
                )
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                sqlx::query(CATALOG_LOCK)
                    .execute(observed(&mut *transaction))
                    .await?;
                sync!(
                    transaction,
                    " FOR UPDATE",
                    "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL",
                    POSTGRES_TOOL_INSERT,
                    postgres,
                    "CAST(CAST($3 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }
}
