// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use axum::extract::Query;
use indexmap::IndexMap;
use serde_json::Map;

use crate::{
    catalog::{CatalogEntryFilters, CatalogScope, PromptRecord, ResourceRecord, ToolRecord},
    gateway_records::{GatewayList, GatewayRecord},
};

use super::{
    catalog_api::{CatalogApiError, normalized_tags, query_boolean, require_catalog_permission},
    *,
};

const ENTITY_TYPES: &[&str] = &[
    "tools",
    "gateways",
    "servers",
    "prompts",
    "resources",
    "roots",
];
const MASKED: &str = "*****";
const ENCRYPTED_HEADER: &str = "_mcpgateway_encrypted_header_value_v1";

pub struct ExportSettings {
    pub source_gateway: String,
    pub root_path: String,
    pub version: String,
}

impl Default for ExportSettings {
    fn default() -> Self {
        Self {
            source_gateway: "http://127.0.0.1:4444".into(),
            root_path: String::new(),
            version: "2025-11-25".into(),
        }
    }
}

#[derive(Deserialize)]
struct ExportQuery {
    types: Option<String>,
    exclude_types: Option<String>,
    tags: Option<String>,
    include_inactive: Option<String>,
    include_dependencies: Option<String>,
}

#[derive(Deserialize)]
struct SelectiveQuery {
    include_dependencies: Option<String>,
}

type Selections = BTreeMap<String, Vec<String>>;

enum Selection {
    All(Vec<String>),
    Specific(Selections),
}

struct ExportRequest {
    selection: Selection,
    tags: Vec<String>,
    include_inactive: bool,
    include_dependencies: bool,
}

impl ExportRequest {
    fn selective(&self) -> bool {
        matches!(self.selection, Selection::Specific(_))
    }

    fn includes(&self, kind: &str) -> bool {
        match &self.selection {
            Selection::All(types) => types.iter().any(|item| item == kind),
            Selection::Specific(entries) => entries.contains_key(kind),
        }
    }

    fn selection_for(&self, kind: &str) -> Option<&[String]> {
        match &self.selection {
            Selection::All(_) => None,
            Selection::Specific(entries) => entries.get(kind).map(Vec::as_slice),
        }
    }

    fn matches(&self, kind: &str, keys: &[&str]) -> bool {
        self.selection_for(kind)
            .is_none_or(|ids| ids.iter().any(|id| keys.contains(&id.as_str())))
    }

    fn catalog_filter(&self) -> CatalogEntryFilters<'_> {
        CatalogEntryFilters {
            tags: &self.tags,
            ..CatalogEntryFilters::associated(self.include_inactive)
        }
    }

    fn options(&self) -> Value {
        match &self.selection {
            Selection::All(types) => json!({
                "include_inactive":self.include_inactive,
                "include_dependencies":self.include_dependencies,
                "selected_types":types,"filter_tags":self.tags
            }),
            Selection::Specific(entries) => json!({
                "selective":true,"include_dependencies":self.include_dependencies,"selections":entries
            }),
        }
    }
}

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut routes = Router::new();
    for base in ["/export", "/v1/export"] {
        routes = routes
            .route(base, get(full_export))
            .route(&format!("{base}/selective"), post(selective_export));
    }
    routes
}

async fn full_export(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ExportQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    let include = entity_types(query.types.as_deref());
    let exclude = entity_types(query.exclude_types.as_deref());
    let includes_roots = if include.is_empty() {
        !exclude.iter().any(|kind| kind == "roots")
    } else {
        include.iter().any(|kind| kind == "roots")
    };
    authorize(&service, &principal, includes_roots).await?;
    let mut types = include;
    if types.is_empty() {
        types = ENTITY_TYPES.iter().map(|kind| (*kind).into()).collect();
    }
    types.retain(|kind| ENTITY_TYPES.contains(&kind.as_str()) && !exclude.contains(kind));
    let request = ExportRequest {
        selection: Selection::All(types),
        tags: csv(query.tags.as_deref()).map(str::to_owned).collect(),
        include_inactive: query_boolean(
            "include_inactive",
            query.include_inactive.as_deref(),
            false,
        )?,
        include_dependencies: query_boolean(
            "include_dependencies",
            query.include_dependencies.as_deref(),
            true,
        )?,
    };
    configuration(&service, &principal, &request).await
}

async fn selective_export(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<SelectiveQuery>,
    Json(selections): Json<Selections>,
) -> Result<Json<Value>, CatalogApiError> {
    authorize(
        &service,
        &principal,
        selections
            .get("roots")
            .is_some_and(|roots| !roots.is_empty()),
    )
    .await?;
    let request = ExportRequest {
        selection: Selection::Specific(selections),
        tags: Vec::new(),
        include_inactive: true,
        include_dependencies: query_boolean(
            "include_dependencies",
            query.include_dependencies.as_deref(),
            true,
        )?,
    };
    configuration(&service, &principal, &request).await
}

async fn authorize(
    service: &GatewayService,
    principal: &Principal,
    includes_roots: bool,
) -> Result<(), CatalogApiError> {
    require_catalog_permission(service, principal, "admin.export", true).await?;
    if includes_roots && !principal.is_global_admin() {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    Ok(())
}

async fn configuration(
    service: &GatewayService,
    principal: &Principal,
    request: &ExportRequest,
) -> Result<Json<Value>, CatalogApiError> {
    let scope = access::catalog_scope(Some(principal));
    let mut entities = Map::new();
    if request.includes("tools") {
        entities.insert(
            "tools".into(),
            json!(export_tools(service, scope, request).await?),
        );
    }
    if request.includes("gateways") {
        entities.insert(
            "gateways".into(),
            json!(export_gateways(service, scope, request).await?),
        );
    }
    if request.includes("servers") {
        entities.insert(
            "servers".into(),
            json!(export_servers(service, scope, request).await?),
        );
    }
    if request.includes("prompts") {
        let records = service
            .database
            .managed_prompts(scope, request.catalog_filter())
            .await?;
        let prompts = selected(records, request.selective(), |row| &row.id)
            .into_iter()
            .filter(|row| request.matches("prompts", &[&row.id, &row.name]))
            .map(|row| export_prompt(row, request.selective()))
            .collect::<Vec<_>>();
        entities.insert("prompts".into(), json!(prompts));
    }
    if request.includes("resources") {
        let records = service
            .database
            .managed_resources(scope, request.catalog_filter(), Some(false))
            .await?;
        let resources = selected(records, request.selective(), |row| &row.id)
            .into_iter()
            .filter(|row| request.matches("resources", &[&row.uri]))
            .map(|row| export_resource(row, request.selective()))
            .collect::<Vec<_>>();
        entities.insert("resources".into(), json!(resources));
    }
    if request.includes("roots") {
        entities.insert(
            "roots".into(),
            json!(
                service
                    .roots
                    .export_configuration(request.selection_for("roots"))
            ),
        );
    }

    let counts: Map<String, Value> = entities
        .iter()
        .filter_map(|(kind, values)| {
            values
                .as_array()
                .map(|entries| (kind.clone(), json!(entries.len())))
        })
        .collect();
    let dependencies = dependencies(&entities, request.include_dependencies);
    Ok(Json(json!({
        "version":service.export.version,
        "exported_at":Timestamp::now().strftime("%Y-%m-%dT%H:%M:%S.%6fZ").to_string(),
        "exported_by":principal.email,
        "source_gateway":service.export.source_gateway,
        "encryption_method":"AES-256-GCM",
        "entities":entities,
        "metadata":{
            "entity_counts":counts,"dependencies":dependencies,"export_options":request.options()
        }
    })))
}

fn dependencies(entities: &Map<String, Value>, enabled: bool) -> Value {
    if !enabled {
        return json!({});
    }
    let mut tools = Map::new();
    if entities.contains_key("tools")
        && let Some(servers) = entities.get("servers").and_then(Value::as_array)
    {
        for server in servers {
            if let Some(name) = server["name"].as_str()
                && server["tool_ids"]
                    .as_array()
                    .is_some_and(|ids| !ids.is_empty())
            {
                tools.insert(name.into(), server["tool_ids"].clone());
            }
        }
    }
    json!({"servers_to_tools":tools,"servers_to_resources":{},"servers_to_prompts":{}})
}

async fn export_tools(
    service: &GatewayService,
    scope: CatalogScope<'_>,
    request: &ExportRequest,
) -> Result<Vec<Value>, sqlx::Error> {
    let records = service
        .database
        .managed_tools(scope, request.catalog_filter())
        .await?;
    Ok(selected(records, request.selective(), |row| &row.id)
        .into_iter()
        .filter(|row| request.matches("tools", &[&row.id]))
        .filter(|row| !is_sigv4(row.auth_type.as_deref()))
        .filter(|row| row.gateway_id.is_none() || row.integration_type != "MCP")
        .map(|row| export_tool(row, service.credential_cipher.as_ref(), request.selective()))
        .collect())
}

fn export_tool(row: ToolRecord, cipher: Option<&CredentialCipher>, selective: bool) -> Value {
    let name = nonempty(&row.original_name).unwrap_or(&row.custom_name);
    let url = row.url.as_deref().map(|url| export_url(url, selective));
    let mut data = json!({
        "name": name,
        "displayName": row.display_name.as_deref().and_then(nonempty).unwrap_or(&row.custom_name),
        "url": url,"integration_type":row.integration_type,"request_type":row.request_type,
        "description":row.description,"headers":tool_headers(row.headers.as_deref(), cipher, selective),
        "input_schema":object(Some(&row.input_schema), json!({"type":"object","properties":{}})),
        "output_schema":parsed(row.output_schema.as_deref()),
        "annotations":object(row.annotations.as_deref(), json!({})),"jsonpath_filter":row.jsonpath_filter,
        "tool_validation_policy":row.tool_validation_policy,"tags":export_tags(&row.tags, selective),
        "rate_limit":null,"timeout":null,"is_active":row.enabled,
        "created_at":export_timestamp(&row.created_at),"updated_at":export_timestamp(&row.updated_at)
    });
    if !selective {
        data["original_description"] = json!(row.original_description);
    }
    if let (Some(kind), Some(value)) = (row.auth_type.as_deref(), row.auth_value.as_deref())
        && let Some(ciphertext) = verified_ciphertext(cipher, value)
    {
        data["auth_type"] = json!(kind);
        data["auth_value"] = json!(selective.then_some(ciphertext));
    }
    data
}

fn tool_headers(raw: Option<&str>, cipher: Option<&CredentialCipher>, selective: bool) -> Value {
    let mut headers = object(raw, json!({}));
    if let Some(headers) = headers.as_object_mut() {
        for value in headers.values_mut() {
            let encoded = value.get(ENCRYPTED_HEADER).and_then(Value::as_str);
            *value = match encoded
                .filter(|encoded| selective && verified_ciphertext(cipher, encoded).is_some())
            {
                Some(encoded) => json!({(ENCRYPTED_HEADER):encoded}),
                None => json!(MASKED),
            };
        }
    }
    headers
}

async fn export_gateways(
    service: &GatewayService,
    scope: CatalogScope<'_>,
    request: &ExportRequest,
) -> Result<Vec<Value>, CatalogApiError> {
    let records = service
        .database
        .listed_gateways(
            scope,
            GatewayList {
                include_inactive: request.include_inactive,
                visibility: None,
                team: None,
                after: None,
                limit: i64::MAX,
                offset: 0,
            },
        )
        .await?;
    selected(records, request.selective(), |row| &row.id)
        .into_iter()
        .filter(|row| request.matches("gateways", &[&row.id]))
        .filter(|row| !is_sigv4(row.auth_type.as_deref()))
        .filter(|row| request.tags.is_empty() || has_tag(&row.tags, &request.tags))
        .map(|row| export_gateway(row, service.credential_cipher.as_ref(), request.selective()))
        .collect()
}

fn export_gateway(
    row: GatewayRecord,
    cipher: Option<&CredentialCipher>,
    selective: bool,
) -> Result<Value, CatalogApiError> {
    let url = export_url(&row.url, selective);
    let mut data = json!({
        "name":row.name,"url":url,"description":row.description,"transport":row.transport,
        "capabilities":object(Some(&row.capabilities), json!({})),
        "health_check":{"url":format!("{url}/health"),"interval":30,"timeout":10,"retries":3},
        "is_active":row.enabled,"tags":export_tags(&row.tags, selective),
        "passthrough_headers":array(row.passthrough_headers.as_deref()),
        "tool_validation_policy":row.tool_validation_policy
    });
    if let Some(kind) = row.auth_type.as_deref().and_then(nonempty) {
        let auth = parsed(row.auth_value.as_deref());
        let encrypted = match auth {
            Value::String(value) => verified_ciphertext(cipher, &value).map(str::to_owned),
            Value::Object(ref values) if !values.is_empty() => Some(
                cipher
                    .and_then(|cipher| cipher.seal(&auth).ok())
                    .ok_or_else(|| {
                        CatalogApiError::detail(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Export credential encryption failed",
                        )
                    })?,
            ),
            _ => None,
        };
        if selective || encrypted.is_some() {
            data["auth_type"] = json!(kind);
        }
        if let Some(value) = encrypted {
            data["auth_value"] = json!(value);
        }
        if selective && kind == "query_param" {
            let mut query = object(row.auth_query_params.as_deref(), json!({}));
            if let Some(fields) = query.as_object_mut() {
                for value in fields.values_mut() {
                    if !value
                        .as_str()
                        .is_some_and(|text| verified_ciphertext(cipher, text).is_some())
                    {
                        *value = json!(MASKED);
                    }
                }
                if !fields.is_empty() {
                    data["auth_query_params"] = query;
                }
            }
        }
    }
    Ok(data)
}

async fn export_servers(
    service: &GatewayService,
    scope: CatalogScope<'_>,
    request: &ExportRequest,
) -> Result<Vec<Value>, sqlx::Error> {
    let records = service
        .database
        .managed_servers(scope, request.catalog_filter())
        .await?;
    let records = selected(records, request.selective(), |row| &row.id)
        .into_iter()
        .filter(|row| request.matches("servers", &[&row.id]))
        .collect::<Vec<_>>();
    let ids = records
        .iter()
        .map(|row| row.id.as_str())
        .collect::<Vec<_>>();
    let links = service.database.managed_server_links(&ids, scope).await?;
    Ok(records
        .into_iter()
        .map(|row| {
            let path = format!("{}/servers/{}", service.export.root_path, row.id);
            let tools = links
                .get(&row.id)
                .into_iter()
                .flat_map(|links| &links.tools)
                .map(|(id, name)| if request.selective() { id } else { name })
                .collect::<Vec<_>>();
            let mut data = json!({
                "name":row.name,"description":row.description,"tool_ids":tools,
                "sse_endpoint":format!("{path}/sse"),"websocket_endpoint":format!("{path}/ws"),
                "jsonrpc_endpoint":format!("{path}/jsonrpc"),
                "capabilities":{"tools":{"list_changed":true},"prompts":{"list_changed":true}},
                "is_active":row.enabled,"tags":export_tags(&row.tags, request.selective())
            });
            if !request.selective() {
                data["instructions"] = json!(row.instructions);
            }
            data
        })
        .collect())
}

fn export_prompt(row: PromptRecord, selective: bool) -> Value {
    let name = nonempty(&row.original_name).unwrap_or(&row.name);
    let custom = nonempty(&row.custom_name).unwrap_or(name);
    let display = row
        .display_name
        .as_deref()
        .and_then(nonempty)
        .unwrap_or(custom);
    let raw_schema = row.argument_schema.as_deref();
    let schema = if selective {
        object(
            raw_schema,
            json!({"type":"object","properties":{},"required":[]}),
        )
    } else {
        prompt_schema(raw_schema)
    };
    json!({
        "name":name,"original_name":name,"custom_name":custom,"display_name":display,
        "template":row.template,"description":row.description,
        "input_schema":schema,
        "tags":export_tags(&row.tags, selective),"is_active":row.enabled
    })
}

fn prompt_schema(raw: Option<&str>) -> Value {
    #[derive(Default, Deserialize)]
    struct Arguments {
        #[serde(default)]
        properties: IndexMap<String, Value>,
        #[serde(default)]
        required: Vec<String>,
    }
    let arguments = raw
        .and_then(|raw| serde_json::from_str::<Arguments>(raw).ok())
        .unwrap_or_default();
    let mut properties = Map::new();
    let mut required = Vec::new();
    for (name, argument) in arguments.properties {
        if arguments.required.contains(&name) {
            required.push(name.clone());
        }
        properties.insert(name, json!({"type":"string","description":argument["description"].as_str().unwrap_or_default()}));
    }
    json!({"type":"object","properties":properties,"required":required})
}

fn export_resource(row: ResourceRecord, selective: bool) -> Value {
    let mut name = row.name.clone();
    if row.gateway_id.is_some()
        && let Some(base) = [
            row.custom_name_slug.as_deref(),
            row.original_name.as_deref(),
            Some(row.name.as_str()),
        ]
        .into_iter()
        .flatten()
        .filter_map(nonempty)
        .map(|item| item.chars().take(255).collect::<String>())
        .find(|item| {
            item.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.- ".contains(&byte))
        })
    {
        name = base;
    }
    let raw_tags = array(Some(&row.tags));
    let tags = if selective {
        raw_tags
    } else {
        json!(
            raw_tags
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|tag| tag.as_str().or_else(|| tag["label"].as_str()))
                .collect::<Vec<_>>()
        )
    };
    let mut data = json!({
        "name":name,"uri":row.uri,"description":row.description,"mime_type":row.mime_type,
        "tags":tags,"is_active":row.enabled,"last_modified":export_timestamp(&row.updated_at)
    });
    if row.gateway_id.is_some() {
        data["original_name"] = json!(row.original_name);
        data["custom_name_slug"] = json!(row.custom_name_slug);
    }
    data
}

fn selected<T>(mut rows: Vec<T>, selective: bool, id: impl Fn(&T) -> &str) -> Vec<T> {
    if selective {
        rows.sort_by(|left, right| id(left).cmp(id(right)));
    }
    rows
}

fn export_timestamp(stored: &str) -> Option<String> {
    let stored = nonempty(stored)?;
    let value = stored.replacen(' ', "T", 1);
    let Some((base, suffix)) = value.split_at_checked(19) else {
        return Some(value);
    };
    let (fraction, offset) = suffix.split_at(suffix.find(['+', '-', 'Z']).unwrap_or(suffix.len()));
    let mut timestamp = base.to_owned();
    if let Some(digits) = fraction.strip_prefix('.') {
        let micros = digits.get(..6).unwrap_or(digits);
        if !micros.trim_end_matches('0').is_empty() {
            timestamp.push_str(&format!(".{micros:0<6}"));
        }
    }
    match offset {
        "Z" => timestamp.push_str("+00:00"),
        name if name.len() == 3 => {
            timestamp.push_str(name);
            timestamp.push_str(":00");
        }
        name => timestamp.push_str(name),
    }
    Some(timestamp)
}

fn csv(value: Option<&str>) -> impl Iterator<Item = &str> {
    value
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter_map(nonempty)
}

fn nonempty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn entity_types(value: Option<&str>) -> Vec<String> {
    csv(value).map(str::to_ascii_lowercase).collect()
}

fn parsed(raw: Option<&str>) -> Value {
    raw.and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default()
}

fn object(raw: Option<&str>, default: Value) -> Value {
    match parsed(raw) {
        Value::Object(fields) => Value::Object(fields),
        _ => default,
    }
}

fn array(raw: Option<&str>) -> Value {
    match parsed(raw) {
        Value::Array(items) => Value::Array(items),
        _ => json!([]),
    }
}

fn export_tags(raw: &str, selective: bool) -> Value {
    let tags = serde_json::from_str::<Vec<Value>>(raw).unwrap_or_default();
    if selective {
        Value::Array(tags)
    } else {
        normalized_tags(tags).unwrap_or_else(|_| json!([]))
    }
}

fn has_tag(raw: &str, tags: &[String]) -> bool {
    array(Some(raw))
        .as_array()
        .into_iter()
        .flatten()
        .any(|item| {
            item.as_str()
                .or_else(|| item["id"].as_str())
                .is_some_and(|id| tags.iter().any(|tag| tag == id))
        })
}

fn export_url(input: &str, selective: bool) -> String {
    if !selective && let Ok(url) = url::Url::parse(input) {
        return url.into();
    }
    input.to_owned()
}

fn verified_ciphertext<'a>(
    cipher: Option<&CredentialCipher>,
    ciphertext: &'a str,
) -> Option<&'a str> {
    cipher?.open::<serde::de::IgnoredAny>(ciphertext).ok()?;
    Some(ciphertext)
}

fn is_sigv4(kind: Option<&str>) -> bool {
    kind.is_some_and(|kind| kind.eq_ignore_ascii_case("sigv4"))
}
