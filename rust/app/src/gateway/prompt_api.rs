// SPDX-License-Identifier: Apache-2.0

use axum::extract::{DefaultBodyLimit, Path, Query};
use rmcp::model::{GetPromptRequest, GetPromptRequestParams, GetPromptResult, PromptMessage, Role};
use tokio_util::sync::CancellationToken;

use super::{catalog_api::*, *};
use crate::catalog::{MetricEntity, PromptRecord};

mod write;
pub(super) use write::{
    change_state, create_record, editable, import_prompt, remove, update_record,
};

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
struct ArgumentSchema {
    #[serde(rename = "type")]
    kind: String,
    properties: indexmap::IndexMap<String, Value>,
    required: Vec<String>,
}

pub(super) fn router(max_bytes: usize) -> Router<Arc<GatewayService>> {
    let mut routes = Router::new();
    for base in ["/prompts", "/v1/prompts"] {
        routes = routes
            .route(base, get(list).post(write::create))
            .route(&format!("{base}/"), get(list).post(write::create))
            .route(
                &format!("{base}/{{id}}"),
                get(read)
                    .post(execute)
                    .put(write::update)
                    .delete(write::delete),
            )
            .route(&format!("{base}/{{id}}/state"), post(write::set_state))
            .route(&format!("{base}/{{id}}/toggle"), post(write::set_state));
    }
    routes.layer(DefaultBodyLimit::max(
        max_bytes.saturating_mul(6).saturating_add(65536),
    ))
}

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<CatalogListQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(&service, &principal, "prompts.read", true).await?;
    let page = CatalogPage::prepare(&service, &principal, &query, "rest/prompts")?;
    let rows = service
        .database
        .managed_prompts(access::catalog_scope(Some(&principal)), page.filters())
        .await?;
    Ok(Json(page.envelope(
        &service,
        rows,
        "prompts",
        |row| (&row.created_at, &row.id),
        |row| metadata(row, true),
    )?))
}

async fn read(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Value>, CatalogApiError> {
    retrieve(&service, &principal, &id, &headers, None).await
}

async fn execute(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    input: Option<Json<serde_json::Map<String, Value>>>,
) -> Result<Json<Value>, CatalogApiError> {
    let arguments = input.map(|Json(arguments)| arguments).unwrap_or_default();
    retrieve(&service, &principal, &id, &headers, Some(arguments)).await
}

async fn retrieve(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
    headers: &HeaderMap,
    arguments: Option<serde_json::Map<String, Value>>,
) -> Result<Json<Value>, CatalogApiError> {
    require_catalog_permission(service, principal, "prompts.read", true).await?;
    let execute = arguments.is_some();
    let error = |status, message: String| {
        if execute {
            CatalogApiError(status, json!({"message":message}))
        } else {
            CatalogApiError::detail(status, message)
        }
    };
    let arguments = arguments.unwrap_or_default();
    if arguments.values().any(|argument| !argument.is_string()) {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Prompt arguments must be strings".into(),
        ));
    }
    let scope = access::catalog_scope(Some(principal));
    let server = headers
        .get("x-server-id")
        .map(http_server_id)
        .transpose()?
        .filter(|value| !value.is_empty());
    let record = service
        .database
        .prompt_content(scope, server, id, false)
        .await;
    let record = match record {
        Ok(Some(record)) => record,
        Ok(None) => {
            let message = if service
                .database
                .inactive_prompt_exists(scope, id, server)
                .await?
            {
                format!("Prompt '{id}' exists but is inactive")
            } else {
                format!("Prompt not found: {id}")
            };
            return Err(error(StatusCode::NOT_FOUND, message));
        }
        Err(error_value) => {
            if matches!(&error_value, sqlx::Error::Protocol(message) if message == "ambiguous prompt name in visible catalog")
            {
                return Err(error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!(
                        "Prompt name '{id}' is ambiguous across multiple scopes; use /servers/{{id}}/mcp to disambiguate."
                    ),
                ));
            }
            return Err(error_value.into());
        }
    };
    let resolved_id = record.id.clone();
    let started = std::time::Instant::now();
    let span = service
        .prompt_span(id, arguments.len(), Some(principal), server)
        .await;
    let result = async {
        let mut result = if let Some(gateway) = record.gateway.as_ref()
            && record.template.as_deref().is_none_or(str::is_empty)
        {
            let mut params = GetPromptRequestParams::new(record.original_name.clone());
            params.arguments = Some(arguments);
            let cancellation = CancellationToken::new();
            service
                .request_content(
                    gateway,
                    GetPromptRequest::new(params).into(),
                    Some(principal),
                    ToolContext {
                        cancellation: &cancellation,
                        progress: None,
                        notifications: None,
                        client_capabilities: None,
                        request_headers: Some(headers),
                    },
                    None,
                    None,
                )
                .await
                .map_err(|remote| {
                    error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        remote.message.into_owned(),
                    )
                })?
        } else if arguments.is_empty() {
            let mut raw = GetPromptResult::new(vec![PromptMessage::new_text(
                Role::User,
                record.template.unwrap_or_default(),
            )]);
            raw.description = record.description;
            json!(raw)
        } else {
            json!(
                content::render_prompt(record, arguments, false).map_err(|render| error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    render.message.into_owned()
                ))?
            )
        };
        if let Some(fields) = result.as_object_mut()
            && fields.get("resultType").and_then(Value::as_str) != Some("input_required")
        {
            fields.remove("resultType");
            fields.entry("description").or_insert(Value::Null);
        }
        if let Some(messages) = result["messages"].as_array_mut() {
            for message in messages {
                let content = &mut message["content"];
                if let Some(fields) = content.as_object_mut() {
                    fields.entry("_meta").or_insert(Value::Null);
                    fields.entry("annotations").or_insert(Value::Null);
                }
            }
        }
        Ok(Json(result))
    }
    .await;
    let pending = matches!(&result, Ok(Json(value)) if value["resultType"] == "input_required");
    if !pending {
        service
            .record_rest_execution(
                (MetricEntity::Prompt, &resolved_id),
                principal,
                server,
                started,
                result.is_ok(),
            )
            .await;
    }
    let outcome = if pending {
        crate::observability::Outcome::InputRequired
    } else {
        crate::observability::Outcome::completed(result.is_ok(), "Prompt render failed")
    };
    span.finish(outcome).await;
    result
}

pub(super) fn metadata(record: &PromptRecord, aliases: bool) -> Value {
    let mut response = json!(record);
    response["created_at"] = record.created_at.replacen(' ', "T", 1).into();
    response["updated_at"] = record.updated_at.replacen(' ', "T", 1).into();
    response["mcp_server_id"] = json!(record.gateway_id);
    response["display_name"] = json!(
        record
            .display_name
            .as_deref()
            .unwrap_or(&record.custom_name)
    );
    let schema: ArgumentSchema = record
        .argument_schema
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .unwrap_or_default();
    let arguments = schema
        .properties
        .iter()
        .map(|(name, property)| {
            json!({
                "name":name,
                "description":property["description"].as_str().unwrap_or_default(),
                "required":schema.required.contains(name),
            })
        })
        .collect::<Vec<_>>();
    response["arguments"] = json!(arguments);
    response["tags"] = serde_json::from_str(&record.tags).unwrap_or_else(|_| json!([]));
    response["title"] = Value::Null;
    response["metrics"] = Value::Null;
    if aliases {
        alias_metadata(response)
    } else {
        response["meta"] = Value::Null;
        response
    }
}
