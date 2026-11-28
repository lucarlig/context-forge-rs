// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt,
    io::{self, Write},
    time::Duration,
};

use base64::{Engine, prelude::BASE64_STANDARD};
use rmcp::model::{
    ClientRequest, CompleteRequest, CompleteRequestParams, CompleteResult, CompletionInfo,
    ErrorCode, ErrorData, GetPromptRequest, GetPromptRequestParams, GetPromptResponse,
    GetPromptResult, InputRequiredResult, JsonObject, PromptMessage, ReadResourceRequest,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Reference,
    ResourceContents, Role,
};
use serde_json::{Value, json};

use super::{
    DirectTarget, GatewayService, Principal, Session, ToolContext, UpstreamError, UpstreamUse,
    access, metrics::ExecutionTarget,
};
use crate::catalog::{
    CatalogServer, ContentGateway, MetricEntity, PromptContentRecord, ResourceContentRecord,
};
use crate::{
    http_boundary::CorrelationId,
    observability::{OperationSpan, Outcome},
    upstream::UpstreamEndpoint,
};

impl GatewayService {
    pub(crate) async fn read_resource(
        &self,
        params: ReadResourceRequestParams,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        context: ToolContext<'_>,
        downstream: Option<&Session>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let started = std::time::Instant::now();
        self.check_mcp_permission(principal, server, "resources.read")
            .await?;
        let mut span = self
            .resource_span(
                &params.uri,
                principal,
                server.map(|server| server.id.as_str()),
            )
            .await;
        let mut target = None;
        let result = span
            .scope(Box::pin(self.read_resource_inner(
                params,
                principal,
                server,
                context,
                downstream,
                &mut target,
            )))
            .await;
        let pending = matches!(result, Ok(ReadResourceResponse::InputRequired(_)));
        if let Ok(ReadResourceResponse::Complete(response)) = &result
            && let [ResourceContents::TextResourceContents { text, .. }] =
                response.contents.as_slice()
        {
            span.capture_output(&json!({"content":text}));
        }
        if !pending {
            self.record_target(target, server, started, result.is_ok())
                .await;
        }
        span.finish(content_outcome(&result, pending, "Resource read failed"))
            .await;
        result
    }

    async fn read_resource_inner(
        &self,
        mut params: ReadResourceRequestParams,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        context: ToolContext<'_>,
        downstream: Option<&Session>,
        metric: &mut Option<ExecutionTarget>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let uri = params.uri.clone();
        let unknown = || ErrorData::invalid_params(format!("Unknown resource: {uri}"), None);
        let (gateway, direct_timeout) = match self
            .direct_target(context.request_headers, principal)
            .await
            .map_err(content_database_error)?
        {
            DirectTarget::Found {
                gateway, timeout, ..
            } => {
                *metric = Some(ExecutionTarget::Forwarded);
                (gateway, Some(timeout))
            }
            DirectTarget::Denied => return Err(unknown()),
            DirectTarget::Fallback | DirectTarget::Disabled => {
                let mut resource = self
                    .database
                    .resource_content(
                        access::catalog_scope(principal),
                        server.map(|server| server.id.as_str()),
                        &uri,
                    )
                    .await
                    .map_err(content_database_error)?
                    .ok_or_else(unknown)?;
                *metric = Some(ExecutionTarget::Catalog(
                    MetricEntity::Resource,
                    resource.id.clone(),
                ));
                let Some(gateway) = resource.gateway.take() else {
                    return Ok(ReadResourceResult::new(vec![local_resource(resource, uri)]).into());
                };
                (gateway, None)
            }
        };
        params.meta = None;
        let result = self
            .request_content(
                &gateway,
                ReadResourceRequest::new(params).into(),
                principal,
                context,
                downstream,
                direct_timeout,
            )
            .await?;
        if result["resultType"] == "input_required" {
            return serde_json::from_value::<InputRequiredResult>(result)
                .map(Into::into)
                .map_err(|_| invalid_upstream_result());
        }
        let mut result: ReadResourceResult =
            serde_json::from_value(result).map_err(|_| invalid_upstream_result())?;
        if direct_timeout.is_some() {
            return Ok(result.into());
        }
        let first = result.contents.into_iter().next();
        let first = match first {
            Some(ResourceContents::TextResourceContents {
                text,
                mime_type,
                meta,
                ..
            }) if !text.is_empty() => ResourceContents::TextResourceContents {
                uri,
                text,
                mime_type,
                meta,
            },
            Some(ResourceContents::BlobResourceContents {
                blob,
                mime_type,
                meta,
                ..
            }) => ResourceContents::BlobResourceContents {
                uri,
                blob,
                mime_type,
                meta,
            },
            _ => ResourceContents::TextResourceContents {
                uri,
                text: String::new(),
                mime_type: None,
                meta: None,
            },
        };
        result.contents = vec![first];
        Ok(result.into())
    }

    pub(crate) async fn get_prompt(
        &self,
        params: GetPromptRequestParams,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        context: ToolContext<'_>,
        downstream: Option<&Session>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let started = std::time::Instant::now();
        if params
            .arguments
            .iter()
            .flat_map(|arguments| arguments.values())
            .any(|value| !value.is_string())
        {
            return Err(ErrorData::invalid_params(
                "Invalid request parameters",
                Some(Value::String(String::new())),
            ));
        }
        self.check_mcp_permission(principal, server, "prompts.read")
            .await?;
        let mut span = self
            .prompt_span(
                &params.name,
                params.arguments.as_ref(),
                principal,
                server.map(|server| server.id.as_str()),
            )
            .await;
        let mut resolved = None;
        let result = span
            .scope(Box::pin(async {
                let prompt = self
                    .database
                    .prompt_content(
                        access::catalog_scope(principal),
                        server.map(|server| server.id.as_str()),
                        &params.name,
                        false,
                    )
                    .await
                    .map_err(content_database_error)?
                    .ok_or_else(|| {
                        ErrorData::invalid_params(format!("Unknown prompt: {}", params.name), None)
                    })?;
                resolved = Some((prompt.id.clone(), prompt.name.clone(), prompt.version));
                self.get_prompt_inner(prompt, params, principal, context, downstream)
                    .await
            }))
            .await;
        let pending = matches!(result, Ok(GetPromptResponse::InputRequired(_)));
        if let Some((id, name, version)) = resolved
            && !pending
        {
            if let Ok(GetPromptResponse::Complete(response)) = &result {
                span.prompt_rendered(&name, version, response.messages.len());
                span.capture_output(response);
            }
            self.record_target(
                Some(ExecutionTarget::Catalog(MetricEntity::Prompt, id)),
                server,
                started,
                result.is_ok(),
            )
            .await;
        }
        span.finish(content_outcome(&result, pending, "Prompt render failed"))
            .await;
        result
    }

    async fn get_prompt_inner(
        &self,
        prompt: PromptContentRecord,
        mut params: GetPromptRequestParams,
        principal: Option<&Principal>,
        context: ToolContext<'_>,
        downstream: Option<&Session>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let Some(gateway) = prompt.gateway.as_ref() else {
            return render_prompt(
                prompt,
                params.arguments.unwrap_or_default(),
                context.client_capabilities.is_some(),
            )
            .map(Into::into);
        };
        params.name = prompt.original_name;
        params.meta = None;
        params.arguments.get_or_insert_default();
        let result = self
            .request_content(
                gateway,
                GetPromptRequest::new(params).into(),
                principal,
                context,
                downstream,
                None,
            )
            .await?;
        if result["resultType"] == "input_required" {
            return serde_json::from_value::<InputRequiredResult>(result)
                .map(Into::into)
                .map_err(|_| invalid_upstream_result());
        }
        serde_json::from_value::<GetPromptResult>(result)
            .map(Into::into)
            .map_err(|_| invalid_upstream_result())
    }

    pub(super) async fn resource_span(
        &self,
        uri: &str,
        principal: Option<&Principal>,
        server: Option<&str>,
    ) -> OperationSpan {
        let mut span = OperationSpan::start(&self.database,"resource.read","internal",None,|| {
            let safe_uri = resource_trace_uri(uri);
            let http_url = safe_uri.starts_with("http").then_some(&safe_uri);
            json!({
                "resource.uri":safe_uri,
                "resource.type":if safe_uri.contains('{') && safe_uri.contains('}') {"template"} else {"static"},
                "http.url":http_url, "user":principal.map_or("anonymous", |principal| principal.email.as_str()),
                "server_id":server, "request_id":request_id(),
            })
        }).await;
        span.identify(principal);
        span.capture_input(&json!({"uri":resource_trace_uri(uri)}));
        span
    }

    pub(super) async fn prompt_span(
        &self,
        name: &str,
        arguments: Option<&JsonObject>,
        principal: Option<&Principal>,
        server: Option<&str>,
    ) -> OperationSpan {
        let mut span = OperationSpan::start(&self.database,"prompt.render","internal",None,|| {
            json!({
                "prompt.id":name.chars().take(255).collect::<String>(), "arguments_count":arguments.map_or(0, JsonObject::len),
                "user":principal.map_or("anonymous", |principal| principal.email.as_str()),
                "server_id":server, "tenant_id":null, "request_id":request_id().as_deref().unwrap_or("none"),
            })
        }).await;
        span.identify(principal);
        span.capture_input(arguments.unwrap_or(&Default::default()));
        span
    }

    pub(crate) async fn complete(
        &self,
        mut params: CompleteRequestParams,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        context: ToolContext<'_>,
        downstream: Option<&Session>,
    ) -> Result<CompleteResult, ErrorData> {
        self.check_mcp_permission(principal, server, "tools.read")
            .await?;
        if params.argument.name.is_empty() {
            return Err(ErrorData::invalid_params(
                "Missing reference type or argument name",
                None,
            ));
        }
        let scope = access::catalog_scope(principal);
        let server_id = server.map(|server| server.id.as_str());
        let gateway = match &mut params.r#ref {
            Reference::Prompt(reference) => {
                let name = &reference.name;
                if name.is_empty() {
                    return Err(ErrorData::invalid_params("Missing prompt name", None));
                }
                let prompt = self
                    .database
                    .prompt_content(scope, server_id, name, true)
                    .await
                    .map_err(content_database_error)?
                    .ok_or_else(|| {
                        ErrorData::invalid_params(format!("Prompt not found: {name}"), None)
                    })?;
                let Some(gateway) = prompt.gateway else {
                    return prompt_completions(prompt.argument_schema.as_ref(), &params);
                };
                reference.name = prompt.original_name;
                gateway
            }
            Reference::Resource(reference) => {
                let template = &reference.uri;
                if template.is_empty() {
                    return Err(ErrorData::invalid_params("Missing URI template", None));
                }
                let resource = self
                    .database
                    .resource_template_content(scope, server_id, template)
                    .await
                    .map_err(content_database_error)?
                    .ok_or_else(|| {
                        ErrorData::invalid_params(
                            format!("Resource template not found: {template}"),
                            None,
                        )
                    })?;
                let Some(gateway) = resource.gateway else {
                    return self
                        .database
                        .resource_completions(scope, server_id, &params.argument.value)
                        .await
                        .map(CompleteResult::new)
                        .map_err(content_database_error);
                };
                gateway
            }
            _ => return Err(ErrorData::invalid_params("Invalid reference type", None)),
        };
        if let Some(meta) = &mut params.meta {
            meta.0.retain(|key, _| {
                key != "progressToken" && !key.starts_with("io.modelcontextprotocol/")
            });
            if meta.0.is_empty() {
                params.meta = None;
            }
        }
        if params
            .context
            .as_ref()
            .is_some_and(|context| !context.has_arguments())
        {
            params.context = None;
        }
        let reply = self
            .request_content(
                &gateway,
                CompleteRequest::new(params).into(),
                principal,
                context,
                downstream,
                None,
            )
            .await?;
        let mut result: CompleteResult =
            serde_json::from_value(reply).map_err(|_| invalid_upstream_result())?;
        let completion = &mut result.completion;
        let has_more = completion
            .total
            .is_some_and(|total| total as usize > completion.values.len());
        completion.has_more.get_or_insert(has_more);
        Ok(CompleteResult::new(result.completion))
    }

    pub(super) async fn check_mcp_permission(
        &self,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        permission: &str,
    ) -> Result<(), ErrorData> {
        if let Some(principal) = principal
            && !self
                .access
                .allows(principal, permission, access::role_context(server), true)
                .await
                .map_err(content_database_error)?
        {
            return Err(ErrorData::new(ErrorCode(0), "Access denied", None));
        }
        Ok(())
    }

    pub(super) async fn request_content(
        &self,
        gateway: &ContentGateway,
        request: ClientRequest,
        principal: Option<&Principal>,
        context: ToolContext<'_>,
        downstream: Option<&Session>,
        timeout: Option<Duration>,
    ) -> Result<Value, ErrorData> {
        let transport = gateway
            .transport
            .filter(|_| gateway.available)
            .ok_or_else(|| ErrorData::internal_error("Upstream gateway unavailable", None))?;
        let credentials = self
            .configured_upstream(
                &gateway.id,
                &gateway.url,
                gateway.needs_upstream_config,
                context.request_headers,
                principal,
                UpstreamUse::Invocation,
            )
            .await
            .map_err(|_| ErrorData::internal_error("Upstream gateway unavailable", None))?;
        let endpoint = UpstreamEndpoint {
            url: &gateway.url,
            transport,
            credentials: credentials.as_ref(),
        };
        let association = downstream.and_then(|session| {
            session.upstream(
                &gateway.id,
                endpoint,
                principal.map(Principal::authorization_fingerprint),
            )
        });
        let modern = context.client_capabilities.is_some();
        let completion = matches!(request, ClientRequest::CompleteRequest(_));
        let client = timeout.map(|timeout| self.upstream.with_timeout_cap(timeout));
        client.as_ref().unwrap_or(&self.upstream).request_with_context(endpoint, request, context, association.as_deref(), None)
            .await.map_err(|error| match error {
                UpstreamError::CompletionUnsupported => ErrorData::new(
                    ErrorCode::METHOD_NOT_FOUND,
                    format!("Upstream gateway '{}' does not support completions", gateway.id),
                    None,
                ),
                UpstreamError::Rpc { code, message, .. } if completion => {
                    let code = match code {
                        -32601 => ErrorCode::METHOD_NOT_FOUND,
                        -32602 => ErrorCode::INVALID_PARAMS,
                        _ => ErrorCode::INTERNAL_ERROR,
                    };
                    ErrorData::new(code, format!("Upstream gateway '{}' returned an error: {message}", gateway.id), None)
                }
                UpstreamError::Rpc { code, message, data } => {
                    let mut code = i32::try_from(code).map_or(ErrorCode::INTERNAL_ERROR, ErrorCode);
                    if modern && code == ErrorCode::RESOURCE_NOT_FOUND { code = ErrorCode::INVALID_PARAMS; }
                    ErrorData::new(code, message, data)
                }
                UpstreamError::Cancelled => ErrorData::new(ErrorCode(-32800), "Request cancelled", None),
                error => {
                    tracing::warn!(%error, gateway = %gateway.id, "upstream MCP content request failed");
                    ErrorData::internal_error("Upstream gateway unavailable", None)
                }
            })
    }
}

fn content_outcome<T>(
    result: &Result<T, ErrorData>,
    pending: bool,
    message: &'static str,
) -> Outcome {
    match result {
        Ok(_) if pending => Outcome::InputRequired,
        Ok(_) => Outcome::Ok,
        Err(error) if error.code == ErrorCode(-32800) => Outcome::Cancelled,
        Err(_) => Outcome::Error(message),
    }
}

fn request_id() -> Option<String> {
    CorrelationId::current()
        .and_then(|id| id.as_str().map(|value| value.chars().take(64).collect()))
}

fn resource_trace_uri(uri: &str) -> String {
    let without_query = uri.split(['?', '#']).next().unwrap_or_default();
    if let Ok(mut url) = url::Url::parse(without_query)
        && (!url.username().is_empty() || url.password().is_some())
    {
        let _ = url.set_password(None);
        let _ = url.set_username("");
        return url.as_str().chars().take(767).collect();
    }
    without_query.chars().take(767).collect()
}

fn prompt_completions(
    schema: Option<&Value>,
    params: &CompleteRequestParams,
) -> Result<CompleteResult, ErrorData> {
    let name = &params.argument.name;
    let argument = schema
        .and_then(|schema| schema["properties"].as_object())
        .and_then(|properties| {
            properties
                .values()
                .find(|value| value["name"].as_str() == Some(name))
        })
        .ok_or_else(|| ErrorData::invalid_params(format!("Argument not found: {name}"), None))?;
    let needle = params.argument.value.to_lowercase();
    let mut values = Vec::new();
    let mut total = 0_u32;
    for value in argument["enum"].as_array().into_iter().flatten() {
        let Some(value) = value.as_str() else {
            return Err(ErrorData::internal_error(
                "Invalid prompt completion value",
                None,
            ));
        };
        if value.to_lowercase().contains(&needle) {
            total = total.saturating_add(1);
            if values.len() < CompletionInfo::MAX_VALUES {
                values.push(value.to_owned());
            }
        }
    }
    let has_more = total as usize > values.len();
    CompletionInfo::with_pagination(values, Some(total), has_more)
        .map(CompleteResult::new)
        .map_err(|_| ErrorData::internal_error("Invalid prompt completions", None))
}

pub(super) fn local_resource(record: ResourceContentRecord, uri: String) -> ResourceContents {
    match (record.text, record.blob) {
        (None, Some(blob)) => ResourceContents::blob(BASE64_STANDARD.encode(blob), uri)
            .with_mime_type(
                record
                    .mime
                    .unwrap_or_else(|| "application/octet-stream".into()),
            ),
        (text, _) => ResourceContents::text(text.unwrap_or_default(), uri)
            .with_mime_type(record.mime.unwrap_or_else(|| "text/plain".into())),
    }
}

pub(super) fn render_prompt(
    record: PromptContentRecord,
    arguments: JsonObject,
    modern: bool,
) -> Result<GetPromptResult, ErrorData> {
    let processing_error = || {
        if modern {
            ErrorData::internal_error("Internal server error", None)
        } else {
            ErrorData::new(
                ErrorCode(0),
                "Failed to process prompt: An unexpected error occurred",
                None,
            )
        }
    };
    let mut missing: Vec<_> = record
        .argument_schema
        .as_ref()
        .and_then(|schema| schema["required"].as_array())
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|name| !arguments.contains_key(*name))
        .collect();
    if !missing.is_empty() {
        missing.sort_unstable();
        return Err(ErrorData::invalid_params(
            format!("Missing required arguments: {}", missing.join(", ")),
            None,
        ));
    }
    let schema = record
        .argument_schema
        .as_ref()
        .ok_or_else(processing_error)?;
    let validator = jsonschema::options()
        .offline()
        .build(schema)
        .map_err(|_| processing_error())?;
    let arguments = Value::Object(arguments);
    if !validator.is_valid(&arguments) {
        return Err(processing_error());
    }
    let mut environment = minijinja::Environment::new();
    environment.set_fuel(Some(50_000));
    environment.set_trim_blocks(true);
    environment.set_lstrip_blocks(true);
    environment.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
    environment.set_formatter(|output, state, value| {
        if state.auto_escape() == minijinja::AutoEscape::Html && !value.is_safe() {
            if let Some(text) = value.as_str() {
                write_prompt_escaped(output, text)?;
            } else {
                write_prompt_escaped(output, &value.to_string())?;
            }
            Ok(())
        } else {
            minijinja::escape_formatter(output, state, value)
        }
    });
    let template = record.template.as_deref().unwrap_or_default();
    let mut output = PromptOutput::default();
    environment
        .template_from_str(template)
        .and_then(|template| {
            template
                .render_captured_to(&arguments, &mut output)
                .map(|_| ())
        })
        .map_err(|_| processing_error())?;
    let text = String::from_utf8(output.0)
        .map_err(|_| ErrorData::internal_error("Invalid rendered prompt", None))?;
    let mut messages = Vec::new();
    let mut lines = Vec::new();
    let mut role = Role::User;
    for line in text.split('\n') {
        let next = if line.starts_with("# Assistant:") {
            Role::Assistant
        } else if line.starts_with("# User:") {
            Role::User
        } else {
            lines.push(line);
            continue;
        };
        if !lines.is_empty() {
            messages.push(PromptMessage::new_text(role, lines.join("\n").trim()));
            lines.clear();
        }
        role = next;
    }
    if !lines.is_empty() {
        messages.push(PromptMessage::new_text(role, lines.join("\n").trim()));
    }
    let mut result = GetPromptResult::new(messages);
    result.description = record.description;
    Ok(result)
}

fn write_prompt_escaped(output: &mut impl fmt::Write, text: &str) -> fmt::Result {
    let mut start = 0;
    for (index, character) in text.match_indices(['&', '<', '>', '"', '\'']) {
        output.write_str(&text[start..index])?;
        output.write_str(match character {
            "&" => "&amp;",
            "<" => "&lt;",
            ">" => "&gt;",
            "\"" => "&#34;",
            _ => "&#39;",
        })?;
        start = index + character.len();
    }
    output.write_str(&text[start..])
}

#[derive(Default)]
struct PromptOutput(Vec<u8>);

impl Write for PromptOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(buffer.len()) > crate::mcp::MAX_REQUEST_BODY_BYTES {
            return Err(io::Error::other(
                "rendered prompt exceeds the gateway size limit",
            ));
        }
        self.0.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invalid_upstream_result() -> ErrorData {
    ErrorData::internal_error("Invalid upstream MCP content", None)
}

fn content_database_error(error: sqlx::Error) -> ErrorData {
    tracing::error!(%error, "MCP content lookup failed");
    ErrorData::internal_error("Content catalog unavailable", None)
}
