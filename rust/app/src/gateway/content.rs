// SPDX-License-Identifier: Apache-2.0

use std::io::{self, Write};

use base64::{Engine, prelude::BASE64_STANDARD};
use rmcp::model::{
    ClientRequest, ErrorCode, ErrorData, GetPromptRequest, GetPromptRequestParams,
    GetPromptResponse, GetPromptResult, InputRequiredResult, JsonObject, PromptMessage,
    ReadResourceRequest, ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult,
    ResourceContents, Role,
};
use serde_json::Value;

use super::{GatewayService, Principal, Session, ToolContext, UpstreamError, access};
use crate::catalog::{CatalogServer, ContentGateway, PromptContentRecord, ResourceContentRecord};

impl GatewayService {
    pub(crate) async fn read_resource(
        &self,
        mut params: ReadResourceRequestParams,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        context: ToolContext<'_>,
        downstream: Option<&Session>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        self.check_content_access(principal, server, "resources.read")
            .await?;
        let resource = self
            .database
            .resource_content(
                access::catalog_scope(principal),
                server.map(|server| server.id.as_str()),
                &params.uri,
            )
            .await
            .map_err(content_database_error)?
            .ok_or_else(|| {
                ErrorData::invalid_params(format!("Unknown resource: {}", params.uri), None)
            })?;
        let uri = params.uri.clone();
        let Some(gateway) = resource.gateway.as_ref() else {
            return Ok(ReadResourceResult::new(vec![local_resource(resource, uri)]).into());
        };
        params.meta = None;
        let result = self
            .request_content(
                gateway,
                ReadResourceRequest::new(params).into(),
                principal,
                context,
                downstream,
            )
            .await?;
        if result["resultType"] == "input_required" {
            return serde_json::from_value::<InputRequiredResult>(result)
                .map(Into::into)
                .map_err(|_| invalid_upstream_result());
        }
        let mut result: ReadResourceResult =
            serde_json::from_value(result).map_err(|_| invalid_upstream_result())?;
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
        mut params: GetPromptRequestParams,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        context: ToolContext<'_>,
        downstream: Option<&Session>,
    ) -> Result<GetPromptResponse, ErrorData> {
        self.check_content_access(principal, server, "prompts.read")
            .await?;
        let prompt = self
            .database
            .prompt_content(
                access::catalog_scope(principal),
                server.map(|server| server.id.as_str()),
                &params.name,
            )
            .await
            .map_err(content_database_error)?
            .ok_or_else(|| {
                ErrorData::invalid_params(format!("Unknown prompt: {}", params.name), None)
            })?;
        if params
            .arguments
            .iter()
            .flat_map(|arguments| arguments.values())
            .any(|value| !value.is_string())
        {
            return Err(ErrorData::invalid_params(
                "Prompt arguments must be strings",
                None,
            ));
        }
        let Some(gateway) = prompt.gateway.as_ref() else {
            return render_prompt(prompt, params.arguments.unwrap_or_default()).map(Into::into);
        };
        params.name = prompt.original_name;
        params.meta = None;
        let result = self
            .request_content(
                gateway,
                GetPromptRequest::new(params).into(),
                principal,
                context,
                downstream,
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

    async fn check_content_access(
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

    async fn request_content(
        &self,
        gateway: &ContentGateway,
        request: ClientRequest,
        principal: Option<&Principal>,
        context: ToolContext<'_>,
        downstream: Option<&Session>,
    ) -> Result<Value, ErrorData> {
        if !gateway.available {
            return Err(ErrorData::internal_error(
                "Upstream gateway unavailable",
                None,
            ));
        }
        let association = downstream.and_then(|session| {
            session.upstream(
                &gateway.id,
                &gateway.url,
                principal.map(Principal::authorization_fingerprint),
            )
        });
        let modern = context.client_capabilities.is_some();
        self.upstream.request_with_context(&gateway.url, request, context, association.as_deref())
            .await.map_err(|error| match error {
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

fn local_resource(record: ResourceContentRecord, uri: String) -> ResourceContents {
    if let Some(blob) = record.blob {
        ResourceContents::blob(BASE64_STANDARD.encode(blob), uri).with_mime_type(
            record
                .mime
                .unwrap_or_else(|| "application/octet-stream".into()),
        )
    } else {
        ResourceContents::text(record.text.unwrap_or_default(), uri)
            .with_mime_type(record.mime.unwrap_or_else(|| "text/plain".into()))
    }
}

fn render_prompt(
    record: PromptContentRecord,
    arguments: JsonObject,
) -> Result<GetPromptResult, ErrorData> {
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
    let mut environment = minijinja::Environment::new();
    environment.set_fuel(Some(50_000));
    let template = record.template.as_deref().unwrap_or_default();
    let mut output = PromptOutput::default();
    environment
        .template_from_str(template)
        .and_then(|template| {
            template
                .render_captured_to(&arguments, &mut output)
                .map(|_| ())
        })
        .map_err(|_| ErrorData::invalid_params("Failed to render prompt template", None))?;
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
