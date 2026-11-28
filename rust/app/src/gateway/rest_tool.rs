// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt::Write, sync::LazyLock};

use axum::http::{HeaderValue, Method};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde_json::Map;
use url::{Url, form_urlencoded};

use super::*;
use crate::{
    catalog::RestTool,
    forward_headers::hop_header_name,
    schema_validation::Target,
    sigv4::{SigV4Config, has_query_signature},
    upstream::RestResponse,
};

mod diagnostics;
mod response_body;

const URL_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
type Mapping = BTreeMap<String, String>;

pub(super) async fn execute(
    service: &GatewayService,
    tool: &CatalogTool,
    config: &RestTool,
    params: &CallToolRequestParams,
    principal: Option<&Principal>,
    incoming: Option<&HeaderMap>,
    phases: &mut tool_phases::ToolPhases,
) -> Result<Value, ToolError> {
    if config.pending_policy {
        return tool_result_error("REST tool requires an unavailable invocation policy");
    }
    let arguments = params.arguments.clone().unwrap_or_default();
    let input_schema = &tool.definition.input_schema;
    if input_schema.as_object().is_some_and(|fields| {
        !fields.is_empty() && !(fields.len() == 1 && fields.get("type") == Some(&json!("object")))
    }) {
        let schema = input_schema.clone();
        let data = Value::Object(arguments.clone());
        let validation = service
            .schema_validation
            .validate(schema, data, Target::Input)
            .await;
        match validation {
            Ok((_, None)) => {}
            Ok((_, Some(error))) => {
                return Err(ToolError::InvalidArguments(format!(
                    "Invalid arguments for tool '{}': {error}",
                    params.name
                )));
            }
            Err(_) => {
                return tool_result_error(
                    "Input validation error: REST validation could not complete",
                );
            }
        }
    }
    let mut lookup = phases.start("tool.lookup");
    let connection = with_trace(lookup.context(), async {
        if !tool.needs_upstream_config {
            return Ok(None);
        }
        let version = tool.gateway_version.ok_or(ToolError::Unavailable)?;
        let connection = service
            .database
            .gateway_connection(
                &tool.gateway_id,
                &tool.gateway_url,
                false,
                Some(version),
                None,
            )
            .await?
            .ok_or(ToolError::Unavailable)?;
        Ok::<_, ToolError>(Some(connection))
    })
    .await;
    let connection = match connection {
        Ok(connection) => connection,
        Err(error) => {
            lookup.finish(Some("REST tool configuration lookup failed"));
            return Err(error);
        }
    };
    let gateway_signer = connection
        .as_ref()
        .filter(|gateway| gateway.kind == "sigv4")
        .and_then(|gateway| stored_sigv4(gateway.sigv4.as_deref()));
    let uses_signer = config
        .auth_type
        .as_deref()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("sigv4"));
    let inherited_signer = uses_signer && stored_sigv4(config.sigv4_config.as_deref()).is_none();
    if inherited_signer && gateway_signer.is_none() {
        lookup.finish(Some("No stored REST tool credentials"));
        return tool_result_error("Tool invocation failed: SigV4 tool has no stored credentials");
    }
    let stored = stored_credentials(service, config, gateway_signer);
    lookup.finish(
        stored
            .is_err()
            .then_some("REST tool credential lookup failed"),
    );
    let (mut credentials, managed) = match stored {
        Ok(config) => config,
        Err(_) if uses_signer => {
            return tool_result_error(
                "Tool invocation failed: Stored SigV4 credentials could not be loaded",
            );
        }
        Err(error) => return tool_result_error(error.to_string()),
    };
    let exchange = connection
        .as_ref()
        .filter(|gateway| gateway.kind == "oauth")
        .and_then(|gateway| {
            gateway
                .oauth
                .as_deref()
                .filter(|encoded| {
                    credentials.sigv4.is_none() && oauth_api::is_token_exchange(encoded)
                })
                .map(|encoded| (gateway, encoded))
        });
    if let Some(incoming) = incoming {
        service
            .header_forwarding
            .apply(
                &service.database,
                &mut credentials.headers,
                incoming,
                None,
                managed || exchange.is_some(),
            )
            .await?;
    }
    let mut request = match build_request(tool, config, arguments, &mut credentials.headers) {
        Ok(request) => request,
        Err(message) => return tool_result_error(format!("Tool invocation failed: {message}")),
    };
    if (inherited_signer || exchange.is_some())
        && !Url::parse(&tool.gateway_url).is_ok_and(|url| url.origin() == request.url().origin())
    {
        return tool_result_error(
            "Tool invocation failed: REST tool URL must share the linked gateway's origin to use its credentials",
        );
    }
    if credentials.sigv4.is_some() && has_query_signature(request.url()) {
        return tool_result_error("A presigned URL cannot be combined with auth_type 'sigv4'");
    }
    let audience = if tool.gateway_id.is_empty() {
        &tool.id
    } else {
        &tool.gateway_id
    };
    service
        .identity_forwarding
        .apply(
            &mut credentials,
            principal,
            audience,
            connection
                .as_ref()
                .and_then(|gateway| gateway.identity.as_deref()),
        )
        .map_err(|_| ToolError::Unavailable)?;
    *request.headers_mut() = credentials.headers;
    let upstream = service.upstream.with_timeout(service.rest_timeout);
    let retry = exchange.and_then(|_| request.try_clone());
    let mut call = phases.start("tool.gateway_call");
    let initial = with_trace(
        call.context(),
        upstream.rest_response(request, credentials.sigv4.as_deref()),
    )
    .await;
    let result = match (initial, exchange, retry) {
        (
            Ok(RestResponse {
                status: StatusCode::UNAUTHORIZED,
                ..
            }),
            Some((gateway, encoded)),
            Some(mut retry),
        ) => {
            let authorization = match with_trace(
                call.context(),
                refreshed_exchange(service, tool, gateway, encoded, principal, incoming),
            )
            .await
            {
                Ok(header) => header,
                Err(message) => {
                    call.finish(Some("Upstream credential refresh failed"));
                    return tool_result_error(format!("Tool invocation failed: {message}"));
                }
            };
            retry
                .headers_mut()
                .insert(header::AUTHORIZATION, authorization);
            with_trace(call.context(), upstream.rest_response(retry, None)).await
        }
        (result, _, _) => result,
    };
    call.finish(result.is_err().then_some("Upstream REST request failed"));
    match result {
        Ok(response) => {
            phases.mark_result_ready();
            Ok(response_result(
                service,
                &tool.response_filter,
                &response,
                tool.definition.output_schema.as_ref(),
            )
            .await)
        }
        Err(UpstreamError::BlockedDestination | UpstreamError::InvalidUrl) => {
            tool_result_error("Tool invocation failed: Outbound URL blocked by URL policy")
        }
        Err(UpstreamError::Timeout) => tool_result_error(format!(
            "Tool invocation timed out after {}s",
            service.rest_timeout.as_secs_f64()
        )),
        Err(_) => tool_result_error("Tool invocation failed: REST upstream request failed"),
    }
}

async fn refreshed_exchange(
    service: &GatewayService,
    tool: &CatalogTool,
    gateway: &GatewayConnectionRow,
    encoded: &str,
    principal: Option<&Principal>,
    incoming: Option<&HeaderMap>,
) -> Result<HeaderValue, String> {
    let principal = principal.ok_or(
        "Token exchange requires an authenticated user identity. Contact your administrator.",
    )?;
    let subject = incoming
        .and_then(|headers| principal.verified_bearer(headers))
        .ok_or_else(|| {
            format!(
                "User authentication required for token-exchange gateway '{}'.",
                tool.gateway_name
            )
        })?;
    let failed = || {
        format!(
            "Token exchange failed for gateway '{}'. Contact your administrator.",
            tool.gateway_name
        )
    };
    let vault = service.vault.as_ref().ok_or_else(failed)?;
    let config = OAuthConfig::load(vault, encoded)
        .await
        .map_err(|_| failed())?;
    let tls = service
        .connection_tls(gateway)
        .await
        .map_err(|_| failed())?;
    let upstream = service
        .upstream
        .with_timeout_cap(service.gateway_oauth.request_timeout);
    let correlation_id = incoming
        .and_then(|headers| headers.get("x-correlation-id"))
        .and_then(|header| header.to_str().ok())
        .filter(|value| {
            value.len() <= 128
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    let refreshed = service
        .exchanged_tokens
        .authorization(
            ExchangeConnection {
                gateway_id: &tool.gateway_id,
                version: gateway.version,
                upstream: &upstream,
                config: &config,
                tls: tls.as_ref(),
                cipher: service.credential_cipher.as_ref(),
            },
            principal,
            subject,
            ExchangeMode::Refresh,
        )
        .await;
    tracing::info!(gateway = %tool.gateway_id, correlation_id, success = refreshed.is_ok(), "REST tool OAuth token exchange");
    refreshed.map_err(|_| failed())
}

fn stored_sigv4(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim)
        .filter(|value| !matches!(*value, "" | "null" | "{}"))
}

fn stored_credentials(
    service: &GatewayService,
    config: &RestTool,
    gateway_sigv4: Option<&str>,
) -> Result<(UpstreamCredentials, bool), CredentialError> {
    let cipher = service.credential_cipher.as_ref();
    let mut credentials = UpstreamCredentials::default();
    if let Some(raw) = config.headers.as_deref() {
        let fields: Option<Map<String, Value>> =
            serde_json::from_str(raw).map_err(|_| CredentialError)?;
        for (name, value) in fields.unwrap_or_default() {
            let value = match value {
                Value::String(text) => text,
                Value::Object(value) => {
                    let encrypted = value
                        .get(tool_api::SECRET_HEADER)
                        .and_then(Value::as_str)
                        .ok_or(CredentialError)?;
                    let payload: Value = cipher.ok_or(CredentialError)?.open(encrypted)?;
                    payload
                        .get("data")
                        .or_else(|| payload.get("value"))
                        .and_then(Value::as_str)
                        .ok_or(CredentialError)?
                        .to_owned()
                }
                _ => return Err(CredentialError),
            };
            insert_stored_header(&mut credentials.headers, &name, &value)?;
        }
    }
    let auth_type = config
        .auth_type
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let auth_value = config
        .auth_value
        .as_deref()
        .filter(|value| !value.is_empty());
    let managed = match auth_type.as_str() {
        "" | "none" | "one_time_auth" if auth_value.is_none() => false,
        "sigv4" => {
            credentials.sigv4 = Some(SigV4Config::load(
                cipher.ok_or(CredentialError)?,
                stored_sigv4(config.sigv4_config.as_deref())
                    .or(gateway_sigv4)
                    .ok_or(CredentialError)?,
            )?);
            true
        }
        "" | "basic" | "bearer" | "authheaders" => {
            let auth = tool_api::decode_stored_auth(
                cipher.ok_or(CredentialError)?,
                auth_value.ok_or(CredentialError)?,
            )?;
            for (name, value) in auth {
                insert_stored_header(&mut credentials.headers, &name, &value)?;
            }
            true
        }
        _ => return Err(CredentialError),
    };
    Ok((credentials, managed))
}

fn insert_stored_header(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
) -> Result<(), CredentialError> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| CredentialError)?;
    let normalized = name.as_str();
    if normalized.starts_with("mcp-")
        || normalized.starts_with("x-mcp-")
        || hop_header_name(normalized)
        || name == header::HOST
        || name == header::CONTENT_LENGTH
    {
        return Err(CredentialError);
    }
    let mut value = HeaderValue::from_str(value).map_err(|_| CredentialError)?;
    value.set_sensitive(tool_api::protected_header(normalized) && name != header::CONTENT_TYPE);
    headers.insert(name, value);
    Ok(())
}

fn build_request(
    tool: &CatalogTool,
    config: &RestTool,
    arguments: Map<String, Value>,
    headers: &mut HeaderMap,
) -> Result<reqwest::Request, String> {
    let method = match tool.request_type.to_ascii_uppercase().as_str() {
        "GET" => Method::GET,
        "" | "POST" => Method::POST,
        "PUT" => Method::PUT,
        "PATCH" => Method::PATCH,
        "DELETE" => Method::DELETE,
        _ => return Err("Unsupported REST request method".into()),
    };
    let mut payload = arguments.clone();
    let mut url = resolved_url(
        config
            .http_url
            .as_deref()
            .ok_or("REST tool URL is missing")?,
        &mut payload,
    )?;
    let query_mapping = mapping(config.query_mapping.as_deref())?;
    let header_mapping = mapping(config.header_mapping.as_deref())?;
    for (key, target) in &header_mapping {
        let name =
            tool_api::mapped_header_name(target).ok_or("Invalid REST header mapping target")?;
        if let Some(value) = arguments.get(key) {
            let value = value
                .as_str()
                .and_then(|value| HeaderValue::from_str(value).ok())
                .ok_or("Invalid REST header mapping value")?;
            headers.insert(name, value);
        }
    }
    let mapped = !query_mapping.is_empty() || !header_mapping.is_empty();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let is_form = matches!(
        content_type.as_str(),
        "application/x-www-form-urlencoded" | "multipart/form-data"
    );

    if method == Method::GET || mapped {
        let mut static_query = Map::new();
        for (key, value) in url.query_pairs().filter(|(_, value)| !value.is_empty()) {
            static_query
                .entry(key.into_owned())
                .or_insert_with(|| value.into_owned().into());
        }
        url.set_query(None);
        if query_mapping.is_empty() {
            payload.extend(static_query.clone());
        } else {
            for (key, value) in payload {
                if let Some(target) = query_mapping.get(&key) {
                    if value.is_object() || value.is_array() {
                        return Err(format!(
                            "Tool '{}': query_mapping produced non-scalar value for parameter '{target}'",
                            tool.definition.name
                        ));
                    }
                    static_query.insert(target.clone(), value);
                }
            }
            payload = static_query.clone();
        }
        if method == Method::GET {
            let mut query = url.query_pairs_mut();
            for (key, value) in payload {
                if let Value::Array(values) = value {
                    for value in values {
                        query.append_pair(&key, &form_value(&value));
                    }
                } else {
                    query.append_pair(&key, &form_value(&value));
                }
            }
            drop(query);
            if url.query() == Some("") {
                url.set_query(None);
            }
            return Ok(reqwest::Request::new(method, url));
        }
        if is_form && query_mapping.is_empty() && !static_query.is_empty() {
            url.query_pairs_mut().extend_pairs(
                static_query
                    .into_iter()
                    .map(|(key, value)| (key, form_value(&value))),
            );
        }
    }

    let body = match content_type.as_str() {
        "application/x-www-form-urlencoded" => form_urlencoded::Serializer::new(String::new())
            .extend_pairs(
                payload
                    .into_iter()
                    .map(|(key, value)| (key, form_value(&value))),
            )
            .finish(),
        "multipart/form-data" => multipart(headers, payload),
        _ => {
            headers
                .entry(header::CONTENT_TYPE)
                .or_insert(HeaderValue::from_static("application/json"));
            Value::Object(payload).to_string()
        }
    };
    let mut request = reqwest::Request::new(method, url);
    *request.body_mut() = Some(body.into());
    Ok(request)
}

fn resolved_url(template: &str, payload: &mut Map<String, Value>) -> Result<Url, String> {
    static PLACEHOLDER: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)\{(\w+)\}|%7b(\w+)%7d").expect("URL placeholder regex")
    });
    let original = Url::parse(template).map_err(|_| "Invalid REST tool URL")?;
    let authority_end = template
        .find("://")
        .and_then(|start| {
            template[start + 3..]
                .find(['/', '?', '#'])
                .map(|end| start + 3 + end)
        })
        .unwrap_or(template.len());
    let mut result = String::new();
    let mut end = 0;
    let mut used = BTreeMap::new();
    for capture in PLACEHOLDER.captures_iter(template) {
        let matched = capture.get(0).expect("full URL placeholder");
        if matched.start() < authority_end {
            return Err("REST URL parameters cannot change the authority".into());
        }
        let name = capture
            .get(1)
            .or_else(|| capture.get(2))
            .expect("URL placeholder name")
            .as_str();
        let value = if let Some(value) = used.get(name) {
            value
        } else {
            let raw = payload
                .remove(name)
                .ok_or_else(|| format!("Required URL parameter '{name}' not found in arguments"))?;
            let text = match &raw {
                Value::Null => "None".to_owned(),
                Value::Bool(true) => "True".to_owned(),
                Value::Bool(false) => "False".to_owned(),
                _ => form_value(&raw),
            };
            if text
                .split(['/', '\\'])
                .any(|segment| matches!(segment, "." | ".."))
            {
                return Err(format!(
                    "URL parameter '{name}' must not contain dot segments"
                ));
            }
            if percent_decode_str(&text).decode_utf8_lossy() != text {
                return Err(format!(
                    "URL parameter '{name}' must not contain percent-encoded sequences"
                ));
            }
            used.entry(name)
                .or_insert_with(|| utf8_percent_encode(&text, URL_VALUE).to_string())
        };
        result.push_str(&template[end..matched.start()]);
        result.push_str(value);
        end = matched.end();
    }
    if end == 0 {
        return Ok(original);
    }
    result.push_str(&template[end..]);
    let substituted = Url::parse(&result).map_err(|_| "Invalid REST tool URL")?;
    if substituted.origin() != original.origin() {
        return Err("REST URL parameters cannot change the authority".into());
    }
    Ok(substituted)
}

fn mapping(raw: Option<&str>) -> Result<Mapping, String> {
    raw.map(serde_json::from_str::<Option<Mapping>>)
        .transpose()
        .map(Option::flatten)
        .map(Option::unwrap_or_default)
        .map_err(|_| "Invalid REST tool mapping".into())
}

fn form_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        value => value.to_string(),
    }
}

fn multipart(headers: &mut HeaderMap, fields: Map<String, Value>) -> String {
    let boundary = Uuid::new_v4().simple().to_string();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&format!("multipart/form-data; boundary={boundary}"))
            .expect("valid multipart boundary"),
    );
    let mut body = String::new();
    for (name, value) in fields {
        let escaped = name
            .replace('\\', "\\\\")
            .replace('"', "%22")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        write!(
            body,
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{escaped}\"\r\n\r\n{}\r\n",
            form_value(&value)
        )
        .expect("write multipart field");
    }
    write!(body, "--{boundary}--\r\n").expect("write multipart boundary");
    body
}

async fn response_result(
    service: &GatewayService,
    expression: &str,
    response: &RestResponse,
    output_schema: Option<&Value>,
) -> Value {
    let status = response.status;
    if status == StatusCode::NO_CONTENT {
        return text_result("Request completed successfully (No Content)", false);
    }
    let text_limit = service.rest_response_text_limit;
    let text = response_body::decode_text(
        &response.body,
        response
            .content_type
            .as_ref()
            .and_then(|value| value.to_str().ok()),
    );
    let bounded: String = text.chars().take(text_limit).collect();
    let json_body = response_body::decode_json(&response.body);
    let output_schema = output_schema.filter(|value| !value.as_object().is_some_and(Map::is_empty));
    let success = matches!(status.as_u16(), 200 | 201 | 202 | 206);
    if !success {
        let message = match &json_body {
            Ok(value) if value.get("error").is_some() => value["error"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    value["error"]
                        .to_string()
                        .chars()
                        .take(text_limit)
                        .collect()
                }),
            Ok(_) if status.is_success() => "Tool error encountered".into(),
            Ok(_) => format!("HTTP {}: {bounded}", status.as_u16()),
            Err(error) => {
                let diagnostic = diagnostics::parse_error(error, &text, &bounded, text_limit);
                if status.is_success() {
                    diagnostic
                } else {
                    format!("HTTP {}: {diagnostic}", status.as_u16())
                }
            }
        };
        let mut result = text_result(message, true);
        if !status.is_success() {
            result["structuredContent"] = json!({"status_code":status.as_u16()});
        }
        return result;
    }

    let result = match json_body {
        Ok(value) => value,
        Err(error) if output_schema.is_some() => {
            return text_result(
                diagnostics::parse_error(&error, &text, &bounded, text_limit),
                true,
            );
        }
        Err(_) if text.is_empty() => json!({"error":"Empty response body"}),
        Err(_) => json!({"response_text":bounded}),
    };
    let result = match service.response_filters.apply(expression, result).await {
        Ok(value) => value,
        Err(error) => return text_result(error.invocation_message(), true),
    };
    let envelope = mcp_envelope(&result);
    let wrapped = envelope.is_some();
    let mut response = envelope.unwrap_or_else(|| {
        text_result(
            serde_json::to_string_pretty(&result).expect("JSON serialization"),
            false,
        )
    });
    if let Some(schema) = output_schema
        && response["isError"] != true
    {
        let parsed_text = wrapped
            .then(|| {
                response["content"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|block| block["text"].as_str())
                    .find_map(|text| serde_json::from_str::<Value>(text).ok())
            })
            .flatten();
        let data = if wrapped {
            response
                .get("structuredContent")
                .or(parsed_text.as_ref().filter(|value| !value.is_null()))
        } else {
            (!result.is_null()).then_some(&result)
        };
        if let Some(data) = data {
            let validation = service
                .schema_validation
                .validate(schema.clone(), data.clone(), Target::Output)
                .await;
            let Ok((data, error)) = validation else {
                return text_result(
                    "Output validation error: REST validation could not complete",
                    true,
                );
            };
            if let Some(error) = error {
                response["content"] = json!([ContentBlock::text(error)]);
                response["isError"] = json!(true);
            }
            response["structuredContent"] = data;
        }
    }
    response
}

pub(super) fn for_caller(mut result: Value, modern: bool) -> Value {
    let Some(fields) = result.as_object_mut() else {
        return result;
    };
    if fields.get("structuredContent").is_some_and(Value::is_null) {
        fields.remove("structuredContent");
    } else if !modern
        && fields
            .get("structuredContent")
            .is_some_and(|value| !value.is_object())
    {
        let data = fields
            .remove("structuredContent")
            .expect("structured content");
        if let Some(content) = fields.get_mut("content").and_then(Value::as_array_mut)
            && !content.iter().any(|block| {
                block["type"] == "text"
                    && block["text"].as_str().is_some_and(|text| {
                        serde_json::from_str::<Value>(text).is_ok_and(|value| value == data)
                    })
            })
        {
            content.push(json!(ContentBlock::text(data.to_string())));
        }
    }
    result
}

fn mcp_envelope(result: &Value) -> Option<Value> {
    let fields = result.as_object()?;
    let aliases = [
        ("is_error", "isError"),
        ("structured_content", "structuredContent"),
        ("meta", "_meta"),
    ];
    if fields.keys().any(|key| {
        key != "content"
            && !aliases
                .iter()
                .any(|(alias, canonical)| key == alias || key == canonical)
    }) {
        return None;
    }
    let markers = [
        "isError",
        "is_error",
        "structuredContent",
        "structured_content",
    ];
    let has_content_blocks =
        fields
            .get("content")
            .and_then(Value::as_array)
            .is_some_and(|blocks| {
                !blocks.is_empty() && blocks.iter().all(|block| block["type"].is_string())
            });
    if !has_content_blocks && !markers.iter().any(|key| fields.contains_key(*key)) {
        return None;
    }
    let mut fields = fields.clone();
    for (alias, canonical) in aliases {
        if let Some(value) = fields.remove(alias) {
            fields.entry(canonical.to_owned()).or_insert(value);
        }
    }
    let result = serde_json::from_value::<CallToolResult>(Value::Object(fields)).ok()?;
    serde_json::to_value(result).ok()
}

fn text_result(text: impl Into<String>, error: bool) -> Value {
    json!({"content":[ContentBlock::text(text.into())],"isError":error})
}
