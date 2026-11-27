// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt::Write, sync::LazyLock};

use axum::http::{HeaderValue, Method};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde_json::Map;
use url::{Url, form_urlencoded};

use super::*;
use crate::{catalog::RestTool, forward_headers::hop_header_name, sigv4::SigV4Config};

const URL_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
const TEXT_LIMIT: usize = 5000;
type Mapping = BTreeMap<String, String>;

pub(super) async fn execute(
    service: &GatewayService,
    tool: &CatalogTool,
    config: &RestTool,
    params: &CallToolRequestParams,
    principal: Option<&Principal>,
    incoming: Option<&HeaderMap>,
) -> Result<Value, ToolError> {
    if config.pending_policy || tool.needs_upstream_config {
        return tool_result_error("REST tool requires an unavailable invocation policy");
    }
    let arguments = params.arguments.clone().unwrap_or_default();
    let (mut credentials, managed) = match stored_credentials(service, config) {
        Ok(config) => config,
        Err(error) => return tool_result_error(error.to_string()),
    };
    if let Some(incoming) = incoming {
        service
            .header_forwarding
            .apply(
                &service.database,
                &mut credentials.headers,
                incoming,
                None,
                managed,
            )
            .await?;
    }
    let mut request = match build_request(tool, config, arguments, &mut credentials.headers) {
        Ok(request) => request,
        Err(message) => return tool_result_error(format!("Tool invocation failed: {message}")),
    };
    let audience = if tool.gateway_id.is_empty() {
        &tool.id
    } else {
        &tool.gateway_id
    };
    service
        .identity_forwarding
        .apply(&mut credentials, principal, audience, None)
        .map_err(|_| ToolError::Unavailable)?;
    *request.headers_mut() = credentials.headers;
    let upstream = config
        .timeout_ms
        .and_then(|ms| u64::try_from(ms).ok())
        .filter(|ms| *ms > 0)
        .map(|ms| service.upstream.with_timeout_cap(Duration::from_millis(ms)));
    let result = upstream
        .as_ref()
        .unwrap_or(&service.upstream)
        .rest_response(request, credentials.sigv4.as_deref())
        .await;
    match result {
        Ok((status, body)) => Ok(response_result(
            &service.response_filters,
            &tool.response_filter,
            status,
            &body,
            tool.definition.output_schema.as_ref(),
        )
        .await),
        Err(UpstreamError::BlockedDestination | UpstreamError::InvalidUrl) => {
            tool_result_error("Tool invocation failed: Outbound URL blocked by URL policy")
        }
        Err(UpstreamError::Timeout) => tool_result_error("Tool invocation timed out"),
        Err(_) => tool_result_error("Tool invocation failed: REST upstream request failed"),
    }
}

fn stored_credentials(
    service: &GatewayService,
    config: &RestTool,
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
    let managed = match auth_type.as_str() {
        "" | "none" | "one_time_auth" if config.auth_value.is_none() => false,
        "sigv4" => {
            credentials.sigv4 = Some(SigV4Config::load(
                cipher.ok_or(CredentialError)?,
                config.sigv4_config.as_deref().ok_or(CredentialError)?,
            )?);
            true
        }
        "" | "basic" | "bearer" | "authheaders" => {
            let auth = tool_api::decode_stored_auth(
                cipher.ok_or(CredentialError)?,
                config.auth_value.as_deref().ok_or(CredentialError)?,
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
    filters: &crate::response_filter::ResponseFilters,
    expression: &str,
    status: StatusCode,
    body: &[u8],
    output_schema: Option<&Value>,
) -> Value {
    if status == StatusCode::NO_CONTENT {
        return text_result("Request completed successfully (No Content)", false);
    }
    let text = String::from_utf8_lossy(body);
    let bounded: String = text.chars().take(TEXT_LIMIT).collect();
    let json_body: Result<Value, _> = serde_json::from_slice(body);
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
                        .take(TEXT_LIMIT)
                        .collect()
                }),
            Ok(_) if status.is_success() => "Tool error encountered".into(),
            Ok(_) => format!("HTTP {}: {bounded}", status.as_u16()),
            Err(_) if body.is_empty() => format!("HTTP {}: Empty response body", status.as_u16()),
            Err(_) => format!(
                "HTTP {}: Response body is not valid JSON.\n{bounded}",
                status.as_u16()
            ),
        };
        let mut result = text_result(message, true);
        if !status.is_success() {
            result["structuredContent"] = json!({"status_code":status.as_u16()});
        }
        return result;
    }

    let result = match json_body {
        Ok(value) => value,
        Err(_) if output_schema.is_some() => {
            return text_result(
                if body.is_empty() {
                    "Empty response body".into()
                } else {
                    format!("Response body is not valid JSON.\n{bounded}")
                },
                true,
            );
        }
        Err(_) if body.is_empty() => json!({"error":"Empty response body"}),
        Err(_) => json!({"response_text":bounded}),
    };
    let result = match filters.apply(expression, result).await {
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
    if let Some(schema) = output_schema.filter(|schema| *schema != &json!({}))
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
            response.get("structuredContent").or(parsed_text.as_ref())
        } else {
            Some(&result)
        };
        let Some(data) = data else {
            return text_result(
                "Output validation error: outputSchema defined but no structured output returned",
                true,
            );
        };
        let validator = jsonschema::options().offline().build(schema);
        if validator.is_err() || !validator.is_ok_and(|validator| validator.is_valid(data)) {
            return text_result(
                "Output validation error: REST response does not match outputSchema",
                true,
            );
        }
        response["structuredContent"] = data.clone();
    }
    response
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
