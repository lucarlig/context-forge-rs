// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, time::Instant};

use axum::http::HeaderValue;
use url::Url;

use super::*;
use crate::{
    gateway_records::{GatewayList, GatewayRecord},
    upstream::HandshakeFailure,
};

const STRICT_TIMEOUT: Duration = Duration::from_secs(10);
const UNAVAILABLE: &str = "The requested MCP gateway is unavailable for this handshake.";
const BLOCKED: &str = "The MCP server URL is not allowed for testing. Confirm the URL is correct and the host is permitted by your test policy.";
const AUTH_REJECTED: &str = "The MCP server rejected the credentials. Check the stored credentials for this server or supply an Authorization header.";
const UNREACHABLE: &str = "Could not reach the MCP server. Verify the URL and that the server is running and reachable from this host.";
const INVALID_MCP: &str = "The server's response is not valid MCP. The URL may point at a service that does not speak MCP.";
const NEGOTIATION_FAILED: &str = "The server responded but MCP negotiation failed. Confirm the URL points at an MCP endpoint (for example /mcp or /sse) and supports an MCP protocol this gateway understands.";
const STORED_CREDENTIAL_DENIED: &str = "Testing an MCP server with its stored credentials requires gateways.update and ownership of the MCP server";

#[derive(Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Validation {
    #[default]
    Handshake,
    PostAuthorization,
}

#[derive(Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Credentials {
    #[default]
    StoredWithOverride,
    CandidateOnly,
}

#[derive(Deserialize)]
pub(in crate::gateway) struct Input {
    #[serde(alias = "baseUrl")]
    base_url: String,
    path: Option<String>,
    headers: Option<BTreeMap<String, String>>,
    #[serde(alias = "gatewayId", alias = "mcp_server_id", alias = "mcpServerId")]
    gateway_id: Option<String>,
    #[serde(default, alias = "validationMode")]
    validation_mode: Validation,
    #[serde(default, alias = "credentialMode")]
    credential_mode: Credentials,
}

#[derive(Deserialize)]
pub(in crate::gateway) struct Scope {
    team_id: Option<String>,
}

pub(in crate::gateway) async fn test(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(scope): Query<Scope>,
    incoming: HeaderMap,
    Json(input): Json<Input>,
) -> Result<Json<Value>, CatalogApiError> {
    let start = Instant::now();
    if !service
        .access
        .allows(&principal, "gateways.read", RoleContext::AnyTeam, false)
        .await?
    {
        return Err(access_denied());
    }
    let team = scope
        .team_id
        .as_deref()
        .filter(|team| !team.is_empty())
        .map(|team| {
            Uuid::parse_str(team)
                .map(|team| team.simple().to_string())
                .map_err(|_| CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid team ID"))
        })
        .transpose()?;
    if let Some(team) = team.as_ref()
        && !match &principal.visibility {
            TeamVisibility::Admin => true,
            TeamVisibility::Public => false,
            TeamVisibility::Teams(teams) => teams.contains(team),
        }
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access to requested team is not permitted",
        ));
    }
    let strict = input.validation_mode == Validation::PostAuthorization;
    let candidate = input.credential_mode == Credentials::CandidateOnly;
    if (strict || candidate) && input.gateway_id.as_deref().is_none_or(str::is_empty) {
        return Err(invalid(if strict {
            "gateway_id is required for post_authorization validation"
        } else {
            "gateway_id is required when credential_mode is candidate_only"
        }));
    }
    if strict
        && (candidate
            || input
                .headers
                .as_ref()
                .is_some_and(|headers| !headers.is_empty()))
    {
        return Err(invalid(
            "post_authorization validation requires stored credentials and does not accept header overrides",
        ));
    }
    let path = input
        .path
        .as_deref()
        .unwrap_or_default()
        .trim_start_matches('/');
    if path.chars().any(char::is_control) {
        return Err(invalid("Path must not contain control characters"));
    }
    let base = Url::parse(&input.base_url).map_err(|_| invalid("Invalid base_url"))?;
    let mut target = base.clone();
    if !path.is_empty() {
        target.set_path(&format!("{}/{path}", base.path().trim_end_matches('/')));
    }
    let gateways = service
        .database
        .listed_gateways(
            access::catalog_scope(Some(&principal)),
            GatewayList {
                include_inactive: false,
                visibility: None,
                team: team.as_deref(),
                after: None,
                limit: i64::MAX,
            },
        )
        .await?;
    let permitted = base.host_str().is_some_and(|host| {
        let host = host.trim_end_matches('.');
        if service.gateway_oauth.handshake_registered_only {
            gateways.iter().any(|gateway| {
                Url::parse(&gateway.url)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .is_some_and(|registered| {
                        host.eq_ignore_ascii_case(registered.trim_end_matches('.'))
                    })
            })
        } else {
            service
                .gateway_oauth
                .handshake_allowed_hosts
                .iter()
                .any(|rule| host_matches(host, rule))
        }
    });
    let client = if service.gateway_oauth.handshake_public_only {
        service.upstream.public_targets_only()
    } else {
        service.upstream.clone()
    };
    if !permitted || client.check_pinned_endpoint(target.as_str()).await.is_err() {
        return Ok(Json(if strict {
            stage_failure(start, "gateway", "blocked", None)
        } else {
            ordinary_failure(start, "none", "transport", BLOCKED)
        }));
    }
    let gateway = gateways
        .into_iter()
        .find(|gateway| match input.gateway_id.as_deref() {
            Some(id) => gateway.id == id,
            None => same_url(&gateway.url, &base),
        });
    if strict {
        let Some(gateway) = gateway else {
            return Ok(Json(stage_failure(
                start,
                "gateway",
                "gateway_unavailable",
                None,
            )));
        };
        if !service
            .access
            .allows(&principal, "gateways.update", role_context(&gateway), false)
            .await?
        {
            return Err(access_denied());
        }
        if !same_url(&gateway.url, &target) {
            return Ok(Json(stage_failure(
                start,
                "gateway",
                "gateway_unavailable",
                None,
            )));
        }
        return Ok(Json(
            validate_authorization(&service, &client, &gateway, &principal, start).await,
        ));
    }
    if input.gateway_id.is_some()
        && !gateway
            .as_ref()
            .is_some_and(|gateway| same_url(&gateway.url, &base))
    {
        return Ok(Json(ordinary_failure(
            start,
            "none",
            "transport",
            UNAVAILABLE,
        )));
    }
    let mut form = HeaderMap::new();
    for (name, value) in input.headers.into_iter().flatten() {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid("Invalid handshake header name"))?;
        if name == header::HOST {
            continue;
        }
        let mut value =
            HeaderValue::from_str(&value).map_err(|_| invalid("Invalid handshake header value"))?;
        value.set_sensitive(true);
        form.insert(name, value);
    }
    let mut credential_source = "none";
    let mut credentials = UpstreamCredentials::default();
    let transport = gateway
        .as_ref()
        .and_then(|gateway| UpstreamTransport::from_name(&gateway.transport))
        .unwrap_or(UpstreamTransport::StreamableHttp);
    if let Some(gateway) = gateway.as_ref() {
        let has_stored = gateway.client_cert.is_some()
            || gateway
                .auth_type
                .as_deref()
                .is_some_and(|kind| !matches!(kind, "" | "none" | "one_time_auth"));
        if candidate || !has_stored {
            credentials.tls = TlsMaterial::from_pem(gateway.ca_certificate.as_deref(), None, None)
                .map_err(|_| CatalogApiError::unavailable())?;
        } else {
            if (!path.is_empty() || !form.is_empty())
                && (!service
                    .access
                    .allows(&principal, "gateways.update", role_context(gateway), false)
                    .await?
                    || !management::owns_gateway(&service.database, &principal, gateway).await?)
            {
                return Err(CatalogApiError::detail(
                    StatusCode::FORBIDDEN,
                    STORED_CREDENTIAL_DENIED,
                ));
            }
            let connection = service
                .database
                .gateway_connection(
                    &gateway.id,
                    &gateway.url,
                    false,
                    Some(gateway.version),
                    None,
                )
                .await?
                .ok_or_else(CatalogApiError::unavailable)?;
            if form.contains_key(header::AUTHORIZATION) && connection.kind == "oauth" {
                credentials.tls = service
                    .connection_tls(&connection)
                    .await
                    .map_err(|_| CatalogApiError::unavailable())?;
            } else {
                let mut subject_header = HeaderMap::new();
                if connection.oauth.as_deref().is_some_and(is_token_exchange)
                    && let Some(value) = incoming.get(header::AUTHORIZATION)
                {
                    subject_header.insert(header::AUTHORIZATION, value.clone());
                }
                match service
                    .connection_credentials(
                        &gateway.id,
                        &gateway.url,
                        connection,
                        Some(&subject_header),
                        Some(&principal),
                        UpstreamUse::Discovery,
                    )
                    .await
                {
                    Ok(Some(loaded)) => {
                        credentials = loaded;
                        credential_source = "stored";
                    }
                    Ok(None) => {}
                    Err(ToolError::OAuthRequired(_)) => {
                        return Ok(Json(ordinary_failure(
                            start,
                            "none",
                            "auth",
                            &format!(
                                "Please authorize {} first. Visit /oauth/authorize/{} to complete OAuth flow.",
                                gateway.name, gateway.id,
                            ),
                        )));
                    }
                    Err(_) => {
                        return Ok(Json(ordinary_failure(
                            start,
                            "none",
                            "auth",
                            "The stored credentials could not be loaded.",
                        )));
                    }
                }
            }
        }
    }
    if !form.is_empty()
        && (candidate
            || form.contains_key(header::AUTHORIZATION)
            || form
                .keys()
                .any(|name| credentials.headers.contains_key(name)))
    {
        credential_source = "form";
    }
    credentials.headers.extend(form);
    let endpoint = UpstreamEndpoint {
        url: target.as_str(),
        transport,
        credentials: Some(&credentials),
    };
    let outcome = client.test_handshake(endpoint, false).await;
    let mut response = match outcome {
        Ok(details) => success(start, details, credential_source, false),
        Err(HandshakeFailure::Negotiation(
            UpstreamError::Status(401 | 403) | UpstreamError::OAuthRejected(_),
        )) => ordinary_failure(start, credential_source, "auth", AUTH_REJECTED),
        Err(HandshakeFailure::Negotiation(
            UpstreamError::Timeout
            | UpstreamError::Transport
            | UpstreamError::Resolve
            | UpstreamError::BlockedDestination
            | UpstreamError::Status(300..=399),
        )) => ordinary_failure(start, credential_source, "transport", UNREACHABLE),
        Err(HandshakeFailure::Negotiation(UpstreamError::Rpc { .. })) => {
            ordinary_failure(start, credential_source, "protocol", NEGOTIATION_FAILED)
        }
        Err(_) => ordinary_failure(start, credential_source, "invalid_response", INVALID_MCP),
    };
    for (_, value) in credentials
        .headers
        .iter()
        .filter(|(_, value)| value.is_sensitive())
    {
        if let Ok(value) = value.to_str() {
            redact(
                &mut response,
                value.strip_prefix("Bearer ").unwrap_or(value),
            );
        }
    }
    Ok(Json(response))
}

fn role_context(gateway: &GatewayRecord) -> RoleContext<'_> {
    gateway
        .team_id
        .as_deref()
        .map_or(RoleContext::Global, RoleContext::Team)
}

fn same_url(configured: &str, expected: &Url) -> bool {
    Url::parse(configured).is_ok_and(|configured| configured == *expected)
}

fn host_matches(host: &str, rule: &str) -> bool {
    let rule = rule.to_ascii_lowercase();
    let rule = rule.trim_end_matches('.');
    let host = host.to_ascii_lowercase();
    match rule.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.')),
        None => host == rule,
    }
}

fn access_denied() -> CatalogApiError {
    CatalogApiError::detail(StatusCode::FORBIDDEN, "Access denied")
}

fn invalid(message: &'static str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}

async fn validate_authorization(
    service: &GatewayService,
    client: &UpstreamClient,
    gateway: &GatewayRecord,
    principal: &Principal,
    start: Instant,
) -> Value {
    if gateway.auth_type.as_deref() != Some("oauth")
        || !gateway
            .oauth_config
            .as_deref()
            .is_some_and(is_authorization_code)
    {
        return stage_failure(start, "gateway", "unsupported_auth", None);
    }
    let token = match tokio::time::timeout(
        STRICT_TIMEOUT.saturating_sub(start.elapsed()),
        token_access::read_validation_token(
            service,
            &gateway.id,
            gateway.version,
            &principal.email,
        ),
    )
    .await
    {
        Ok(Ok(token)) => token,
        Ok(Err(code)) => return stage_failure(start, "token", code, None),
        Err(_) => return stage_failure(start, "token", "timeout", None),
    };
    let Some(transport) = UpstreamTransport::from_name(&gateway.transport) else {
        return stage_failure(start, "negotiation", "mcp_handshake_failed", None);
    };
    let header = Zeroizing::new(format!("Bearer {}", token.as_str()));
    let Ok(mut header) = HeaderValue::from_str(&header) else {
        return stage_failure(start, "token", "invalid_token", None);
    };
    header.set_sensitive(true);
    let tls = match tokio::time::timeout(
        STRICT_TIMEOUT.saturating_sub(start.elapsed()),
        service.oauth_connection_tls(&gateway.id, &gateway.url, gateway.version),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(_)) => return stage_failure(start, "negotiation", "mcp_handshake_failed", None),
        Err(_) => return stage_failure(start, "negotiation", "timeout", None),
    };
    let mut credentials = UpstreamCredentials {
        tls,
        ..UpstreamCredentials::default()
    };
    credentials.headers.insert(header::AUTHORIZATION, header);
    let endpoint = UpstreamEndpoint {
        url: &gateway.url,
        transport,
        credentials: Some(&credentials),
    };
    let remaining = STRICT_TIMEOUT.saturating_sub(start.elapsed());
    if remaining.is_zero() {
        return stage_failure(start, "negotiation", "timeout", None);
    }
    let result = client
        .with_timeout_cap(remaining)
        .test_handshake(endpoint, true)
        .await;
    match result {
        Ok(details) => {
            let mut response = success(start, details, "stored", true);
            redact(&mut response, &token);
            response
        }
        Err(HandshakeFailure::Negotiation(error)) => stage_failure(
            start,
            "negotiation",
            failure_code(&error, "mcp_handshake_failed"),
            None,
        ),
        Err(HandshakeFailure::ToolsUnsupported(path)) => {
            stage_failure(start, "tools_list", "tools_unsupported", Some(path))
        }
        Err(HandshakeFailure::ToolsList(path, error)) => stage_failure(
            start,
            "tools_list",
            failure_code(&error, "tools_list_failed"),
            Some(path),
        ),
    }
}

fn failure_code(error: &UpstreamError, fallback: &'static str) -> &'static str {
    match error {
        UpstreamError::Timeout => "timeout",
        UpstreamError::Status(401) => "invalid_token",
        UpstreamError::OAuthRejected(code) => code,
        UpstreamError::Rpc {
            data: Some(data), ..
        } => match data["error"].as_str() {
            Some("invalid_token") => "invalid_token",
            Some("insufficient_scope") => "insufficient_scope",
            _ => fallback,
        },
        _ => fallback,
    }
}

fn base_response(start: Instant) -> Value {
    json!({
        "success":false,"latencyMs":u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        "negotiationPath":null,"protocolVersion":null,"serverName":null,
        "serverVersion":null,"capabilities":null,"componentCounts":null,"countsPartial":false,
        "credentialSource":"none","failureClass":null,"error":null,"rawPreview":null,
        "stages":null,"failedStage":null,"errorCode":null,"reauthorizationRequired":false,
    })
}

fn success(start: Instant, mut details: Value, source: &str, strict: bool) -> Value {
    let mut result = base_response(start);
    if let (Some(result), Some(details)) = (result.as_object_mut(), details.as_object_mut()) {
        result.append(details);
    }
    result["success"] = true.into();
    result["credentialSource"] = source.into();
    if strict {
        result["stages"] = json!({"token":"ok","negotiation":"ok","tools_list":"ok"});
    }
    result
}

fn ordinary_failure(start: Instant, source: &str, class: &str, message: &str) -> Value {
    let mut result = base_response(start);
    result["credentialSource"] = source.into();
    result["failureClass"] = class.into();
    result["error"] = message.into();
    result
}

fn stage_failure(start: Instant, stage: &str, code: &str, path: Option<&str>) -> Value {
    let (class, message) = match code {
        "gateway_unavailable" => (
            "transport",
            "The requested gateway is unavailable for validation.",
        ),
        "blocked" => (
            "transport",
            "The target is blocked by the gateway test policy.",
        ),
        "unsupported_auth" => (
            "protocol",
            "Post-authorization validation requires an OAuth authorization_code gateway.",
        ),
        "authorization_missing" => (
            "auth",
            "Authorize this gateway before testing the connection.",
        ),
        "token_expired" => (
            "auth",
            "The stored token has expired. Authorize this gateway again.",
        ),
        "invalid_token" => (
            "auth",
            "The stored token is invalid. Authorize this gateway again.",
        ),
        "insufficient_scope" => (
            "auth",
            "The provider reports insufficient scope. Review the requested scopes and authorize again.",
        ),
        "token_storage_unavailable" => (
            "transport",
            "Stored authorization cannot be read. Try again later.",
        ),
        "tools_unsupported" => (
            "protocol",
            "The server does not advertise tools. A live tools/list request cannot be validated.",
        ),
        "tools_list_failed" => (
            "protocol",
            "The required tools/list request fails. Check upstream access and protocol support.",
        ),
        "mcp_handshake_failed" => (
            "protocol",
            "MCP negotiation fails. Check the gateway transport and server configuration.",
        ),
        "timeout" => (
            "transport",
            "Connection validation exceeds its ten-second budget.",
        ),
        _ => ("protocol", "Connection validation fails. Try again later."),
    };
    let stages = match stage {
        "token" => ["failed", "skipped", "skipped"],
        "negotiation" => ["ok", "failed", "skipped"],
        "tools_list" if code == "tools_unsupported" => ["ok", "ok", "unsupported"],
        "tools_list" => ["ok", "ok", "failed"],
        _ => ["skipped", "skipped", "skipped"],
    };
    let source = if matches!(stage, "negotiation" | "tools_list") {
        "stored"
    } else {
        "none"
    };
    let mut result = ordinary_failure(start, source, class, message);
    result["negotiationPath"] = json!(path);
    result["stages"] = json!({"token":stages[0],"negotiation":stages[1],"tools_list":stages[2]});
    result["failedStage"] = stage.into();
    result["errorCode"] = code.into();
    result["reauthorizationRequired"] = (class == "auth").into();
    result
}

fn redact(value: &mut Value, token: &str) {
    if token.is_empty() {
        return;
    }
    match value {
        Value::String(text) if text.contains(token) => *text = text.replace(token, "[REDACTED]"),
        Value::Array(items) => items.iter_mut().for_each(|value| redact(value, token)),
        Value::Object(fields) => {
            for (key, mut value) in std::mem::take(fields) {
                redact(&mut value, token);
                fields.insert(key.replace(token, "[REDACTED]"), value);
            }
        }
        _ => {}
    }
}
