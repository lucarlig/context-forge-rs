// SPDX-License-Identifier: Apache-2.0

use axum::extract::{DefaultBodyLimit, rejection::JsonRejection};
use serde_json::Map;

use super::*;
use crate::{access::BrowserApiSession, http_boundary::csrf::browser_proof_valid};

const MAX_REGISTRATION_BYTES: usize = 96 * 1024;
const DUPLICATE: &str = "Server already registered";
const MISSING: &str = "Server not found in catalog";

pub(super) fn routes(router: Router<Arc<GatewayService>>) -> Router<Arc<GatewayService>> {
    router.route(
        "/v1/catalog/{id}/register",
        post(register).layer(DefaultBodyLimit::max(MAX_REGISTRATION_BYTES)),
    )
}

pub(super) fn admin_routes(
    router: Router<Arc<GatewayService>>,
    base: &str,
) -> Router<Arc<GatewayService>> {
    router
        .route(
            &format!("{base}/{{id}}/register"),
            post(admin_register).layer(DefaultBodyLimit::max(MAX_REGISTRATION_BYTES)),
        )
        .route(
            &format!("{base}/bulk-register"),
            post(bulk_register).layer(DefaultBodyLimit::max(MAX_REGISTRATION_BYTES)),
        )
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Visibility {
    #[default]
    Private,
    Team,
    Public,
}

impl Visibility {
    fn name(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Team => "team",
            Self::Public => "public",
        }
    }
}

#[derive(Default, Deserialize)]
struct ScopeInput {
    visibility: Option<Visibility>,
    team_id: Option<String>,
}

#[derive(Default, Deserialize)]
struct RegisterInput {
    name: Option<String>,
    api_key: Option<String>,
    oauth_credentials: Option<Map<String, Value>>,
    server_id: Option<String>,
    #[serde(flatten)]
    scope: ScopeInput,
}

struct RegistrationScope<'a> {
    visibility: Visibility,
    team: Option<&'a str>,
}

async fn authorize(
    service: &GatewayService,
    principal: &Principal,
    team: Option<&str>,
) -> Result<(), CatalogApiError> {
    if can_register(service, principal, team).await? {
        Ok(())
    } else {
        Err(forbidden("Access denied"))
    }
}

pub(super) async fn can_register(
    service: &GatewayService,
    principal: &Principal,
    team: Option<&str>,
) -> Result<bool, sqlx::Error> {
    for permission in ["servers.create", "gateways.create"] {
        if !service
            .access
            .allows(
                principal,
                permission,
                team.map_or(RoleContext::AnyTeam, RoleContext::Team),
                false,
            )
            .await?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn resolve_scope<'a>(
    service: &GatewayService,
    registry: &CatalogRegistry,
    principal: &Principal,
    input: &'a ScopeInput,
) -> Result<RegistrationScope<'a>, CatalogApiError> {
    let visibility = input.visibility.unwrap_or_default();
    let team = input
        .team_id
        .as_deref()
        .map(str::trim)
        .filter(|team| !team.is_empty());
    if principal.email.is_empty() || principal.email == "unknown" {
        return Err(forbidden(
            "Authenticated identity required for catalog registration",
        ));
    }
    if principal.visibility == TeamVisibility::Public && !matches!(visibility, Visibility::Public) {
        return Err(forbidden(
            "Public-only tokens can only create public catalog registrations",
        ));
    }
    if matches!(visibility, Visibility::Public) && team.is_some() && !registry.allow_public_team {
        return Err(forbidden(
            "Public visibility is disabled by platform configuration (ALLOW_PUBLIC_VISIBILITY=false).",
        ));
    }
    if matches!(visibility, Visibility::Team) && team.is_none() {
        return Err(forbidden("team_id is required when visibility is 'team'"));
    }
    if let Some(team) = team {
        let in_scope = match &principal.visibility {
            TeamVisibility::Admin => true,
            TeamVisibility::Public => false,
            TeamVisibility::Teams(teams) => teams.iter().any(|id| id == team),
        };
        if !in_scope {
            return Err(forbidden(
                "Requested team is not in the caller's token scope",
            ));
        }
        if !service
            .database
            .memberships(&principal.email)
            .await?
            .iter()
            .any(|id| id == team)
        {
            return Err(forbidden(format!(
                "Caller is not an active member of team '{team}' or team is inactive"
            )));
        }
        authorize(service, principal, Some(team)).await?;
    }
    Ok(RegistrationScope { visibility, team })
}

#[derive(Serialize)]
struct Registration {
    success: bool,
    server_id: String,
    message: String,
    error: Option<&'static str>,
    oauth_required: bool,
    #[serde(skip)]
    public_error: Option<(StatusCode, &'static str)>,
}

impl Registration {
    fn failure(message: &'static str, detail: &'static str) -> Self {
        Self {
            success: false,
            server_id: String::new(),
            message: message.into(),
            error: Some(detail),
            oauth_required: false,
            public_error: None,
        }
    }

    fn duplicate(id: String) -> Self {
        Self {
            server_id: id,
            public_error: Some((StatusCode::CONFLICT, DUPLICATE)),
            ..Self::failure(DUPLICATE, "This server is already registered in the system")
        }
    }
}

type OptionalBody = Result<Option<Json<Option<RegisterInput>>>, JsonRejection>;

fn input_from_request(input: OptionalBody, admin: bool) -> Result<RegisterInput, CatalogApiError> {
    let input = input.map_err(json_error)?.and_then(|Json(input)| input);
    if admin
        && input
            .as_ref()
            .is_some_and(|input| input.server_id.is_none())
    {
        return Err(invalid("server_id is required"));
    }
    validate_input(input.unwrap_or_default())
}

fn validate_input(input: RegisterInput) -> Result<RegisterInput, CatalogApiError> {
    if input.name.as_ref().is_some_and(|name| {
        name.len() > 255
            || name
                .chars()
                .any(|c| c.is_control() || matches!(c, '<' | '>'))
    }) {
        return Err(invalid("Invalid server name"));
    }
    if input
        .api_key
        .as_ref()
        .is_some_and(|key| key.chars().count() > 4096)
    {
        return Err(invalid("Invalid API key"));
    }
    if let Some(credentials) = &input.oauth_credentials
        && (credentials.len() > 16
            || serde_json::to_vec(credentials).map_or(true, |body| body.len() > 65536)
            || credentials.values().any(|value| match value {
                Value::Array(items) => items.iter().any(|item| item.is_array() || item.is_object()),
                Value::Object(_) => true,
                _ => false,
            }))
    {
        return Err(invalid("Invalid OAuth credentials"));
    }
    Ok(input)
}

async fn register(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    input: OptionalBody,
) -> Result<Json<Registration>, CatalogApiError> {
    let input = input_from_request(input, false)?;
    let mut result = register_one(&service, &principal, &id, input).await?;
    if let Some((status, message)) = result.public_error {
        return Err(CatalogApiError::detail(status, message));
    }
    result.error = None;
    Ok(Json(result))
}

async fn admin_register(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    session: Option<Extension<BrowserApiSession>>,
    Path(id): Path<String>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    input: OptionalBody,
) -> Result<Response, CatalogApiError> {
    csrf(&service, session.is_some(), &uri, &headers)?;
    let input = input_from_request(input, true)?;
    let result = register_one(&service, &principal, &id, input).await?;
    if headers
        .get("hx-request")
        .is_some_and(|value| value == "true")
    {
        return Ok(crate::local_auth::browser::registry_registration_fragment(
            &id,
            &service.gateway_oauth.admin_root,
            serde_json::to_value(result).map_err(|_| CatalogApiError::unavailable())?,
        ));
    }
    Ok(Json(result).into_response())
}

#[derive(Deserialize)]
struct BulkInput {
    server_ids: Vec<String>,
    skip_errors: Option<bool>,
    #[serde(flatten)]
    scope: ScopeInput,
}

async fn bulk_register(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    session: Option<Extension<BrowserApiSession>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    input: Result<Json<BulkInput>, JsonRejection>,
) -> Result<Json<Value>, CatalogApiError> {
    csrf(&service, session.is_some(), &uri, &headers)?;
    let Json(input) = input.map_err(json_error)?;
    register_batch(&service, &principal, input).await.map(Json)
}

async fn register_batch(
    service: &GatewayService,
    principal: &Principal,
    input: BulkInput,
) -> Result<Value, CatalogApiError> {
    authorize(service, principal, None).await?;
    let registry = enabled(service)?;
    let scope = resolve_scope(service, registry, principal, &input.scope).await?;
    let entries = registry.entries().await;
    let overrides = RegisterInput::default();
    let mut successful = Vec::new();
    let mut failed = Vec::new();
    for id in &input.server_ids {
        let error = match register_entry(service, principal, &entries, id, &scope, &overrides).await
        {
            Ok(result) => result.error,
            Err(_) => Some("Registration failed"),
        };
        match error {
            Some(error) => {
                failed.push(json!({"server_id":id,"error":error}));
                if !input.skip_errors.unwrap_or(true) {
                    break;
                }
            }
            None => successful.push(id),
        }
    }
    Ok(json!({
        "successful":successful,"failed":failed,"total_attempted":input.server_ids.len(),
        "total_successful":successful.len()
    }))
}

impl GatewayService {
    pub(crate) async fn register_registry_form(
        &self,
        principal: &Principal,
        id: &str,
        values: Value,
    ) -> Result<Value, CatalogApiError> {
        let input =
            serde_json::from_value(values).map_err(|_| invalid("Invalid registration fields"))?;
        let result = register_one(self, principal, id, validate_input(input)?).await?;
        serde_json::to_value(result).map_err(|_| CatalogApiError::unavailable())
    }

    pub(crate) async fn register_registry_batch_form(
        &self,
        principal: &Principal,
        values: Value,
    ) -> Result<Value, CatalogApiError> {
        let input: BulkInput =
            serde_json::from_value(values).map_err(|_| invalid("Invalid registration fields"))?;
        if input.server_ids.is_empty() {
            return Err(invalid("Select at least one server to register"));
        }
        register_batch(self, principal, input).await
    }
}

async fn register_one(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
    input: RegisterInput,
) -> Result<Registration, CatalogApiError> {
    authorize(service, principal, None).await?;
    let registry = enabled(service)?;
    let scope = resolve_scope(service, registry, principal, &input.scope).await?;
    let entries = registry.entries().await;
    register_entry(service, principal, &entries, id, &scope, &input).await
}

async fn register_entry(
    service: &GatewayService,
    principal: &Principal,
    entries: &[Entry],
    id: &str,
    scope: &RegistrationScope<'_>,
    input: &RegisterInput,
) -> Result<Registration, CatalogApiError> {
    let Some(entry) = entries.iter().find(|entry| entry.id == id) else {
        return Ok(Registration {
            public_error: Some((StatusCode::NOT_FOUND, "Catalog server not found")),
            ..Registration::failure(MISSING, "Invalid catalog server ID")
        });
    };
    let urls = [entry.url.as_str()];
    let duplicate = || {
        service
            .database
            .registry_gateways(&urls, &principal.email, &principal.visibility)
    };
    if let Some(existing) = duplicate().await?.into_iter().next() {
        return Ok(Registration::duplicate(existing.id));
    }
    if url::Url::parse(&entry.url).is_ok_and(|url| {
        url.host()
            .is_some_and(|host| matches!(host, url::Host::Ipv6(_)))
    }) {
        return Ok(Registration::failure(
            "Registration failed",
            "IPv6 URLs are not currently supported for security reasons. Please use IPv4 or domain names.",
        ));
    }
    let (auth, oauth_required) = match default_auth(service, entry, input) {
        Ok(auth) => auth,
        Err(()) => {
            return Ok(Registration::failure(
                "Registration failed: invalid configuration",
                "Invalid registration parameters",
            ));
        }
    };
    let request = RegisterGateway {
        name: input
            .name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(&entry.name)
            .to_owned(),
        url: entry.url.clone(),
        description: Some(entry.description.clone()),
        transport: Some(
            entry
                .transport
                .clone()
                .unwrap_or_else(|| transport_from_url(&entry.url).into()),
        ),
        tags: Some(
            entry
                .tags
                .iter()
                .filter_map(Tag::id)
                .map(str::to_owned)
                .collect(),
        ),
        auth,
        ..RegisterGateway::default()
    };
    let result = register_gateway(
        service,
        principal,
        request,
        GatewayRegistrationSource::Registry {
            visibility: scope.visibility.name(),
            team: scope.team,
        },
    )
    .await;
    let payload = match result {
        Ok(result) => result.payload,
        Err(error)
            if error.status == StatusCode::CONFLICT
                && error.message == "Gateway already exists" =>
        {
            let existing = duplicate().await?.into_iter().next().map(|row| row.id);
            return Ok(Registration::duplicate(existing.unwrap_or_default()));
        }
        Err(error) if error.status == StatusCode::SERVICE_UNAVAILABLE => {
            return Err(CatalogApiError::unavailable());
        }
        Err(error) => {
            let message = match error.status {
                StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => {
                    "Registration failed: invalid configuration"
                }
                _ => error.message,
            };
            return Ok(Registration::failure(message, message));
        }
    };
    let server_id = payload["id"]
        .as_str()
        .ok_or_else(CatalogApiError::unavailable)?;
    let name = payload["name"]
        .as_str()
        .ok_or_else(CatalogApiError::unavailable)?;
    let tools = payload["toolCount"].as_u64().unwrap_or_default();
    let mut message = format!("Successfully registered {name}");
    if oauth_required {
        message.push_str(" - OAuth configuration required before activation");
    } else if tools > 0 {
        use std::fmt::Write as _;
        let _ = write!(message, " with {tools} tools discovered");
    }
    Ok(Registration {
        success: true,
        server_id: server_id.to_owned(),
        message,
        error: None,
        oauth_required,
        public_error: None,
    })
}

fn transport_from_url(endpoint: &str) -> &'static str {
    let endpoint = endpoint.to_ascii_lowercase();
    if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
        "WEBSOCKET"
    } else if endpoint.ends_with("/sse") || endpoint.contains("/sse/") {
        "SSE"
    } else if endpoint.contains("/mcp") || endpoint.ends_with('/') {
        "STREAMABLEHTTP"
    } else {
        "SSE"
    }
}

fn default_auth(
    service: &GatewayService,
    entry: &Entry,
    input: &RegisterInput,
) -> Result<(AuthInput, bool), ()> {
    let oauth = matches!(
        entry.auth_type.as_str(),
        "OAuth2.1" | "OAuth" | "OAuth2.1 & API Key"
    );
    let (auth, oauth_required) = if let Some(key) =
        input.api_key.as_deref().filter(|key| !key.is_empty())
        && entry.auth_type != "Open"
    {
        if oauth || matches!(entry.auth_type.as_str(), "API" | "API Key") {
            (json!({"auth_type":"bearer","auth_token":key}), false)
        } else {
            (
                json!({"auth_type":"authheaders","auth_headers":[{"key":"X-API-Key","value":key}]}),
                false,
            )
        }
    } else if oauth {
        let config = oauth_config(
            service,
            entry.oauth.as_ref(),
            input.oauth_credentials.as_ref(),
        )?;
        (json!({"auth_type":"oauth","oauth_config":config}), true)
    } else {
        return Ok((AuthInput::default(), false));
    };
    Ok((
        serde_json::from_value(auth).map_err(|_| ())?,
        oauth_required,
    ))
}

fn oauth_config(
    service: &GatewayService,
    metadata: Option<&OAuthMetadata>,
    overrides: Option<&Map<String, Value>>,
) -> Result<Value, ()> {
    let mut config = Map::new();
    config.insert("grant_type".into(), "authorization_code".into());
    if let Some(metadata) = metadata {
        for (key, value) in [
            ("issuer", metadata.issuer.as_deref()),
            ("authorization_url", metadata.authorization_url.as_deref()),
            ("token_url", metadata.token_url.as_deref()),
            ("resource", metadata.resource.as_deref()),
        ] {
            if let Some(value) = value {
                config.insert(key.into(), value.into());
            }
        }
        if !metadata.scopes.is_empty() {
            config.insert("scopes".into(), json!(metadata.scopes));
        }
    }
    let submitted = |key: &str| {
        overrides
            .and_then(|values| values.get(key))
            .filter(|value| match value {
                Value::Null => false,
                Value::String(value) => !value.is_empty(),
                Value::Array(values) => !values.is_empty(),
                _ => true,
            })
    };
    if submitted("issuer").is_some_and(|issuer| config.get("issuer") != Some(issuer)) {
        config.remove("authorization_url");
        config.remove("token_url");
    }
    if metadata.is_some_and(|metadata| !metadata.supports_dcr)
        && submitted("client_id").is_none()
        && submitted("issuer").is_none()
    {
        config.remove("issuer");
    }
    for key in [
        "issuer",
        "client_id",
        "client_secret",
        "authorization_url",
        "token_url",
        "redirect_uri",
        "audience",
    ] {
        if let Some(value) = submitted(key) {
            let text = value.as_str().ok_or(())?;
            config.insert(key.into(), text.into());
        }
    }
    if let Some(scopes) = submitted("scopes") {
        let scopes = match scopes {
            Value::String(text) => vec![text.as_str()],
            Value::Array(values) => values
                .iter()
                .map(|value| value.as_str().ok_or(()))
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(()),
        };
        let scopes: Vec<_> = scopes
            .into_iter()
            .flat_map(|text| text.split(|ch: char| ch == ',' || ch.is_whitespace()))
            .filter(|scope| !scope.is_empty())
            .collect();
        if !scopes.is_empty() {
            config.insert("scopes".into(), json!(scopes));
        }
    }
    if let Some(resource) = submitted("resource") {
        match resource {
            Value::String(_) => {}
            Value::Array(resources)
                if resources
                    .iter()
                    .all(|value| value.as_str().is_some_and(|text| !text.is_empty())) => {}
            _ => return Err(()),
        }
        config.insert("resource".into(), resource.clone());
    }
    for field in ["issuer", "authorization_url", "token_url"] {
        if let Some(endpoint) = config.get(field).and_then(Value::as_str) {
            crate::oauth_client::validate_endpoint(&service.upstream, endpoint, None)
                .map_err(|_| ())?;
        }
    }
    Ok(Value::Object(config))
}

fn csrf(
    service: &GatewayService,
    browser: bool,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
) -> Result<(), CatalogApiError> {
    if browser
        && !browser_proof_valid(
            &service.gateway_oauth.browser_origin,
            &service.gateway_oauth.csrf_origins,
            uri,
            headers,
        )
    {
        return Err(forbidden("CSRF validation failed"));
    }
    Ok(())
}

fn forbidden(message: impl Into<String>) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::FORBIDDEN, message)
}

fn invalid(message: &'static str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn json_error(error: JsonRejection) -> CatalogApiError {
    CatalogApiError::detail(error.status(), "Invalid registration body")
}
