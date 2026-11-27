// SPDX-License-Identifier: Apache-2.0

mod gateway;

use serde_json::Map;

use super::*;

pub(in crate::local_auth::browser) async fn save(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(kind): Extension<ManagedCatalog>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Option<Path<String>>,
    request: Request,
) -> Response {
    let id = path.map(|Path(id)| id);
    let gateway = matches!(kind, ManagedCatalog::Gateways);
    let json_allowed = gateway && (id.is_none() || request.method() == Method::PUT);
    let AuthorizedForm {
        principal,
        parts,
        form,
        json,
    } = match authorized_form(
        &accounts,
        &format!("{}.{}", kind.name(), operation(id.as_deref())),
        request,
        peer.ip(),
        json_allowed,
    )
    .await
    {
        Ok(form) => form,
        Err(response) => return *response,
    };
    let response = async {
        let browser = form.get("_dashboard") == "true";
        let input = json.map_or_else(|| fields(kind, &form, id.is_some(), browser), Ok);
        let result = match input {
            Ok(fields) if gateway => {
                let legacy_edit = !browser && id.is_some() && parts.method == Method::POST;
                service
                    .save_admin_gateway(
                        &principal,
                        id.as_deref(),
                        fields,
                        &parts.headers,
                        peer,
                        legacy_edit,
                    )
                    .await
            }
            Ok(fields) => service
                .save_admin_catalog(
                    kind,
                    &principal,
                    id.as_deref(),
                    fields,
                    &parts.headers,
                    peer,
                )
                .await
                .map(|()| {
                    Json(json!({"message":success(kind, id.is_some()),"success":true}))
                        .into_response()
                }),
            Err(error) => Err(error),
        };
        match (browser, result) {
            (false, Ok(response)) => response,
            (false, Err(error)) => error.form_response(),
            (true, Ok(response)) => {
                let mut location = back(kind, &parts.uri, &principal);
                if response.status() == StatusCode::ACCEPTED {
                    location.push_str("&message=gateway_write_pending");
                }
                settings_for(&accounts).redirect(&location)
            }
            (true, Err(error)) => {
                let original = match id.as_deref() {
                    Some(id) => match service.editable_admin_catalog(kind, &principal, id).await {
                        Ok(value) => value,
                        Err(error) => return error.into_response(),
                    },
                    None => Value::Null,
                };
                let proof = cookie(&parts.headers, CSRF_COOKIE).unwrap_or_default();
                let page = Page::new(kind, id.as_deref(), &parts.uri, &principal, &original);
                let mut editor = page.with_form(&form);
                editor.error = Some(error.form_message());
                let mut result = display(settings_for(&accounts), proof, editor)
                    .unwrap_or_else(IntoResponse::into_response);
                if result.status().is_success() {
                    *result.status_mut() = error.into_response().status();
                }
                result
            }
        }
    };
    with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

pub(in crate::local_auth::browser) async fn page(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(kind): Extension<ManagedCatalog>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Option<Path<String>>,
    request: Request,
) -> Result<Response, AccountError> {
    let settings = settings_for(&accounts);
    let Session { principal, token } =
        match access(&accounts, request.headers(), request.uri(), peer.ip()).await {
            Ok(session) => session,
            Err(denial) => return Ok(denial.response(settings, request.headers())),
        };
    if password_change_pending(&accounts, &principal).await? {
        return Ok(settings.redirect(CHANGE));
    }
    let id = path.map(|Path(id)| id);
    let team = sessions::request_team(request.uri(), &principal);
    if !allows(
        &accounts,
        &principal,
        kind,
        operation(id.as_deref()),
        team.as_deref(),
    )
    .await?
    {
        return Err(AccountError::detail(
            StatusCode::FORBIDDEN,
            "Permission denied",
        ));
    }
    let proof = sessions::proof(&accounts, request.headers(), &principal, token)?;
    let (parts, _) = request.into_parts();
    let response = async {
        let record = match id.as_deref() {
            Some(id) => match service.editable_admin_catalog(kind, &principal, id).await {
                Ok(record) => record,
                Err(error) => return error.into_response(),
            },
            None => Value::Null,
        };
        display(
            settings,
            &proof,
            Page::new(kind, id.as_deref(), &parts.uri, &principal, &record),
        )
        .and_then(|mut response| {
            sessions::set_proof(
                &mut response,
                settings,
                accounts.settings.token_seconds,
                &proof,
            )?;
            Ok(response)
        })
        .unwrap_or_else(IntoResponse::into_response)
    };
    Ok(with_usage(&accounts, &principal, &parts, peer.ip(), response).await)
}

fn operation(id: Option<&str>) -> &'static str {
    if id.is_some() { "update" } else { "create" }
}

fn success(kind: ManagedCatalog, edit: bool) -> &'static str {
    match (kind, edit) {
        (ManagedCatalog::Tools, false) => "Tool registered successfully!",
        (ManagedCatalog::Tools, true) => "Edit tool successfully",
        (ManagedCatalog::Resources, false) => "Add resource registered successfully!",
        (ManagedCatalog::Resources, true) => "Resource updated successfully!",
        (ManagedCatalog::Prompts, false) => "Prompt registered successfully!",
        (ManagedCatalog::Prompts, true) => "Prompt updated successfully!",
        (ManagedCatalog::Servers, false) => "Server created successfully!",
        (ManagedCatalog::Servers, true) => "Server updated successfully!",
        (ManagedCatalog::Gateways, _) => unreachable!("catalog editor route"),
    }
}

fn fields(
    kind: ManagedCatalog,
    form: &Form,
    edit: bool,
    browser: bool,
) -> Result<Map<String, Value>, CatalogApiError> {
    let mut fields = Map::new();
    copy(
        form,
        &mut fields,
        &[
            ("name", "name"),
            ("description", "description"),
            ("customName", "customName"),
        ],
    );
    let visibility =
        form.value("visibility")
            .unwrap_or(if matches!(kind, ManagedCatalog::Resources) && !edit {
                "public"
            } else {
                "private"
            });
    if !matches!(kind, ManagedCatalog::Gateways) || !edit || form.value("visibility").is_some() {
        fields.insert("visibility".to_owned(), visibility.into());
    }
    if let Some(team) = nonempty(form, "team_id") {
        fields.insert("team_id".to_owned(), team.trim().into());
    }
    fields.insert(
        "tags".to_owned(),
        json!(comma_separated(form.get("tags")).collect::<Vec<_>>()),
    );
    match kind {
        ManagedCatalog::Tools => {
            copy(
                form,
                &mut fields,
                &[
                    ("url", "url"),
                    ("integrationType", "integrationType"),
                    ("requestType", "requestType"),
                    ("jsonpath_filter", "jsonpathFilter"),
                    ("jsonpathFilter", "jsonpathFilter"),
                    ("tool_validation_policy", "tool_validation_policy"),
                ],
            );
            if let Some(name) = nonempty(form, "displayName") {
                fields.insert("displayName".to_owned(), name.into());
            }
            if !edit && form.value("requestType").is_none() {
                let method = if form.get("integrationType") == "MCP" {
                    "SSE"
                } else {
                    "GET"
                };
                fields.insert("requestType".to_owned(), method.into());
            }
            for name in [
                "headers",
                "input_schema",
                "output_schema",
                "annotations",
                "query_mapping",
                "header_mapping",
                "allowlist",
                "plugin_chain_pre",
                "plugin_chain_post",
            ] {
                json_field(form, &mut fields, name)?;
            }
            if let Some(timeout) = nonempty(form, "timeout_ms") {
                let timeout: i32 = timeout
                    .trim()
                    .parse()
                    .map_err(|_| invalid("Invalid timeout_ms"))?;
                fields.insert("timeout_ms".to_owned(), timeout.into());
            }
            if let Some(expose) = nonempty(form, "expose_passthrough") {
                let enabled = match expose.trim().to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" => true,
                    "false" | "0" | "no" | "off" => false,
                    _ => return Err(invalid("Invalid expose_passthrough")),
                };
                fields.insert("expose_passthrough".to_owned(), enabled.into());
            }
            if form.get("auth_type").eq_ignore_ascii_case("oauth") {
                return Err(invalid(
                    "auth_type 'oauth' is not supported on tools; configure OAuth on the gateway instead",
                ));
            }
            if nonempty(form, "auth_type").is_some() {
                copy(
                    form,
                    &mut fields,
                    &[
                        ("auth_type", "auth_type"),
                        ("auth_username", "auth_username"),
                        ("auth_password", "auth_password"),
                        ("auth_token", "auth_token"),
                        ("auth_header_key", "auth_header_key"),
                        ("auth_header_value", "auth_header_value"),
                    ],
                );
                json_field(form, &mut fields, "auth_headers")?;
                if let Some(headers) = fields.get_mut("auth_headers").and_then(Value::as_array_mut)
                {
                    headers.retain(|header| {
                        header["key"]
                            .as_str()
                            .is_some_and(|key| !key.trim().is_empty())
                    });
                }
            }
        }
        ManagedCatalog::Resources => {
            copy(
                form,
                &mut fields,
                &[("uri", "uri"), ("mimeType", "mimeType")],
            );
            if let Some(template) = nonempty(form, "uri_template").or_else(|| {
                let uri = form.get("uri");
                (uri.contains('{') && uri.contains('}')).then_some(uri)
            }) {
                fields.insert("uri_template".to_owned(), template.into());
            }
            if let Some(content) = form.value("content")
                && (!browser || !edit || !content.is_empty())
            {
                fields.insert("content".to_owned(), content.into());
            }
        }
        ManagedCatalog::Prompts => {
            let template = nonempty(form, "template")
                .ok_or_else(|| invalid("Prompt template is required."))?;
            fields.insert("template".to_owned(), template.into());
            if let Some(name) = nonempty(form, "displayName")
                .or_else(|| nonempty(form, "display_name"))
                .or_else(|| nonempty(form, "name"))
            {
                fields.insert("displayName".to_owned(), name.into());
            }
            if edit && let Some(name) = fields.remove("name") {
                fields.entry("customName").or_insert(name);
            }
            json_field(form, &mut fields, "arguments")?;
        }
        ManagedCatalog::Servers => {
            if let Some(id) = nonempty(form, "id") {
                fields.insert("id".to_owned(), id.into());
            }
            copy(form, &mut fields, &[("icon", "icon")]);
            if let Some(instructions) = form.value("instructions") {
                let instructions = (!instructions.trim().is_empty()).then_some(instructions);
                fields.insert("instructions".to_owned(), json!(instructions));
            }
            for (field, all, ids) in [
                ("associatedTools", "selectAllTools", "allToolIds"),
                (
                    "associatedResources",
                    "selectAllResources",
                    "allResourceIds",
                ),
                ("associatedPrompts", "selectAllPrompts", "allPromptIds"),
            ] {
                if form.value(field).is_some() || form.value(all).is_some() {
                    let selected = if form.get(all).eq_ignore_ascii_case("true") {
                        comma_separated(form.get(ids)).collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };
                    let ids = form
                        .values(field)
                        .flat_map(comma_separated)
                        .chain(selected)
                        .collect::<Vec<_>>();
                    fields.insert(field.to_owned(), json!(ids));
                }
            }
            if form.value("oauth_enabled").is_some()
                || [
                    "oauth_authorization_server",
                    "oauth_scopes",
                    "oauth_token_endpoint",
                    "oauth_audience",
                ]
                .into_iter()
                .any(|name| form.value(name).is_some())
            {
                let issuer = nonempty(form, "oauth_authorization_server");
                let enable = form.get("oauth_enabled") == "on" && issuer.is_some();
                fields.insert("oauth_enabled".to_owned(), enable.into());
                let config = enable.then(|| {
                    let mut config = Map::new();
                    config.insert("authorization_servers".to_owned(), json!([issuer]));
                    if let Some(scopes) = nonempty(form, "oauth_scopes") {
                        config.insert(
                            "scopes_supported".to_owned(),
                            json!(scopes.split_whitespace().collect::<Vec<_>>()),
                        );
                    }
                    for (input, output) in [
                        ("oauth_token_endpoint", "token_endpoint"),
                        ("oauth_audience", "audience"),
                    ] {
                        if let Some(value) = nonempty(form, input) {
                            config.insert(output.to_owned(), value.trim().into());
                        }
                    }
                    config
                });
                fields.insert("oauth_config".to_owned(), json!(config));
            }
        }
        ManagedCatalog::Gateways => gateway::fields(form, &mut fields)?,
    }
    Ok(fields)
}

fn copy(form: &Form, fields: &mut Map<String, Value>, names: &[(&str, &str)]) {
    for (input, output) in names {
        if let Some(value) = form.value(input) {
            fields.insert((*output).to_owned(), value.into());
        }
    }
}

fn nonempty<'a>(form: &'a Form, name: &str) -> Option<&'a str> {
    form.value(name).filter(|value| !value.trim().is_empty())
}

fn comma_separated(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn json_field(
    form: &Form,
    fields: &mut Map<String, Value>,
    name: &str,
) -> Result<(), CatalogApiError> {
    if let Some(raw) = nonempty(form, name) {
        let value =
            serde_json::from_str(raw).map_err(|_| invalid(format!("Invalid JSON in {name}")))?;
        fields.insert(name.to_owned(), value);
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn back(kind: ManagedCatalog, uri: &Uri, principal: &Principal) -> String {
    let (include_inactive, team) = catalog_context(uri, principal);
    catalogue_link(
        "/admin/",
        Some(kind.name()),
        None,
        include_inactive,
        team.as_deref(),
    )
}

fn catalog_context(uri: &Uri, principal: &Principal) -> (bool, Option<String>) {
    let include_inactive = forms::query(uri)
        .get("include_inactive")
        .is_some_and(|value| value == "true");
    (include_inactive, sessions::request_team(uri, principal))
}

#[derive(Serialize)]
struct Page<'a> {
    kind: &'static str,
    heading: String,
    editing: bool,
    action: String,
    back: String,
    values: Map<String, Value>,
    error: Option<&'a str>,
}

impl Page<'_> {
    fn new(
        kind: ManagedCatalog,
        id: Option<&str>,
        uri: &Uri,
        principal: &Principal,
        record: &Value,
    ) -> Self {
        let (include_inactive, team) = catalog_context(uri, principal);
        let path = match id {
            Some(id) => format!("/admin/{}/{id}/edit", kind.name()),
            None => format!("/admin/{}", kind.name()),
        };
        let singular = match kind {
            ManagedCatalog::Tools => "tool",
            ManagedCatalog::Servers => "virtual server",
            ManagedCatalog::Resources => "resource",
            ManagedCatalog::Prompts => "prompt",
            ManagedCatalog::Gateways => "MCP server",
        };
        let heading = format!("{} {singular}", if id.is_some() { "Edit" } else { "Add" });
        let mut values = Map::new();
        for name in [
            "name",
            "description",
            "visibility",
            "teamId",
            "url",
            "displayName",
            "integrationType",
            "requestType",
            "uri",
            "uriTemplate",
            "mimeType",
            "template",
            "icon",
            "instructions",
            "transport",
            "gatewayMode",
        ] {
            values.insert(name.to_owned(), record[name].as_str().unwrap_or("").into());
        }
        if let Some(team) = team.as_deref().filter(|_| id.is_none()) {
            values.insert("teamId".to_owned(), team.into());
        }
        if let Some(name) = record["customName"].as_str() {
            values.insert("name".to_owned(), name.into());
        }
        for name in ["inputSchema", "outputSchema", "arguments"] {
            let text = if record[name].is_null() {
                String::new()
            } else {
                serde_json::to_string_pretty(&record[name]).unwrap_or_default()
            };
            values.insert(name.to_owned(), text.into());
        }
        if let Some(headers) = record["passthroughHeaders"].as_array() {
            let headers = headers
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            values.insert("passthroughHeaders".to_owned(), headers.into());
        }
        let tags = record["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|tag| tag.as_str().or_else(|| tag["label"].as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        values.insert("tags".to_owned(), tags.into());
        Self {
            kind: kind.name(),
            heading,
            editing: id.is_some(),
            action: catalogue_link(&path, None, None, include_inactive, team.as_deref()),
            back: back(kind, uri, principal),
            values,
            error: None,
        }
    }

    fn with_form(mut self, form: &Form) -> Self {
        copy(
            form,
            &mut self.values,
            &[
                ("name", "name"),
                ("description", "description"),
                ("visibility", "visibility"),
                ("tags", "tags"),
                ("team_id", "teamId"),
                ("url", "url"),
                ("displayName", "displayName"),
                ("integrationType", "integrationType"),
                ("requestType", "requestType"),
                ("input_schema", "inputSchema"),
                ("output_schema", "outputSchema"),
                ("uri", "uri"),
                ("uri_template", "uriTemplate"),
                ("mimeType", "mimeType"),
                ("content", "content"),
                ("template", "template"),
                ("arguments", "arguments"),
                ("icon", "icon"),
                ("instructions", "instructions"),
                ("transport", "transport"),
                ("gateway_mode", "gatewayMode"),
                ("passthrough_headers", "passthroughHeaders"),
                ("auth_type", "authType"),
            ],
        );
        self
    }
}

fn display(
    settings: &BrowserSettings,
    proof: &str,
    editor: Page<'_>,
) -> Result<Response, AccountError> {
    render(context! {
        title => editor.heading,
        page => "catalog-editor",
        root => settings.root,
        proof => proof,
        editor => editor,
    })
}
