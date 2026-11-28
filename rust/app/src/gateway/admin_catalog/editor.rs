// SPDX-License-Identifier: Apache-2.0

use serde::de::DeserializeOwned;

use super::*;
use crate::gateway::catalog_api::WriteOrigin;

const AUTHORIZATION_CODE_NOTICE: &str = concat!(
    "Gateway registered successfully! 🎉\n\n",
    "⚠️  IMPORTANT: This gateway uses OAuth Authorization Code flow.\n",
    "You must complete the OAuth authorization before tools will work:\n",
    "1. Go to the Gateways list\n",
    "2. Click the '🔐 Authorize' button for this gateway\n",
    "3. Complete the OAuth consent flow\n",
    "4. Return to the admin panel\n\n",
    "Tools will not work until OAuth authorization is completed.",
);

impl GatewayService {
    pub(crate) async fn save_admin_catalog(
        &self,
        kind: ManagedCatalog,
        principal: &Principal,
        id: Option<&str>,
        mut fields: serde_json::Map<String, Value>,
        headers: &HeaderMap,
        peer: SocketAddr,
    ) -> Result<(), CatalogApiError> {
        self.prepare_admin_catalog_team(principal, id.is_none(), &mut fields)
            .await?;
        let fields = Value::Object(fields);
        let origin = WriteOrigin::new(Some(Extension(ConnectInfo(peer))), headers, Some("ui"));
        match (kind, id) {
            (ManagedCatalog::Tools, None) => {
                tool_api::create_record(self, principal, decode(json!({"tool":fields}))?, origin)
                    .await
                    .map(|_| ())
            }
            (ManagedCatalog::Tools, Some(id)) => {
                tool_api::update_record(self, principal, id, decode(fields)?, origin)
                    .await
                    .map(|_| ())
            }
            (ManagedCatalog::Servers, None) => server_api::create_record(
                self,
                principal,
                decode(json!({"server":fields}))?,
                origin,
            )
            .await
            .map(|_| ()),
            (ManagedCatalog::Servers, Some(id)) => {
                server_api::update_record(self, principal, id, decode(fields)?, origin)
                    .await
                    .map(|_| ())
            }
            (ManagedCatalog::Resources, None) => resource_api::create_record(
                self,
                principal,
                decode(json!({"resource":fields}))?,
                origin,
            )
            .await
            .map(|_| ()),
            (ManagedCatalog::Resources, Some(id)) => {
                resource_api::update_record(self, principal, id, decode(fields)?, origin)
                    .await
                    .map(|_| ())
            }
            (ManagedCatalog::Prompts, None) => prompt_api::create_record(
                self,
                principal,
                decode(json!({"prompt":fields}))?,
                origin,
            )
            .await
            .map(|_| ()),
            (ManagedCatalog::Prompts, Some(id)) => {
                prompt_api::update_record(self, principal, id, decode(fields)?, origin)
                    .await
                    .map(|_| ())
            }
            (ManagedCatalog::Gateways, _) => Err(CatalogApiError::detail(
                StatusCode::NOT_FOUND,
                "Catalog editor unavailable",
            )),
        }
    }

    pub(in crate::gateway) async fn prepare_admin_catalog_team(
        &self,
        principal: &Principal,
        creating: bool,
        fields: &mut serde_json::Map<String, Value>,
    ) -> Result<(), CatalogApiError> {
        let requested_team = fields
            .get("team_id")
            .or_else(|| fields.get("teamId"))
            .and_then(Value::as_str);
        if let Some(team) = requested_team {
            if !self.grpc.allow_public_visibility
                && fields.get("visibility") == Some(&json!("public"))
            {
                return Err(invalid(
                    "Public visibility is disabled by platform configuration (ALLOW_PUBLIC_VISIBILITY=false).",
                ));
            }
            if !self
                .database
                .memberships(&principal.email)
                .await?
                .iter()
                .any(|id| id == team)
            {
                return Err(CatalogApiError::detail(
                    StatusCode::FORBIDDEN,
                    "Access denied",
                ));
            }
        } else if creating
            && let Some(team) = self.database.owned_personal_team(&principal.email).await?
            && access::catalog_scope(Some(principal)).visible("team", Some(&team), None)
        {
            fields.insert("team_id".to_owned(), team.into());
        }

        Ok(())
    }

    pub(crate) async fn save_admin_gateway(
        &self,
        principal: &Principal,
        id: Option<&str>,
        mut fields: serde_json::Map<String, Value>,
        headers: &HeaderMap,
        peer: SocketAddr,
        legacy_edit: bool,
    ) -> Result<Response, CatalogApiError> {
        if let Some(tags) = fields.get_mut("tags")
            && let Some(labels) = tags.as_str()
        {
            *tags = json!(
                labels
                    .split(',')
                    .map(str::trim)
                    .filter(|tag| !tag.is_empty())
                    .collect::<Vec<_>>()
            );
        }
        if id.is_none() || legacy_edit {
            fields
                .entry("visibility")
                .or_insert_with(|| "private".into());
        }
        fields.remove("owner_email");
        fields.remove("ownerEmail");
        let team = fields.remove("team_id");
        let alias = fields.remove("teamId");
        if team
            .as_ref()
            .zip(alias.as_ref())
            .is_some_and(|(a, b)| a != b)
        {
            return Err(invalid("Conflicting gateway team IDs"));
        }
        match team.or(alias) {
            None | Some(Value::Null) => {}
            Some(Value::String(team)) if team.trim().is_empty() => {}
            Some(Value::String(team)) => {
                fields.insert("team_id".to_owned(), team.trim().into());
            }
            Some(_) => return Err(invalid("Invalid gateway team ID")),
        }
        let oauth = fields
            .get("oauth_config")
            .or_else(|| fields.get("oauthConfig"));
        let authorization_code = id.is_none()
            && oauth.is_some_and(|config| config["grant_type"] == "authorization_code");
        if id.is_none()
            && let Some(config) = oauth.filter(|config| config["grant_type"] == "token-exchange")
            && !matches!(
                config["token_endpoint_auth_method"].as_str(),
                Some("none" | "private_key_jwt")
            )
            && config["client_secret"]
                .as_str()
                .is_none_or(|secret| secret.is_empty() || secret == "*****")
        {
            return Err(CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                "client_secret is required for token-exchange grant type unless token_endpoint_auth_method is private_key_jwt or none",
            ));
        }
        if oauth.is_some_and(|config| {
            config.is_object() && config.as_object().is_some_and(|fields| !fields.is_empty())
        }) && fields
            .get("auth_type")
            .or_else(|| fields.get("authType"))
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            fields.remove("authType");
            fields.insert("auth_type".to_owned(), "oauth".into());
        }
        self.prepare_admin_catalog_team(principal, id.is_none(), &mut fields)
            .await?;
        let address = Some(peer.ip().to_string());
        let agent = headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok());
        let result = if let Some(id) = id {
            management::update_admin_record(
                self,
                principal,
                id,
                Value::Object(fields),
                address,
                agent,
                legacy_edit,
            )
            .await
            .map_err(CatalogApiError::from)?
        } else {
            let input: RegisterGateway = decode(Value::Object(fields))?;
            register_gateway(
                self,
                principal,
                input,
                GatewayRegistrationSource::Request {
                    address,
                    agent,
                    via: "ui",
                },
            )
            .await
            .map_err(|error| CatalogApiError::detail(error.status, error.message))?
        };
        let pending = result.retry_after.is_some();
        let message = match (id.is_some(), pending, authorization_code) {
            (false, _, true) => AUTHORIZATION_CODE_NOTICE,
            (false, false, false) => "Gateway registered successfully!",
            (false, true, false) => "Gateway registration accepted and pending initialization.",
            (true, false, _) => "Gateway updated successfully!",
            (true, true, _) => "Gateway update accepted and pending initialization.",
        };
        let mut body = json!({"message":message, "success":true, "gateway":result.payload});
        if id.is_none() {
            body["skipped_tools"] = body["gateway"]["skippedTools"]
                .as_array()
                .map_or_else(|| json!([]), |tools| json!(tools));
        }
        let status = if pending {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        };
        Ok((status, Json(body)).into_response())
    }

    pub(crate) async fn admin_gateway_detail(
        &self,
        principal: &Principal,
        id: String,
    ) -> Result<Value, CatalogApiError> {
        let record = management::lookup(self, principal, id.clone())
            .await
            .map_err(|error| CatalogApiError::from(management::UpdateError::from(error)))?;
        if record.id != id {
            return Err(CatalogApiError::detail(
                StatusCode::NOT_FOUND,
                "Gateway not found",
            ));
        }
        Ok(management::response(
            &record,
            self.credential_cipher.as_ref(),
        ))
    }

    pub(crate) async fn delete_admin_gateway(
        &self,
        principal: &Principal,
        id: String,
    ) -> Result<Response, CatalogApiError> {
        let result = management::remove(self, principal, id)
            .await
            .map_err(|error| CatalogApiError::from(management::UpdateError::from(error)))?;
        if result.retry_after.is_none() {
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        Ok((
            StatusCode::ACCEPTED,
            Json(json!({
                "message":"Gateway deletion accepted and pending cleanup.",
                "success":true,
                "gateway":result.payload,
            })),
        )
            .into_response())
    }

    pub(crate) async fn editable_admin_catalog(
        &self,
        kind: ManagedCatalog,
        principal: &Principal,
        id: &str,
    ) -> Result<Value, CatalogApiError> {
        let value = match kind {
            ManagedCatalog::Tools => {
                let row =
                    tool_api::editable(self, principal, id, "tools.update", "update this tool")
                        .await?;
                tool_api::metadata(self, &row, true, false, false)
            }
            ManagedCatalog::Servers => {
                let row = server_api::editable(
                    self,
                    principal,
                    id,
                    "servers.update",
                    "update this server",
                )
                .await?;
                server_api::with_links(self, principal, &row).await?
            }
            ManagedCatalog::Resources => {
                let row = resource_api::editable(self, principal, id, "resources.update", "update")
                    .await?;
                resource_api::metadata(&row, true)
            }
            ManagedCatalog::Prompts => {
                let row = prompt_api::editable(
                    self,
                    principal,
                    id,
                    "prompts.update",
                    "update this prompt",
                )
                .await?;
                prompt_api::metadata(&row, true)
            }
            ManagedCatalog::Gateways => {
                let row = management::manageable(
                    self,
                    principal,
                    id.to_owned(),
                    "gateways.update",
                    "Only the owner can update this gateway",
                )
                .await
                .map_err(|error| CatalogApiError::from(management::UpdateError::from(error)))?;
                management::response(&row, self.credential_cipher.as_ref())
            }
        };
        Ok(value)
    }
}

fn decode<T: DeserializeOwned>(fields: Value) -> Result<T, CatalogApiError> {
    serde_json::from_value(fields).map_err(|_| invalid("Invalid form fields"))
}

fn invalid(message: &str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}
