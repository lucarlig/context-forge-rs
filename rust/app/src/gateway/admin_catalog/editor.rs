// SPDX-License-Identifier: Apache-2.0

use serde::de::DeserializeOwned;

use super::*;
use crate::gateway::catalog_api::WriteOrigin;

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
        let requested_team = fields.get("team_id").and_then(Value::as_str);
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
        } else if id.is_none()
            && let Some(team) = self.database.owned_personal_team(&principal.email).await?
            && access::catalog_scope(Some(principal)).visible("team", Some(&team), None)
        {
            fields.insert("team_id".to_owned(), team.into());
        }

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
                return Err(CatalogApiError::detail(
                    StatusCode::NOT_FOUND,
                    "Catalog editor unavailable",
                ));
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
