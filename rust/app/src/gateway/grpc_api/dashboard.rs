// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde_json::Map;

use super::*;

#[derive(Serialize)]
pub(crate) struct GrpcBrowserRow {
    service: Value,
    editable: bool,
}

#[derive(Serialize)]
pub(crate) struct GrpcBrowserPage {
    pub(crate) rows: Vec<GrpcBrowserRow>,
    pub(crate) pagination: PaginationMeta,
    pub(crate) team: Option<String>,
    pub(crate) include_inactive: bool,
}

pub(crate) enum GrpcBrowserAction {
    State(bool),
    Reflect,
    Delete,
}

impl GatewayService {
    pub(crate) fn grpc_dashboard_enabled(&self) -> bool {
        self.grpc.admin_enabled && self.grpc.enabled
    }

    pub(crate) async fn grpc_dashboard_page(
        &self,
        principal: &Principal,
        query: &GrpcPageQuery,
    ) -> Result<GrpcBrowserPage, CatalogApiError> {
        let page = registry_page(self, principal, query).await?;
        let mut rows = Vec::with_capacity(page.records.len());
        let mut permissions = HashMap::new();
        for record in page.records {
            let target = record.config.team_id.as_deref();
            let editable = if let Some(allow) = permissions.get(&record.config.team_id) {
                *allow
            } else {
                let allow = match require_target_permission(self, principal, target).await {
                    Ok(()) => true,
                    Err(error) if error.0 == StatusCode::FORBIDDEN => false,
                    Err(error) => return Err(error),
                };
                permissions.insert(record.config.team_id.clone(), allow);
                allow
            };
            rows.push(GrpcBrowserRow {
                service: browser_summary(&record),
                editable,
            });
        }
        Ok(GrpcBrowserPage {
            rows,
            pagination: page.pagination,
            team: page.team,
            include_inactive: page.include_inactive,
        })
    }

    pub(crate) async fn grpc_dashboard_editor(
        &self,
        principal: &Principal,
        id: Option<&str>,
    ) -> Result<Value, CatalogApiError> {
        if let Some(id) = id {
            let record = editable_record(self, principal, id).await?;
            let mut fields =
                serde_json::to_value(&record.config).expect("service configuration serializes");
            fields["grpc_metadata"] = Value::Null;
            Ok(fields)
        } else {
            require_access(self, principal).await?;
            Ok(Value::Null)
        }
    }

    pub(crate) async fn grpc_dashboard_methods(
        &self,
        principal: &Principal,
        id: &str,
    ) -> Result<(Value, Vec<Value>), CatalogApiError> {
        let record = visible_record(self, principal, id).await?;
        Ok((browser_summary(&record), service_methods(&record)))
    }

    pub(crate) async fn save_grpc_dashboard_service(
        &self,
        principal: &Principal,
        id: Option<&str>,
        mut fields: Map<String, Value>,
        headers: &HeaderMap,
        peer: SocketAddr,
    ) -> Result<(), CatalogApiError> {
        require_access(self, principal).await?;
        let ip = Some(peer.ip().to_string());
        let agent = user_agent(headers);
        if let Some(id) = id {
            update_service(self, principal, id, fields, ip, agent).await?;
        } else {
            if let Some(team) = fields.get("team_id").and_then(Value::as_str) {
                let team = resolve_list_team(self, principal, Some(team)).await?;
                fields.insert("team_id".to_owned(), json!(team));
            }
            let config = serde_json::from_value(Value::Object(fields)).map_err(|_| {
                CatalogApiError::detail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid gRPC service configuration",
                )
            })?;
            create_service(self, principal, config, ip, agent).await?;
        }
        Ok(())
    }

    pub(crate) async fn mutate_grpc_dashboard_service(
        &self,
        principal: &Principal,
        id: &str,
        action: GrpcBrowserAction,
    ) -> Result<(), CatalogApiError> {
        match action {
            GrpcBrowserAction::State(enabled) => change_service_state(
                self,
                principal,
                id,
                Some(if enabled { "true" } else { "false" }),
            )
            .await
            .map(|_| ()),
            GrpcBrowserAction::Reflect => reflect_service(self, principal, id).await.map(|_| ()),
            GrpcBrowserAction::Delete => delete_service(self, principal, id).await,
        }
    }
}

fn browser_summary(record: &ServiceRecord) -> Value {
    json!({
        "id":record.id, "name":record.config.name, "target":record.config.target,
        "visibility":record.config.visibility, "enabled":record.enabled, "reachable":record.reachable,
        "method_count":record.method_count, "reflection_enabled":record.config.reflection_enabled,
        "team":record.team, "last_reflection":record.last_reflection,
    })
}
