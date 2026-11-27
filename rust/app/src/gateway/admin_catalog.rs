// SPDX-License-Identifier: Apache-2.0

use super::{
    catalog_api::{PaginationMeta, flag},
    *,
};
use crate::{
    catalog::{CatalogEntryFilters, ManagedCatalog, ServerLinks},
    gateway_records::GatewayList,
};

#[derive(Default, Deserialize)]
pub(crate) struct AdminListQuery {
    pub(crate) page: Option<i64>,
    pub(crate) per_page: Option<i64>,
    pub(crate) include_inactive: Option<String>,
}

impl AdminListQuery {
    pub(crate) fn include_inactive(&self) -> Result<bool, CatalogApiError> {
        flag(self.include_inactive.as_deref())
    }
}

#[derive(Serialize)]
pub(crate) struct CatalogListing {
    pub(crate) data: Vec<Value>,
    pub(crate) pagination: PaginationMeta,
    links: Option<Value>,
}

pub(crate) enum CatalogMutation {
    State(bool),
    Delete { purge_metrics: bool },
}

impl GatewayService {
    pub(crate) async fn mutate_admin_catalog(
        &self,
        kind: ManagedCatalog,
        principal: &Principal,
        id: String,
        mutation: CatalogMutation,
    ) -> Result<Option<&'static str>, &'static str> {
        match mutation {
            CatalogMutation::State(enabled) => {
                let result = match kind {
                    ManagedCatalog::Tools => tool_api::change_state(self, principal, &id, enabled)
                        .await
                        .map(|_| ()),
                    ManagedCatalog::Servers => {
                        server_api::change_state(self, principal, &id, enabled)
                            .await
                            .map(|_| ())
                    }
                    ManagedCatalog::Resources => {
                        resource_api::change_state(self, principal, &id, enabled)
                            .await
                            .map(|_| ())
                    }
                    ManagedCatalog::Prompts => {
                        prompt_api::change_state(self, principal, &id, enabled)
                            .await
                            .map(|_| ())
                    }
                    ManagedCatalog::Gateways => {
                        return management::change_state(self, principal, id, enabled)
                            .await
                            .map(|_| None)
                            .map_err(|error| match error {
                                management::ManagementError::ToolNameConflict => "name_conflict",
                                other => flash_error(
                                    other.into_response().status(),
                                    "state_change_failed",
                                ),
                            });
                    }
                };
                result.map(|_| None).map_err(|error| match (kind, error.0) {
                    (ManagedCatalog::Tools | ManagedCatalog::Servers, StatusCode::CONFLICT) => {
                        "conflict"
                    }
                    (_, status) => flash_error(status, "state_change_failed"),
                })
            }
            CatalogMutation::Delete { purge_metrics } => {
                let purge = purge_metrics.then_some("true");
                let result = match kind {
                    ManagedCatalog::Tools => tool_api::remove(self, principal, &id, purge).await,
                    ManagedCatalog::Servers => {
                        server_api::remove(self, principal, &id, purge).await
                    }
                    ManagedCatalog::Resources => {
                        resource_api::remove(self, principal, &id, purge).await
                    }
                    ManagedCatalog::Prompts => {
                        prompt_api::remove(self, principal, &id, purge).await
                    }
                    ManagedCatalog::Gateways => {
                        return management::remove(self, principal, id)
                            .await
                            .map(|response| {
                                (response.status() == StatusCode::ACCEPTED)
                                    .then_some("gateway_delete_pending")
                            })
                            .map_err(|error| {
                                flash_error(error.into_response().status(), "delete_failed")
                            });
                    }
                };
                result
                    .map(|_| None)
                    .map_err(|error| flash_error(error.0, "delete_failed"))
            }
        }
    }

    pub(crate) async fn admin_catalog(
        &self,
        kind: ManagedCatalog,
        principal: &Principal,
        query: &AdminListQuery,
        team: Option<&str>,
    ) -> Result<CatalogListing, CatalogApiError> {
        let include_inactive = query.include_inactive()?;
        let page = query.page.unwrap_or(1);
        let per_page = query
            .per_page
            .unwrap_or(i64::from(self.management_page_size));
        if page < 1 || !(1..=i64::from(self.management_max_page_size)).contains(&per_page) {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid pagination",
            ));
        }
        let per_page = per_page.max(i64::from(self.grpc.min_page_size));
        let scope = access::catalog_scope(Some(principal));
        let total = self
            .database
            .managed_catalog_count(kind, scope, include_inactive, team)
            .await?;
        let pagination = PaginationMeta::new(page, per_page, total);
        let filters = CatalogEntryFilters {
            team,
            limit: per_page,
            offset: pagination.offset(self.grpc.max_page_offset),
            ..CatalogEntryFilters::associated(include_inactive)
        };
        let data = match kind {
            ManagedCatalog::Tools => {
                let tools = self.database.managed_tools(scope, filters).await?;
                let teams = tool_api::header_team_owners(self, principal, &tools).await?;
                tools
                    .iter()
                    .map(|tool| {
                        let owner = tool
                            .team_id
                            .as_deref()
                            .is_some_and(|team| teams.get(team) == Some(&true));
                        tool_api::metadata(
                            self,
                            tool,
                            true,
                            false,
                            tool_api::can_view_headers(principal, tool, owner),
                        )
                    })
                    .collect()
            }
            ManagedCatalog::Servers => {
                let servers = self.database.managed_servers(scope, filters).await?;
                let ids = servers
                    .iter()
                    .map(|server| server.id.as_str())
                    .collect::<Vec<_>>();
                let links = self.database.managed_server_links(&ids, scope).await?;
                let empty = ServerLinks::default();
                servers
                    .iter()
                    .map(|server| {
                        server_api::metadata(self, server, links.get(&server.id).unwrap_or(&empty))
                    })
                    .collect()
            }
            ManagedCatalog::Resources => self
                .database
                .managed_resources(scope, filters, None)
                .await?
                .iter()
                .map(|row| resource_api::metadata(row, true))
                .collect(),
            ManagedCatalog::Prompts => self
                .database
                .managed_prompts(scope, filters)
                .await?
                .iter()
                .map(|row| prompt_api::metadata(row, true))
                .collect(),
            ManagedCatalog::Gateways => self
                .database
                .listed_gateways(
                    scope,
                    GatewayList {
                        include_inactive,
                        visibility: None,
                        team,
                        after: None,
                        limit: per_page,
                        offset: filters.offset,
                    },
                )
                .await?
                .iter()
                .map(|row| management::response(row, self.credential_cipher.as_ref()))
                .collect(),
        };
        let links = self
            .grpc
            .include_page_links
            .then(|| pagination.links(&format!("/admin/{}", kind.name()), include_inactive, team));
        Ok(CatalogListing {
            data,
            pagination,
            links,
        })
    }
}

fn flash_error(status: StatusCode, fallback: &'static str) -> &'static str {
    if status == StatusCode::FORBIDDEN {
        "permission_denied"
    } else {
        fallback
    }
}
