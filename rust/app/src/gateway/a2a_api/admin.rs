// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::catalog::AdminAgentFilters;

#[derive(Default, Deserialize)]
pub(crate) struct AdminA2aQuery {
    pub(crate) page: Option<i64>,
    pub(crate) per_page: Option<i64>,
    pub(crate) limit: Option<i64>,
    pub(crate) include_inactive: Option<String>,
    pub(crate) q: Option<String>,
    pub(crate) tags: Option<String>,
    pub(crate) team_id: Option<String>,
    pub(crate) render: Option<String>,
}

impl AdminA2aQuery {
    pub(crate) fn team(&self) -> Result<Option<String>, CatalogApiError> {
        self.team_id
            .as_deref()
            .filter(|team| !team.is_empty())
            .map(|team| {
                Uuid::parse_str(team)
                    .map(|_| team.to_ascii_lowercase())
                    .map_err(|_| {
                        CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid team ID")
                    })
            })
            .transpose()
    }

    pub(crate) fn include_inactive(&self) -> Result<bool, CatalogApiError> {
        flag(self.include_inactive.as_deref())
    }

    fn search(&self) -> Result<String, CatalogApiError> {
        let text = self.q.as_deref().unwrap_or_default();
        if text.chars().count() > 500 {
            return Err(invalid("A2A search must be at most 500 characters"));
        }
        Ok(text.trim().to_lowercase())
    }

    fn parsed_tags(&self) -> (&str, Vec<Vec<String>>) {
        let expression = self.tags.as_deref().unwrap_or_default().trim();
        let groups = expression
            .split(',')
            .filter_map(|group| {
                let terms: Vec<_> = group
                    .split('+')
                    .map(str::trim)
                    .filter(|term| !term.is_empty())
                    .take(10)
                    .map(str::to_owned)
                    .collect();
                (!terms.is_empty()).then_some(terms)
            })
            .take(20)
            .collect();
        (expression, groups)
    }
}

pub(crate) struct AdminAgentPage {
    pub(crate) rows: Vec<AgentRecord>,
    pub(crate) pagination: PaginationMeta,
    pub(crate) team: Option<String>,
    links: Option<Value>,
}

impl AdminAgentPage {
    pub(crate) fn payload(&self) -> Value {
        json!({"data":self.rows.iter().map(a2a_agent_metadata).collect::<Vec<_>>(),
               "pagination":self.pagination, "links":self.links})
    }
}

pub(crate) fn a2a_agent_metadata(agent: &AgentRecord) -> Value {
    let mut data = read_agent(agent);
    if data["authType"].is_null() {
        data["authType"] = json!("");
    }
    data
}

#[derive(Serialize)]
pub(crate) struct AdminAgentControls {
    pub(crate) edit: bool,
    pub(crate) delete: bool,
    pub(crate) test: bool,
}

pub(crate) enum AdminAgentAction {
    State(bool),
    Delete(bool),
}

impl GatewayService {
    pub(crate) fn admin_a2a_enabled(&self) -> bool {
        self.a2a_enabled
    }

    pub(crate) async fn require_admin_agent(
        &self,
        principal: &Principal,
        permission: &str,
    ) -> Result<(), CatalogApiError> {
        require_enabled(self)?;
        require_catalog_permission(self, principal, permission, false).await
    }

    async fn admin_agent_team(
        &self,
        principal: &Principal,
        requested: Option<&str>,
    ) -> Result<(Option<String>, bool), CatalogApiError> {
        let Some(requested) = requested else {
            return Ok((None, true));
        };
        let requested = Uuid::parse_str(requested)
            .map_err(|_| CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid team ID"))?;
        let matches = |id: &&String| Uuid::parse_str(id).ok() == Some(requested);
        let team = match &principal.visibility {
            TeamVisibility::Public => None,
            TeamVisibility::Teams(allowed) => allowed.iter().find(matches).cloned(),
            TeamVisibility::Admin => self
                .database
                .memberships(&principal.email)
                .await?
                .iter()
                .find(matches)
                .cloned(),
        };
        let allowed = team.is_some();
        Ok((team, allowed))
    }

    pub(crate) async fn admin_agent_page(
        &self,
        principal: &Principal,
        query: &AdminA2aQuery,
    ) -> Result<AdminAgentPage, CatalogApiError> {
        self.require_admin_agent(principal, "a2a.read").await?;
        let (page, size) = self.admin_page_params(query.page, query.per_page)?;
        let requested = query.team()?;
        let (team, allowed) = self
            .admin_agent_team(principal, requested.as_deref())
            .await?;
        let include_inactive = query.include_inactive()?;
        let search = query.search()?;
        let (_, groups) = query.parsed_tags();
        let scope = access::catalog_scope(Some(principal));
        let filters = AdminAgentFilters {
            include_inactive,
            team: team.as_deref(),
            text: &search,
            tag_groups: &groups,
        };
        let total = if allowed {
            self.database.admin_agent_count(scope, &filters).await?
        } else {
            0
        };
        let pagination = PaginationMeta::new(page, size, total);
        let rows = if total > 0 {
            self.database
                .admin_agents(
                    scope,
                    &filters,
                    size,
                    self.admin_page_offset(&pagination),
                    false,
                )
                .await?
        } else {
            Vec::new()
        };
        let links =
            self.admin_page_links(&pagination, "/admin/a2a", include_inactive, filters.team);
        Ok(AdminAgentPage {
            rows,
            pagination,
            team,
            links,
        })
    }

    pub(crate) async fn admin_agent_search(
        &self,
        principal: &Principal,
        query: &AdminA2aQuery,
    ) -> Result<Value, CatalogApiError> {
        self.require_admin_agent(principal, "a2a.read").await?;
        let size = query.limit.unwrap_or(i64::from(self.management_page_size));
        if !(1..=i64::from(self.management_max_page_size)).contains(&size) {
            return Err(invalid("Invalid agent search limit"));
        }
        let requested = query.team()?;
        let (team, allowed) = self
            .admin_agent_team(principal, requested.as_deref())
            .await?;
        let include_inactive = query.include_inactive()?;
        let search = query.search()?;
        let (tags, groups) = query.parsed_tags();
        let scope = access::catalog_scope(Some(principal));
        let filters = AdminAgentFilters {
            include_inactive,
            team: team.as_deref(),
            text: &search,
            tag_groups: &groups,
        };
        let agents = if allowed && (!search.is_empty() || !groups.is_empty()) {
            self.database
                .admin_agents(scope, &filters, size, 0, true)
                .await?
        } else {
            Vec::new()
        };
        let items = agents.into_iter().map(|agent| {
            json!({"id":agent.id, "name":agent.name, "endpoint_url":agent.endpoint_url, "description":agent.description})
        }).collect::<Vec<_>>();
        Ok(
            json!({"agents":items,"items":items,"count":items.len(),"entity_type":"agents",
                  "query":search,"filters_applied":{"q":search,"tags":tags,"tag_groups":groups}}),
        )
    }

    pub(crate) async fn admin_agent_ids(
        &self,
        principal: &Principal,
        query: &AdminA2aQuery,
    ) -> Result<Value, CatalogApiError> {
        self.require_admin_agent(principal, "a2a.read").await?;
        let requested = query.team()?;
        let (team, allowed) = self
            .admin_agent_team(principal, requested.as_deref())
            .await?;
        let filters = AdminAgentFilters {
            include_inactive: query.include_inactive()?,
            team: team.as_deref(),
            text: "",
            tag_groups: &[],
        };
        let ids = if allowed {
            self.database
                .admin_agent_ids(access::catalog_scope(Some(principal)), &filters)
                .await?
        } else {
            Vec::new()
        };
        Ok(json!({"agent_ids":ids,"count":ids.len()}))
    }

    pub(crate) async fn admin_agent(
        &self,
        principal: &Principal,
        id: &str,
        editing: bool,
    ) -> Result<Value, CatalogApiError> {
        let agent = if editing {
            lifecycle::editable(self, principal, id, "a2a.update", "update this agent", true)
                .await?
        } else {
            self.require_admin_agent(principal, "a2a.read").await?;
            find(self, Some(principal), AgentLookup::Id(id)).await?
        };
        Ok(a2a_agent_metadata(&agent))
    }

    pub(crate) async fn admin_agent_controls(
        &self,
        principal: &Principal,
        agent: &AgentRecord,
    ) -> Result<AdminAgentControls, CatalogApiError> {
        let target = || {
            agent
                .team_id
                .as_deref()
                .map_or(RoleContext::AnyTeam, RoleContext::Team)
        };
        let owned = owns_agent(self, principal, agent).await?;
        Ok(AdminAgentControls {
            edit: owned
                && self
                    .access
                    .allows(principal, "a2a.update", target(), false)
                    .await?,
            delete: owned
                && self
                    .access
                    .allows(principal, "a2a.delete", target(), false)
                    .await?,
            test: agent.enabled
                && self
                    .access
                    .allows(principal, "a2a.invoke", target(), false)
                    .await?,
        })
    }

    pub(crate) async fn save_admin_agent(
        &self,
        principal: &Principal,
        id: Option<&str>,
        mut fields: Map<String, Value>,
        headers: &HeaderMap,
        peer: SocketAddr,
    ) -> Result<Value, CatalogApiError> {
        self.require_admin_agent(
            principal,
            if id.is_some() {
                "a2a.update"
            } else {
                "a2a.create"
            },
        )
        .await?;
        let (team, allowed) = self
            .admin_agent_team(principal, fields.get("team_id").and_then(Value::as_str))
            .await?;
        if !allowed {
            return Err(denied_team());
        }
        if let Some(team) = team {
            fields.insert("team_id".into(), json!(team));
        }
        self.prepare_admin_catalog_team(principal, id.is_none(), &mut fields)
            .await?;
        let origin = WriteOrigin {
            address: Some(peer.ip().to_string()),
            agent: user_agent(headers),
            via: Some("ui"),
        };
        if let Some(id) = id {
            let patch = serde_json::from_value(Value::Object(fields))
                .map_err(|_| invalid("Invalid agent fields"))?;
            lifecycle::update_agent(self, principal, id, patch, origin, true).await
        } else {
            let visibility = fields.remove("visibility").unwrap_or(json!("private"));
            let team = fields.remove("team_id");
            let input = serde_json::from_value(
                json!({"agent":fields,"team_id":team,"visibility":visibility}),
            )
            .map_err(|_| invalid("Invalid agent fields"))?;
            register_agent(self, principal, input, origin, true).await
        }
    }

    pub(crate) async fn mutate_admin_agent(
        &self,
        principal: &Principal,
        id: &str,
        action: AdminAgentAction,
    ) -> Result<(), CatalogApiError> {
        match action {
            AdminAgentAction::State(enabled) => {
                lifecycle::set_agent_state(self, principal, id, enabled, true)
                    .await
                    .map(|_| ())
            }
            AdminAgentAction::Delete(metrics) => {
                lifecycle::remove_agent(self, principal, id, metrics, true).await
            }
        }
    }

    pub(crate) async fn test_admin_agent(
        &self,
        principal: &Principal,
        id: &str,
        headers: &HeaderMap,
        text: Option<&str>,
    ) -> Result<Value, CatalogApiError> {
        self.require_admin_agent(principal, "a2a.invoke").await?;
        diagnostics::test_agent(self, principal, id, headers, text, true)
            .await
            .map_err(|error| {
                if error.1["detail"]["success"] == false {
                    CatalogApiError(error.0, error.1["detail"].clone())
                } else {
                    error
                }
            })
    }
}

fn invalid(message: &str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}
