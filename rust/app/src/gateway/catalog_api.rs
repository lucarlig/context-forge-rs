// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::catalog::{CatalogEntryFilters, slugify};

#[derive(Default, Deserialize)]
pub(super) struct CatalogListQuery {
    pub(super) include_inactive: Option<String>,
    pub(super) include_pagination: Option<String>,
    pub(super) include_metrics: Option<String>,
    pub(super) limit: Option<i64>,
    pub(super) cursor: Option<String>,
    pub(super) tags: Option<String>,
    pub(super) visibility: Option<String>,
    pub(super) team_id: Option<String>,
    pub(super) gateway_id: Option<String>,
    pub(super) mcp_server_id: Option<String>,
    pub(super) apijsonpath: Option<String>,
}

impl CatalogListQuery {
    pub(super) fn gateway_filter(&self) -> Result<Option<&str>, CatalogApiError> {
        let gateway = self.gateway_id.as_deref();
        let alias = self.mcp_server_id.as_deref();
        if gateway
            .zip(alias)
            .is_some_and(|(gateway, alias)| gateway != alias)
        {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "gateway_id and mcp_server_id conflict",
            ));
        }
        Ok(gateway.or(alias))
    }

    pub(super) fn tags(&self) -> Vec<String> {
        let mut tags = self
            .tags
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|tag| !tag.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        tags.sort_unstable();
        tags.dedup();
        tags
    }
}

pub(super) struct CatalogPage<'a> {
    include_inactive: bool,
    include_pagination: bool,
    visibility: Option<&'a str>,
    team: Option<&'a str>,
    gateway: Option<&'a str>,
    tags: Vec<String>,
    limit: Option<i64>,
    cursor: Option<(String, String)>,
    fingerprint: [u8; 32],
}

impl<'a> CatalogPage<'a> {
    pub(super) fn prepare(
        service: &GatewayService,
        principal: &Principal,
        query: &'a CatalogListQuery,
        endpoint: &str,
    ) -> Result<Self, CatalogApiError> {
        let include_inactive = flag(query.include_inactive.as_deref())?;
        let include_pagination = flag(query.include_pagination.as_deref())?;
        let gateway = query.gateway_filter()?;
        let team = query.team_id.as_deref();
        if let (TeamVisibility::Teams(allowed), Some(team)) = (&principal.visibility, team)
            && !allowed.iter().any(|id| id == team)
        {
            return Err(CatalogApiError(
                StatusCode::FORBIDDEN,
                json!({
                    "message":"Access issue: This API token does not have the required permissions for this team."
                }),
            ));
        }
        let tags = query.tags();
        let limit = match query.limit {
            Some(0) => None,
            Some(limit) if limit > 0 => {
                Some(limit.min(i64::from(service.management_max_page_size)))
            }
            Some(_) => {
                return Err(CatalogApiError::detail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid limit",
                ));
            }
            None => Some(i64::from(service.management_page_size)),
        };
        let fingerprint = Sha256::digest(
            json!([
                list_fingerprint(endpoint, Some(principal), None),
                include_inactive,
                &tags,
                team,
                gateway,
                &query.visibility,
            ])
            .to_string()
            .as_bytes(),
        )
        .into();
        let cursor = query
            .cursor
            .as_deref()
            .and_then(|value| service.pagination.decode(value, &fingerprint).ok())
            .and_then(|cursor| serde_json::from_str::<(String, String)>(&cursor.after_id).ok());
        Ok(Self {
            include_inactive,
            include_pagination,
            visibility: query.visibility.as_deref(),
            team,
            gateway,
            tags,
            limit,
            cursor,
            fingerprint,
        })
    }

    pub(super) fn filters(&self) -> CatalogEntryFilters<'_> {
        CatalogEntryFilters {
            include_inactive: self.include_inactive,
            visibility: self.visibility,
            team: self.team,
            gateway: self.gateway,
            after: self
                .cursor
                .as_ref()
                .map(|(created, id)| (created.as_str(), id.as_str())),
            limit: self.limit.map_or(i64::MAX, |limit| limit + 1),
            offset: 0,
            tags: &self.tags,
        }
    }

    pub(super) fn envelope<T>(
        &self,
        service: &GatewayService,
        mut rows: Vec<T>,
        key: &str,
        position: impl Fn(&T) -> (&str, &str),
        metadata: impl Fn(&T) -> Value,
    ) -> Result<Value, CatalogApiError> {
        let mut next_cursor = None;
        if let Some(limit) = self.limit
            && rows.len() as i64 > limit
        {
            rows.truncate(limit as usize);
            if self.include_pagination
                && let Some(last) = rows.last()
            {
                let position = json!(position(last)).to_string();
                let expires = Timestamp::now()
                    .as_second()
                    .saturating_add(service.pagination.ttl);
                next_cursor = Some(
                    service
                        .pagination
                        .encode(position, self.fingerprint, expires)
                        .map_err(|_| CatalogApiError::unavailable())?,
                );
            }
        }
        let entries = rows.iter().map(metadata).collect::<Vec<_>>();
        Ok(if self.include_pagination {
            json!({(key): entries, "nextCursor": next_cursor})
        } else {
            json!(entries)
        })
    }
}

pub(super) fn flag(input: Option<&str>) -> Result<bool, CatalogApiError> {
    match input.map(str::to_ascii_lowercase).as_deref() {
        None | Some("0" | "false" | "f" | "off" | "n" | "no") => Ok(false),
        Some("1" | "true" | "t" | "on" | "y" | "yes") => Ok(true),
        _ => Err(CatalogApiError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid boolean query parameter",
        )),
    }
}

pub(super) async fn require_catalog_permission(
    service: &GatewayService,
    principal: &Principal,
    permission: &str,
    bypass: bool,
) -> Result<(), CatalogApiError> {
    if !service
        .access
        .allows(principal, permission, RoleContext::AnyTeam, bypass)
        .await?
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    Ok(())
}

pub(super) fn http_server_id(value: &axum::http::HeaderValue) -> Result<&str, CatalogApiError> {
    value
        .to_str()
        .map_err(|_| CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid server ID"))
}

pub(super) fn alias_metadata(response: Value) -> Value {
    let mut aliased = camelcase_fields(response);
    aliased["_meta"] = Value::Null;
    aliased
}

pub(super) fn camelcase_fields(response: Value) -> Value {
    let Value::Object(response) = response else {
        unreachable!()
    };
    let aliased = response
        .into_iter()
        .map(|(key, value)| {
            let mut pieces = key.split('_');
            let mut camel = pieces.next().unwrap_or_default().to_owned();
            for piece in pieces {
                let mut characters = piece.chars();
                if let Some(first) = characters.next() {
                    camel.extend(first.to_uppercase());
                    camel.push_str(characters.as_str());
                }
            }
            (camel, value)
        })
        .collect();
    Value::Object(aliased)
}

pub(crate) struct CatalogApiError(pub(super) StatusCode, pub(super) Value);

impl CatalogApiError {
    pub(crate) fn detail(status: StatusCode, detail: impl Into<String>) -> Self {
        Self(status, json!({"detail":detail.into()}))
    }

    pub(crate) fn form_message(&self) -> &str {
        self.1["message"]
            .as_str()
            .or_else(|| self.1["detail"].as_str())
            .or_else(|| self.1["detail"]["message"].as_str())
            .unwrap_or("Could not save the entry.")
    }

    pub(crate) fn form_response(self) -> Response {
        (
            self.0,
            Json(json!({"message":self.form_message(),"success":false})),
        )
            .into_response()
    }

    pub(super) fn unavailable() -> Self {
        Self::detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "Catalog service unavailable",
        )
    }
}

impl From<sqlx::Error> for CatalogApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "catalog registry query failed");
        Self::unavailable()
    }
}

impl IntoResponse for CatalogApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

pub(super) fn normalized_tags(tags: Vec<Value>) -> Result<Value, CatalogApiError> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();
    for tag in tags {
        let label = tag
            .as_str()
            .or_else(|| tag.get("label").and_then(Value::as_str))
            .map(str::trim)
            .filter(|label| !label.is_empty() && !label.chars().any(char::is_control))
            .ok_or_else(|| {
                CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, "Invalid catalog tag")
            })?;
        let id = slugify(tag.get("id").and_then(Value::as_str).unwrap_or(label));
        if id.is_empty() {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid catalog tag",
            ));
        }
        if seen.insert(id.clone()) {
            normalized.push(json!({"id":id,"label":label}));
        }
    }
    Ok(json!(normalized))
}

pub(super) fn format_bytes(size: usize) -> String {
    if size < 1024 {
        format!("{size} B")
    } else if size < 1024 * 1024 {
        format!("{:.1} KB", size as f64 / 1024.0)
    } else {
        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
    }
}

pub(super) fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|agent| agent.to_str().ok())
        .map(str::to_owned)
}

pub(super) fn client_address(peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> Option<String> {
    peer.map(|Extension(ConnectInfo(peer))| peer.ip().to_string())
}

pub(super) struct WriteOrigin {
    pub(super) address: Option<String>,
    pub(super) agent: Option<String>,
    pub(super) via: Option<&'static str>,
}

impl WriteOrigin {
    pub(super) fn new(
        peer: Option<Extension<ConnectInfo<SocketAddr>>>,
        headers: &HeaderMap,
        via: Option<&'static str>,
    ) -> Self {
        Self {
            address: client_address(peer),
            agent: user_agent(headers),
            via,
        }
    }
}

pub(super) fn denied_team() -> CatalogApiError {
    CatalogApiError(
        StatusCode::FORBIDDEN,
        json!({
            "message":"Access issue: This API token does not have the required permissions for this team."
        }),
    )
}

#[derive(Serialize)]
pub(crate) struct PaginationMeta {
    pub(crate) page: i64,
    pub(crate) per_page: i64,
    pub(crate) total_items: i64,
    pub(crate) total_pages: i64,
    pub(crate) has_next: bool,
    pub(crate) has_prev: bool,
    page_items: Option<i64>,
    next_cursor: Option<String>,
    prev_cursor: Option<String>,
}

impl PaginationMeta {
    pub(super) fn new(mut page: i64, per_page: i64, total_items: i64) -> Self {
        let total_pages = total_items / per_page + i64::from(total_items % per_page != 0);
        if total_pages > 0 {
            page = page.min(total_pages);
        }
        Self {
            page,
            per_page,
            total_items,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
            page_items: None,
            next_cursor: None,
            prev_cursor: None,
        }
    }

    pub(super) fn offset(&self, max_offset: i64) -> i64 {
        (self.page - 1)
            .saturating_mul(self.per_page)
            .min(max_offset)
    }

    pub(super) fn links(&self, base: &str, include_inactive: bool, team: Option<&str>) -> Value {
        let link = |page| {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            if include_inactive {
                query.append_pair("include_inactive", "True");
            }
            if let Some(team) = team {
                query.append_pair("team_id", team);
            }
            query
                .append_pair("page", &i64::to_string(&page))
                .append_pair("per_page", &self.per_page.to_string());
            format!("{base}?{}", query.finish())
        };
        json!({
            "self":link(self.page), "first":link(1), "last":link(self.total_pages.max(1)),
            "next":self.has_next.then(|| link(self.page + 1)),
            "prev":self.has_prev.then(|| link(self.page - 1)),
        })
    }
}
