// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Default, Deserialize)]
pub(crate) struct AdminTokenQuery {
    pub(crate) page: Option<i64>,
    pub(crate) per_page: Option<i64>,
    pub(crate) include_inactive: Option<String>,
    pub(crate) q: Option<String>,
    pub(crate) limit: Option<i64>,
    pub(crate) team_id: Option<String>,
    pub(crate) render: Option<String>,
}

impl AdminTokenQuery {
    pub(crate) fn include_inactive(&self) -> Result<bool, CatalogApiError> {
        flag(self.include_inactive.as_deref())
    }

    pub(crate) fn team(&self) -> Result<Option<String>, CatalogApiError> {
        self.team_id
            .as_deref()
            .filter(|team| !team.is_empty())
            .map(|team| {
                Uuid::parse_str(team)
                    .map(|id| id.simple().to_string())
                    .map_err(|_| {
                        CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid team ID")
                    })
            })
            .transpose()
    }
}

pub(crate) struct AdminTokenPage {
    pub(crate) tokens: Vec<ApiTokenRecord>,
    pub(crate) pagination: PaginationMeta,
}

impl GatewayService {
    pub(crate) async fn admin_token_page(
        &self,
        principal: &Principal,
        query: &AdminTokenQuery,
        searching: bool,
    ) -> Result<AdminTokenPage, CatalogApiError> {
        require_session(principal)?;
        let team = query.team()?;
        let search = query
            .q
            .as_deref()
            .map(str::trim)
            .filter(|text| !text.is_empty());
        if query
            .q
            .as_ref()
            .is_some_and(|text| text.chars().count() > 500)
        {
            return Err(validation("Invalid token search"));
        }
        let default = i64::from(self.management_page_size);
        let page = if searching {
            1
        } else {
            query.page.unwrap_or(1)
        };
        let size = if searching {
            query.limit.unwrap_or(default)
        } else {
            query.per_page.unwrap_or(default)
        };
        if page < 1 || !(1..=i64::from(self.management_max_page_size)).contains(&size) {
            return Err(validation("Invalid token pagination"));
        }
        let size = if searching {
            size
        } else {
            size.max(i64::from(self.grpc.min_page_size))
        };
        let teams = visible_teams(self, principal).await?;
        let mut filters = TokenList {
            owner: Some(&principal.email),
            team: team.as_deref(),
            owner_teams: &teams,
            search,
            include_inactive: query.include_inactive()?,
            limit: size,
            offset: (page - 1)
                .saturating_mul(size)
                .min(self.grpc.max_page_offset),
        };
        let (mut tokens, total) = self.database.managed_tokens(filters).await?;
        let pagination = PaginationMeta::new(page, size, total);
        if pagination.page != page {
            filters.offset = pagination.offset(self.grpc.max_page_offset);
            tokens = self.database.managed_tokens(filters).await?.0;
        }
        Ok(AdminTokenPage { tokens, pagination })
    }

    pub(crate) async fn issue_admin_token(
        &self,
        principal: &Principal,
        fields: Value,
    ) -> Result<IssuedToken, CatalogApiError> {
        let input =
            serde_json::from_value(fields).map_err(|_| validation("Invalid token fields"))?;
        issue(self, principal, input, None).await
    }

    pub(crate) async fn revoke_admin_token(
        &self,
        principal: &Principal,
        id: &str,
    ) -> Result<StatusCode, CatalogApiError> {
        require_session(principal)?;
        let token = owned_token(self, principal, id).await?;
        revoke_token(
            self,
            principal,
            &token,
            Some("Revoked by user via admin interface"),
        )
        .await
    }

    pub(crate) async fn admin_token_usage(
        &self,
        principal: &Principal,
        id: &str,
        days: i64,
    ) -> Result<(String, Value), CatalogApiError> {
        require_session(principal)?;
        if !(1..=365).contains(&days) {
            return Err(validation("Invalid token usage period"));
        }
        let token = owned_token(self, principal, id).await?;
        let usage = self
            .database
            .token_usage_statistics(&token.jti, days)
            .await?;
        Ok((token.name, usage))
    }
}

impl AdminTokenPage {
    pub(crate) fn search_rows(&self) -> Value {
        json!(
            self.tokens
                .iter()
                .map(|token| {
                    let mut data = metadata(token);
                    if let Value::Object(fields) = &mut data {
                        fields.retain(|name, _| {
                            matches!(
                                name.as_str(),
                                "id" | "name"
                                    | "description"
                                    | "user_email"
                                    | "team_id"
                                    | "created_at"
                                    | "expires_at"
                                    | "last_used"
                                    | "is_active"
                                    | "is_revoked"
                                    | "tags"
                                    | "server_id"
                            )
                        });
                    }
                    data
                })
                .collect::<Vec<_>>()
        )
    }
}
