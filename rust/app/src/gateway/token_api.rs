// SPDX-License-Identifier: Apache-2.0

use axum::extract::{Path, Query};
use serde_json::Map;

use super::{catalog_api::*, *};
use crate::{
    jwt::{JwtError, TokenUse, validate_time_restrictions},
    tokens::{ApiTokenRecord, TokenList, TokenWriteError},
};

const INVALID_INPUT: &str = "Invalid request. Please check your input and try again.";
const SESSION_REQUIRED: &str = "Token management requires an interactive session (JWT from web login or SSO). API tokens cannot create, list, or revoke other tokens.";

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut routes = Router::new();
    for base in ["/tokens", "/v1/tokens"] {
        routes = routes
            .route(base, get(list).post(create))
            .route(
                &format!("{base}/{{id}}"),
                get(detail).put(update).delete(revoke),
            )
            .route(&format!("{base}/{{id}}/usage"), get(usage))
            .route(&format!("{base}/admin/all"), get(admin_list))
            .route(
                &format!("{base}/admin/{{id}}"),
                axum::routing::delete(admin_revoke),
            )
            .route(
                &format!("{base}/teams/{{team}}"),
                get(team_list).post(team_create),
            );
    }
    routes
}

#[derive(Default, Deserialize)]
struct ListQuery {
    include_inactive: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
    user_email: Option<String>,
}

#[derive(Default, Deserialize)]
struct TokenScope {
    server_id: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
    #[serde(default)]
    ip_restrictions: Vec<String>,
    #[serde(default)]
    time_restrictions: Map<String, Value>,
    #[serde(default)]
    usage_limits: Map<String, Value>,
}

#[derive(Deserialize)]
struct CreateToken {
    name: String,
    description: Option<String>,
    expires_in_days: Option<i64>,
    scope: Option<TokenScope>,
    #[serde(default)]
    tags: Vec<Value>,
    team_id: Option<String>,
    is_active: Option<bool>,
    user_email: Option<String>,
}

#[derive(Deserialize)]
struct EditToken {
    name: Option<String>,
    description: Option<String>,
    scope: Option<TokenScope>,
    tags: Option<Vec<Value>>,
    is_active: Option<bool>,
}

#[derive(Default, Deserialize)]
struct RevokeToken {
    reason: Option<String>,
}

#[derive(Default, Deserialize)]
struct UsageQuery {
    days: Option<i64>,
}

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    permit(&service, &principal, "tokens.read", RoleContext::AnyTeam).await?;
    let memberships = service.database.memberships(&principal.email).await?;
    let teams = match &principal.visibility {
        TeamVisibility::Admin => memberships,
        TeamVisibility::Public => Vec::new(),
        TeamVisibility::Teams(allowed) => memberships
            .into_iter()
            .filter(|team| allowed.contains(team))
            .collect(),
    };
    list_response(&service, &query, Some(&principal.email), None, &teams, 50).await
}

async fn admin_list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    require_admin(&principal)?;
    list_response(
        &service,
        &query,
        query.user_email.as_deref(),
        None,
        &[],
        100,
    )
    .await
}

async fn team_list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(team): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    permit(
        &service,
        &principal,
        "tokens.read",
        RoleContext::Team(&team),
    )
    .await?;
    require_team_access(&service, &principal, &team).await?;
    list_response(&service, &query, None, Some(&team), &[], 50).await
}

async fn list_response(
    service: &GatewayService,
    query: &ListQuery,
    owner: Option<&str>,
    team: Option<&str>,
    memberships: &[String],
    default_limit: i64,
) -> Result<Json<Value>, CatalogApiError> {
    let limit = query.limit.unwrap_or(default_limit);
    let offset = query.offset.unwrap_or(0);
    if !(1..=1000).contains(&limit) || offset < 0 {
        return Err(validation("Invalid token pagination"));
    }
    let (records, total) = service
        .database
        .managed_tokens(TokenList {
            owner,
            team,
            owner_teams: memberships,
            limit,
            offset,
            include_inactive: flag(query.include_inactive.as_deref())?,
        })
        .await?;
    let tokens = records.iter().map(metadata).collect::<Vec<_>>();
    Ok(Json(
        json!({"tokens":tokens,"total":total,"limit":limit,"offset":offset}),
    ))
}

async fn detail(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    permit(&service, &principal, "tokens.read", RoleContext::AnyTeam).await?;
    let token = owned_token(&service, &principal, &id).await?;
    Ok(Json(metadata(&token)))
}

async fn create(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Json(input): Json<CreateToken>,
) -> Result<Response, CatalogApiError> {
    issue(&service, &principal, input, None).await
}

async fn team_create(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(team): Path<String>,
    Json(input): Json<CreateToken>,
) -> Result<Response, CatalogApiError> {
    issue(&service, &principal, input, Some(&team)).await
}

async fn issue(
    service: &GatewayService,
    principal: &Principal,
    input: CreateToken,
    route_team: Option<&str>,
) -> Result<Response, CatalogApiError> {
    let requested = input.team_id.as_deref().filter(|team| !team.is_empty());
    if route_team
        .zip(requested)
        .is_some_and(|(outer, inner)| outer != inner)
    {
        return Err(validation("Token team does not match the route"));
    }
    let requested = route_team.or(requested);
    let context = requested.map_or(RoleContext::AnyTeam, RoleContext::Team);
    permit(service, principal, "tokens.create", context).await?;
    if let Some(team) = requested {
        require_team_access(service, principal, team).await?;
    }

    let owner = input.user_email.as_deref().unwrap_or(&principal.email);
    let delegated = !owner.eq_ignore_ascii_case(&principal.email);
    if delegated && !principal.is_global_admin() {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Admin access required to create tokens for other users",
        ));
    }
    let (subject, owner, owner_admin) = service
        .database
        .active_token_owner(owner)
        .await?
        .ok_or_else(|| CatalogApiError::detail(StatusCode::NOT_FOUND, "User not found"))?;
    let mut team = requested.map(str::to_owned);
    if team.is_none() {
        if delegated {
            team = service.database.personal_token_team(&owner).await?;
        } else if let TeamVisibility::Teams(teams) = &principal.visibility {
            team = service
                .database
                .personal_token_team(&owner)
                .await?
                .filter(|team| teams.contains(team))
                .or_else(|| (teams.len() == 1).then(|| teams[0].clone()));
        }
    }
    if let Some(team) = team.as_ref()
        && !service.database.memberships(&owner).await?.contains(team)
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "User is not a member of the requested team",
        ));
    }
    let mut warnings = Vec::new();
    if team.is_none() && !principal.is_global_admin() {
        warnings.push("No team could be inferred for this token, so it is scoped to public resources only. It cannot access your private resources or any team resources. Recreate it with an explicit team_id to scope it.");
    }
    let now = Timestamp::now();
    let expires = input
        .expires_in_days
        .map(|days| {
            if days < 1 {
                return Err(validation("Token expiry must be at least one day"));
            }
            days.checked_mul(86_400)
                .and_then(|duration| now.as_second().checked_add(duration))
                .and_then(|seconds| Timestamp::from_second(seconds).ok())
                .ok_or_else(|| validation("Invalid token expiry"))
        })
        .transpose()?;
    let mut scope = input.scope.unwrap_or_default();
    validate_scope(service, principal, team.as_deref(), &mut scope).await?;
    let mut record = ApiTokenRecord {
        id: Uuid::new_v4().hyphenated().to_string(),
        jti: Uuid::new_v4().hyphenated().to_string(),
        user_email: owner,
        team_id: team,
        name: validate_name(input.name)?,
        description: validate_description(input.description)?,
        tags: Some(validate_tags(input.tags)?),
        expires_at: expires.map(|expires| expires.to_string()),
        is_active: input.is_active.unwrap_or(true),
        ..ApiTokenRecord::default()
    };
    scope.store(&mut record);
    let mut claims = json!({
        "sub":subject,"jti":record.jti,"token_use":"api","iat":now.as_second(),
        "teams":record.team_id.as_ref().map(|team|vec![team]),
        "user":{"email":record.user_email,"full_name":"API Token User","is_admin":owner_admin,"auth_provider":"api_token"},
        "scopes":scope.claims(),
    });
    if let Some(expires) = expires {
        claims["exp"] = expires.as_second().into();
    }
    let signer = service.token_issuer.as_ref().ok_or_else(|| {
        CatalogApiError::detail(
            StatusCode::SERVICE_UNAVAILABLE,
            "API token signing unavailable",
        )
    })?;
    let signed = Zeroizing::new(
        signer
            .sign(claims)
            .map_err(|_| CatalogApiError::unavailable())?,
    );
    record.token_hash = crate::tokens::hash_token(signed.as_str());
    let stored = service
        .database
        .issue_managed_token(&record)
        .await
        .map_err(persistence_error)?;
    let mut response = (
        StatusCode::CREATED,
        Json(json!({"token":metadata(&stored),"access_token":signed.as_str(),"warnings":warnings})),
    )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

async fn update(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(input): Json<EditToken>,
) -> Result<Json<Value>, CatalogApiError> {
    permit(&service, &principal, "tokens.update", RoleContext::AnyTeam).await?;
    let prior = owned_token(&service, &principal, &id).await?;
    let mut token = prior.clone();
    if let Some(name) = input.name {
        token.name = validate_name(name)?;
    }
    if let Some(description) = input.description {
        token.description = validate_description(Some(description))?;
    }
    if let Some(tags) = input.tags {
        token.tags = Some(validate_tags(tags)?);
    }
    if let Some(active) = input.is_active {
        token.is_active = active;
    }
    if let Some(mut scope) = input.scope {
        validate_scope(&service, &principal, prior.team_id.as_deref(), &mut scope).await?;
        scope.store(&mut token);
    }
    let stored = service
        .database
        .update_managed_token(&prior, &token)
        .await
        .map_err(persistence_error)?;
    Ok(Json(metadata(&stored)))
}

async fn revoke(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    input: Option<Json<RevokeToken>>,
) -> Result<StatusCode, CatalogApiError> {
    permit(&service, &principal, "tokens.revoke", RoleContext::AnyTeam).await?;
    let token = owned_token(&service, &principal, &id).await?;
    revoke_token(&service, &principal, &token, input).await
}

async fn admin_revoke(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    input: Option<Json<RevokeToken>>,
) -> Result<StatusCode, CatalogApiError> {
    require_admin(&principal)?;
    let token = service
        .database
        .managed_token(&id)
        .await?
        .ok_or_else(missing)?;
    revoke_token(&service, &principal, &token, input).await
}

async fn revoke_token(
    service: &GatewayService,
    principal: &Principal,
    token: &ApiTokenRecord,
    input: Option<Json<RevokeToken>>,
) -> Result<StatusCode, CatalogApiError> {
    let reason = input.and_then(|Json(input)| input.reason);
    if reason
        .as_ref()
        .is_some_and(|reason| reason.chars().count() > 255)
    {
        return Err(validation(
            "Revocation reason must be at most 255 characters",
        ));
    }
    service
        .database
        .revoke_managed_token(token, &principal.email, reason.as_deref())
        .await
        .map_err(persistence_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn usage(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Query(query): Query<UsageQuery>,
) -> Result<Json<Value>, CatalogApiError> {
    permit(&service, &principal, "tokens.read", RoleContext::AnyTeam).await?;
    let token = owned_token(&service, &principal, &id).await?;
    let days = query.days.unwrap_or(30);
    if !(1..=365).contains(&days) {
        return Err(validation("Invalid token usage period"));
    }
    Ok(Json(
        service
            .database
            .token_usage_statistics(&token.jti, days)
            .await?,
    ))
}

async fn permit(
    service: &GatewayService,
    principal: &Principal,
    permission: &str,
    context: RoleContext<'_>,
) -> Result<(), CatalogApiError> {
    if !service
        .access
        .allows(principal, permission, context, true)
        .await?
    {
        return Err(denied("Access denied"));
    }
    require_session(principal)
}

fn require_session(principal: &Principal) -> Result<(), CatalogApiError> {
    if principal.token_use != TokenUse::Session {
        return Err(denied(SESSION_REQUIRED));
    }
    Ok(())
}

fn require_admin(principal: &Principal) -> Result<(), CatalogApiError> {
    require_session(principal)?;
    if !principal.is_global_admin() {
        return Err(denied("Unrestricted administrator access required"));
    }
    Ok(())
}

async fn require_team_access(
    service: &GatewayService,
    principal: &Principal,
    team: &str,
) -> Result<(), CatalogApiError> {
    if !service.database.active_team(team).await? {
        return Err(CatalogApiError::detail(
            StatusCode::NOT_FOUND,
            "Team not found",
        ));
    }
    if !principal.is_global_admin()
        && (!matches!(&principal.visibility,TeamVisibility::Teams(teams) if teams.iter().any(|id|id==team))
            || !service
                .database
                .memberships(&principal.email)
                .await?
                .iter()
                .any(|id| id == team))
    {
        return Err(denied("Access denied"));
    }
    Ok(())
}

async fn owned_token(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
) -> Result<ApiTokenRecord, CatalogApiError> {
    let token = service
        .database
        .managed_token(id)
        .await?
        .filter(|token| token.user_email == principal.email)
        .ok_or_else(missing)?;
    if let Some(team) = token.team_id.as_deref() {
        require_team_access(service, principal, team).await?;
    }
    Ok(token)
}

impl TokenScope {
    fn claims(&self) -> Value {
        let mut permissions = self.permissions.clone();
        if !permissions
            .iter()
            .any(|name| matches!(name.as_str(), "*" | "servers.use"))
            && permissions.iter().any(|name| {
                ["tools.", "resources.", "prompts.", "logging."]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
            })
        {
            permissions.push("servers.use".to_owned());
        }
        json!({"server_id":self.server_id,"permissions":permissions,"ip_restrictions":self.ip_restrictions,
            "time_restrictions":self.time_restrictions,"usage_limits":self.usage_limits})
    }

    fn store(&self, token: &mut ApiTokenRecord) {
        token.server_id = self.server_id.clone();
        token.resource_scopes = Some(json!(self.permissions).to_string());
        token.ip_restrictions = Some(json!(self.ip_restrictions).to_string());
        token.time_restrictions = Some(json!(self.time_restrictions).to_string());
        token.usage_limits = Some(json!(self.usage_limits).to_string());
    }
}

async fn validate_scope(
    service: &GatewayService,
    principal: &Principal,
    team: Option<&str>,
    scope: &mut TokenScope,
) -> Result<(), CatalogApiError> {
    for values in [&mut scope.ip_restrictions, &mut scope.permissions] {
        for value in &mut *values {
            *value = value.trim().to_owned();
        }
        values.retain(|value| !value.is_empty());
    }
    if scope.ip_restrictions.iter().any(|rule| {
        rule.parse::<ipnet::IpNet>().is_err() && rule.parse::<std::net::IpAddr>().is_err()
    }) {
        return Err(validation("Invalid token IP restriction"));
    }
    if scope.permissions.iter().any(|permission| {
        permission != "*"
            && !permission
                .split_once(['.', ':'])
                .is_some_and(|(object, action)| {
                    [object, action].into_iter().all(|part| {
                        part.starts_with(|character: char| character.is_ascii_alphabetic())
                            && part.chars().all(|character| {
                                character.is_ascii_alphanumeric() || character == '_'
                            })
                    })
                })
    }) {
        return Err(validation("Invalid token permission format"));
    }
    if matches!(
        validate_time_restrictions(&json!(scope.time_restrictions), Timestamp::now()),
        Err(JwtError::InvalidTimeRestrictions)
    ) {
        return Err(validation("Invalid token time restrictions"));
    }
    for key in ["requests_per_hour", "requests_per_day"] {
        if scope.usage_limits.get(key).is_some_and(|count| {
            count
                .as_u64()
                .is_none_or(|count| count == 0 || count > i32::MAX as u64)
        }) {
            return Err(validation("Token usage limits must be positive integers"));
        }
    }
    if let Some(server) = scope.server_id.as_deref() {
        let visible = service
            .database
            .catalog_server(server)
            .await?
            .is_some_and(|entry| entry.is_visible(access::catalog_scope(Some(principal))));
        if !visible {
            return Err(CatalogApiError::detail(
                StatusCode::NOT_FOUND,
                format!("Server not found: {server}"),
            ));
        }
    }
    if !principal.is_global_admin() {
        for permission in &scope.permissions {
            if permission.contains('*')
                || !service
                    .access
                    .allows(
                        principal,
                        permission,
                        team.map_or(RoleContext::Global, RoleContext::Team),
                        false,
                    )
                    .await?
            {
                return Err(denied("Token permissions exceed the caller's permissions"));
            }
        }
    }
    Ok(())
}

fn metadata(record: &ApiTokenRecord) -> Value {
    let mut response = json!(record);
    for (field, value) in [
        ("resource_scopes", record.resource_scopes.as_deref()),
        ("ip_restrictions", record.ip_restrictions.as_deref()),
        ("time_restrictions", record.time_restrictions.as_deref()),
        ("usage_limits", record.usage_limits.as_deref()),
        ("tags", record.tags.as_deref()),
    ] {
        response[field] = value
            .and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or_else(|| {
                if matches!(field, "time_restrictions" | "usage_limits") {
                    json!({})
                } else {
                    json!([])
                }
            });
    }
    for (field, value) in [
        ("created_at", Some(record.created_at.as_str())),
        ("expires_at", record.expires_at.as_deref()),
        ("last_used", record.last_used.as_deref()),
        ("revoked_at", record.revoked_at.as_deref()),
    ] {
        response[field] = json!(value.map(|time| time.replacen(' ', "T", 1)));
    }
    response
}

fn validate_name(name: String) -> Result<String, CatalogApiError> {
    if name.trim().is_empty() || name.chars().count() > 255 || name.chars().any(char::is_control) {
        return Err(validation("Invalid token name"));
    }
    Ok(name)
}

fn validate_description(text: Option<String>) -> Result<Option<String>, CatalogApiError> {
    if text
        .as_ref()
        .is_some_and(|text| text.chars().count() > 1000)
    {
        return Err(validation(
            "Token description must be at most 1000 characters",
        ));
    }
    Ok(text)
}

fn validate_tags(tags: Vec<Value>) -> Result<String, CatalogApiError> {
    if tags.iter().any(|value| {
        !value.is_string()
            && !value
                .as_object()
                .is_some_and(|fields| fields.values().all(Value::is_string))
    }) {
        return Err(validation("Invalid token tag"));
    }
    Ok(json!(tags).to_string())
}

fn missing() -> CatalogApiError {
    CatalogApiError::detail(StatusCode::NOT_FOUND, "Token not found")
}

fn denied(message: &'static str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::FORBIDDEN, message)
}

fn validation(message: &'static str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}

fn persistence_error(error: TokenWriteError) -> CatalogApiError {
    match error {
        TokenWriteError::Duplicate => {
            CatalogApiError::detail(StatusCode::BAD_REQUEST, INVALID_INPUT)
        }
        TokenWriteError::Changed => {
            CatalogApiError::detail(StatusCode::CONFLICT, "Token changed concurrently")
        }
        TokenWriteError::Database(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            CatalogApiError::detail(
                StatusCode::CONFLICT,
                "A token with this name already exists for this user in the same team scope. Token names must be unique per user per team. Please choose a different name.",
            )
        }
        TokenWriteError::Database(error) => error.into(),
    }
}
