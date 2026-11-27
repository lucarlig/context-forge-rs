// SPDX-License-Identifier: Apache-2.0

use super::*;

const READ: &str = "admin.oauth_clients:read";
const DELETE: &str = "admin.oauth_clients:delete";

pub(super) async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, CatalogApiError> {
    check_admin(&service, &principal, READ).await?;
    let clients = service
        .database
        .registered_oauth_clients(None)
        .await?
        .into_iter()
        .map(|client| client.payload(false))
        .collect::<Vec<_>>();
    Ok(Json(json!({"total":clients.len(),"clients":clients})))
}

pub(super) async fn read(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(gateway): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    check_admin(&service, &principal, READ).await?;
    let mut clients = service
        .database
        .registered_oauth_clients(Some(&gateway))
        .await?;
    if clients.len() > 1 {
        return Err(CatalogApiError::detail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to get registered client",
        ));
    }
    let client = clients.pop().ok_or_else(|| {
        CatalogApiError::detail(
            StatusCode::NOT_FOUND,
            format!("No registered OAuth client found for gateway {gateway}"),
        )
    })?;
    Ok(Json(client.payload(true)))
}

pub(super) async fn delete(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    check_admin(&service, &principal, DELETE).await?;
    let (gateway, issuer) = service
        .database
        .delete_registered_oauth_client(&id)
        .await?
        .ok_or_else(|| {
            CatalogApiError::detail(
                StatusCode::NOT_FOUND,
                format!("Registered client {id} not found"),
            )
        })?;
    Ok(Json(json!({"success":true,
        "message":format!("Registered OAuth client {id} deleted successfully"),
        "gateway_id":gateway,"issuer":issuer})))
}

async fn check_admin(
    service: &GatewayService,
    principal: &Principal,
    permission: &str,
) -> Result<(), CatalogApiError> {
    if !service
        .access
        .allows(principal, permission, RoleContext::Global, false)
        .await?
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    if !principal.is_global_admin() {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            if principal.is_admin() {
                "OAuth client management requires un-narrowed admin access"
            } else {
                "Admin access required"
            },
        ));
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct RegisteredClient {
    id: String,
    gateway_id: String,
    issuer: String,
    client_id: String,
    redirect_uris: String,
    grant_types: String,
    scope: Option<String>,
    token_endpoint_auth_method: String,
    registration_client_uri: Option<String>,
    created_at: Option<String>,
    expires_at: Option<String>,
    is_active: bool,
}

impl RegisteredClient {
    fn payload(self, include_management_uri: bool) -> Value {
        let mut value = json!({
            "id":self.id,"gateway_id":self.gateway_id,"issuer":self.issuer,"client_id":self.client_id,
            "redirect_uris":self.redirect_uris.split(',').collect::<Vec<_>>(),
            "grant_types":self.grant_types.split(',').collect::<Vec<_>>(),
            "scope":self.scope,"token_endpoint_auth_method":self.token_endpoint_auth_method,
            "created_at":self.created_at.map(|time|time.replacen(' ', "T", 1)),
            "expires_at":self.expires_at.map(|time|time.replacen(' ', "T", 1)),
            "is_active":self.is_active,
        });
        if include_management_uri {
            value["registration_client_uri"] = json!(self.registration_client_uri);
        }
        value
    }
}

impl Database {
    async fn registered_oauth_clients(
        &self,
        gateway: Option<&str>,
    ) -> Result<Vec<RegisteredClient>, sqlx::Error> {
        const SQL: &str = "SELECT id,gateway_id,issuer,client_id,redirect_uris,grant_types,scope,
            token_endpoint_auth_method,registration_client_uri,CAST(created_at AS TEXT) AS created_at,
            CAST(expires_at AS TEXT) AS expires_at,is_active FROM registered_oauth_clients
            WHERE CAST($1 AS TEXT) IS NULL OR gateway_id=$1 ORDER BY created_at,id";
        match self {
            Self::Sqlite(pool) => sqlx::query_as(SQL).bind(gateway).fetch_all(pool).await,
            Self::Postgres(pool) => sqlx::query_as(SQL).bind(gateway).fetch_all(pool).await,
        }
    }

    async fn delete_registered_oauth_client(
        &self,
        id: &str,
    ) -> Result<Option<(String, String)>, sqlx::Error> {
        const SQL: &str =
            "DELETE FROM registered_oauth_clients WHERE id=$1 RETURNING gateway_id,issuer";
        match self {
            Self::Sqlite(pool) => sqlx::query_as(SQL).bind(id).fetch_optional(pool).await,
            Self::Postgres(pool) => sqlx::query_as(SQL).bind(id).fetch_optional(pool).await,
        }
    }
}
