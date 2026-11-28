// SPDX-License-Identifier: Apache-2.0

mod system;

use std::{
    collections::BTreeMap,
    error::Error,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use jiff::Timestamp;
use minijinja::{AutoEscape, Environment, context};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    access::{AuthError, Authorizer, Principal, bearer, cookie},
    config::{Settings, admin_root, flag, parse, value},
    database::Database,
    jwt::TokenUse,
    probes::RedisProbe,
    tokens::TokenRequest,
};

const PERMISSION: &str = "admin.system_config";

pub struct Diagnostics {
    access: Arc<Authorizer>,
    database: Database,
    redis: Option<RedisProbe>,
    database_url: Option<String>,
    redis_url: Option<String>,
    app_name: String,
    protocol_version: String,
    settings: Value,
    email_auth: bool,
    basic: Option<[u8; 32]>,
    admin_root: String,
    start: Instant,
    system: Arc<Mutex<system::Metrics>>,
}

impl Diagnostics {
    pub fn from_settings(
        settings: &Settings,
        database: Database,
        redis: Option<RedisProbe>,
        access: Arc<Authorizer>,
    ) -> Result<Arc<Self>, Box<dyn Error + Send + Sync>> {
        let basic = if flag("API_ALLOW_BASIC_AUTH")?.unwrap_or(false) {
            let user = value("BASIC_AUTH_USER", "admin")?;
            let password = Zeroizing::new(value("BASIC_AUTH_PASSWORD", "changeme")?);
            let mut hash = Sha256::new();
            hash.update(user.as_bytes());
            hash.update(b":");
            hash.update(password.as_bytes());
            Some(hash.finalize().into())
        } else {
            None
        };
        Ok(Arc::new(Self {
            access,
            database,
            redis,
            database_url: sanitize_url(&settings.database_url),
            redis_url: sanitize_url(&value("REDIS_URL", "")?),
            app_name: value("APP_NAME", "ContextForge")?,
            protocol_version: value("PROTOCOL_VERSION", "2025-11-25")?,
            settings: json!({
                "cache_type": value("CACHE_TYPE", "database")?,
                "mcpgateway_ui_enabled": flag("MCPGATEWAY_UI_ENABLED")?.unwrap_or(false),
                "mcpgateway_admin_api_enabled": flag("MCPGATEWAY_ADMIN_API_ENABLED")?.unwrap_or(false),
                "metrics_retention_days": parse("METRICS_RETENTION_DAYS", 7u32)?,
                "metrics_rollup_retention_days": parse("METRICS_ROLLUP_RETENTION_DAYS", 365u32)?,
                "metrics_cleanup_enabled": flag("METRICS_CLEANUP_ENABLED")?.unwrap_or(true),
                "metrics_rollup_enabled": flag("METRICS_ROLLUP_ENABLED")?.unwrap_or(true),
            }),
            email_auth: Settings::email_auth_enabled()?,
            basic,
            admin_root: admin_root(value("APP_ROOT_PATH", "")?.trim_end_matches('/'))?,
            start: Instant::now(),
            system: Arc::new(Mutex::new(system::Metrics::default())),
        }))
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/version", get(show).head(method_not_allowed))
            .route("/v1/version", get(show).head(method_not_allowed))
            .layer(middleware::map_response(private))
            .with_state(self.clone())
    }

    async fn payload(&self) -> Value {
        let system = self.system.clone();
        let (database, redis, system) = tokio::join!(
            self.database_info(),
            self.redis_info(),
            tokio::task::spawn_blocking(move || system.lock().expect("system metrics").sample()),
        );
        json!({
            "timestamp": Timestamp::now().to_string(),
            "host": sysinfo::System::host_name().unwrap_or_else(|| "localhost".into()),
            "uptime_seconds": self.start.elapsed().as_secs(),
            "app": {"name":self.app_name,"version":env!("CARGO_PKG_VERSION"),"mcp_protocol_version":self.protocol_version},
            "platform": {"runtime":"Rust","os":system::platform()},
            "database": database,
            "redis": redis,
            "settings": self.settings,
            "env": public_env(),
            "system": system.unwrap_or_else(|_| json!({})),
        })
    }

    async fn database_info(&self) -> Value {
        let (dialect, version) = match &self.database {
            Database::Sqlite(pool) => (
                "sqlite",
                sqlx::query_scalar::<_, String>("SELECT sqlite_version()")
                    .fetch_one(pool)
                    .await,
            ),
            Database::Postgres(pool) => (
                "postgresql",
                sqlx::query_scalar::<_, String>("SELECT current_setting('server_version')")
                    .fetch_one(pool)
                    .await,
            ),
        };
        json!({"dialect":dialect,"url":self.database_url,"reachable":version.is_ok(),
            "server_version":version.unwrap_or_else(|_| "Not reachable".into())})
    }

    async fn redis_info(&self) -> Value {
        let (reachable, version) = match &self.redis {
            Some(probe) => match probe.server_version().await {
                Some(version) => (true, Some(version)),
                None => (false, Some("Not reachable".into())),
            },
            None => (false, None),
        };
        json!({"available":true,"url":self.redis_url,"reachable":reachable,"server_version":version})
    }

    async fn authorize(
        &self,
        headers: &HeaderMap,
        peer: Option<SocketAddr>,
    ) -> Result<Option<Principal>, Box<Response>> {
        if let Some(passed) = self.basic_auth(headers) {
            return if passed {
                Ok(None)
            } else {
                Err(Box::new(self.authentication_required(headers, true)))
            };
        }
        if self.email_auth {
            let credential = match bearer(headers) {
                Ok(Some(token)) => Some((token, false)),
                Ok(None) => cookie(headers, "jwt_token").map(|token| (token, true)),
                Err(_) => None,
            };
            if let Some((token, session)) = credential {
                match self
                    .access
                    .authenticate(token, peer.map(|peer| peer.ip()), None)
                    .await
                {
                    Ok(principal) if !session || principal.token_use == TokenUse::Session => {
                        return if allowed(&principal) {
                            Ok(Some(principal))
                        } else {
                            Err(Box::new(self.admin_required(headers)))
                        };
                    }
                    Err(
                        error @ (AuthError::Storage(_)
                        | AuthError::TeamRevoked
                        | AuthError::Forbidden),
                    ) => {
                        return Err(Box::new(error.into_response()));
                    }
                    _ => {}
                }
            }
        }
        Err(Box::new(self.authentication_required(headers, false)))
    }

    fn basic_auth(&self, headers: &HeaderMap) -> Option<bool> {
        let mut fields = headers.get_all(header::AUTHORIZATION).iter();
        let (scheme, credential) = fields.next()?.to_str().ok()?.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        Some(
            fields.next().is_none()
                && self.basic.as_ref().is_some_and(|expected| {
                    let Ok(decoded) = STANDARD.decode(credential.trim()) else {
                        return false;
                    };
                    let decoded = Zeroizing::new(decoded);
                    decoded.is_ascii() && bool::from(Sha256::digest(&*decoded)[..].ct_eq(expected))
                }),
        )
    }

    fn authentication_required(&self, headers: &HeaderMap, basic: bool) -> Response {
        if self.email_auth {
            if wants_html(headers)
                || headers
                    .get("hx-request")
                    .is_some_and(|value| value == "true")
            {
                return self.login_redirect(None, "Authentication required");
            }
            return AuthError::ApiRequired(
                "Authentication required. Please login with email/password or use basic auth.",
            )
            .into_response();
        }
        if basic && self.basic.is_some() {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic")],
                Json(json!({"detail":"Invalid credentials"})),
            )
                .into_response();
        }
        let detail = if basic {
            "Basic authentication is disabled for API endpoints. Use JWT or API tokens instead."
        } else {
            "Authentication required"
        };
        AuthError::ApiRequired(detail).into_response()
    }

    fn admin_required(&self, headers: &HeaderMap) -> Response {
        if wants_html(headers) {
            self.login_redirect(Some("?error=admin_required"), "Admin privileges required")
        } else {
            (
                StatusCode::FORBIDDEN,
                Json(json!({"detail":"Admin privileges required"})),
            )
                .into_response()
        }
    }

    fn login_redirect(&self, suffix: Option<&str>, detail: &str) -> Response {
        let location = format!(
            "{}/admin/login{}",
            self.admin_root,
            suffix.unwrap_or_default()
        );
        (
            StatusCode::FOUND,
            [(header::LOCATION, location)],
            Json(json!({"detail":detail})),
        )
            .into_response()
    }
}

pub(crate) fn allowed(principal: &Principal) -> bool {
    principal.is_global_admin() && principal.token_allows(PERMISSION)
}

async fn private(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "GET")],
        Json(json!({"detail":"Method Not Allowed"})),
    )
        .into_response()
}

async fn show(State(state): State<Arc<Diagnostics>>, request: Request) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0);
    let principal = match state.authorize(request.headers(), peer).await {
        Ok(principal) => principal,
        Err(response) => return *response,
    };
    let started = Instant::now();
    let peer = peer.map(|address| address.ip().to_string());
    let reservation = match state
        .access
        .reserve_usage(
            principal.as_ref(),
            TokenRequest {
                endpoint: request.uri().path(),
                method: request.method().as_str(),
                peer: peer.as_deref(),
                agent: request
                    .headers()
                    .get(header::USER_AGENT)
                    .and_then(|value| value.to_str().ok()),
            },
        )
        .await
    {
        Ok(reservation) => reservation,
        Err(error) => return error.into_response(),
    };
    let response = match Query::<View>::try_from_uri(request.uri()) {
        Ok(Query(view)) => respond(&state, view, request.headers()).await,
        Err(_) => invalid_query(),
    };
    state
        .access
        .finish_usage(reservation, response.status(), started)
        .await;
    response
}

#[derive(Deserialize)]
struct View {
    fmt: Option<String>,
    partial: Option<String>,
}

async fn respond(state: &Diagnostics, view: View, headers: &HeaderMap) -> Response {
    let partial = match view
        .partial
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("1" | "on" | "t" | "true" | "y" | "yes") => true,
        None | Some("0" | "off" | "f" | "false" | "n" | "no") => false,
        _ => return invalid_query(),
    };
    let payload = state.payload().await;
    if partial || view.fmt.as_deref() == Some("html") || wants_html(headers) {
        render(payload, partial, &state.admin_root)
    } else {
        Json(payload).into_response()
    }
}

fn invalid_query() -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"detail":"Invalid diagnostics query"})),
    )
        .into_response()
}

fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/html"))
}

fn render(payload: Value, partial: bool, root: &str) -> Response {
    static ENVIRONMENT: OnceLock<Environment<'static>> = OnceLock::new();
    let environment = ENVIRONMENT.get_or_init(|| {
        let mut environment = Environment::new();
        environment.set_auto_escape_callback(|_| AutoEscape::Html);
        environment
            .add_template("diagnostics.html", include_str!("diagnostics.html"))
            .expect("valid diagnostics template");
        environment
    });
    match environment
        .get_template("diagnostics.html")
        .and_then(|template| template.render(context! { payload, partial, root }))
    {
        Ok(html) => Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "could not render diagnostics");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"detail":"Could not render diagnostics"})),
            )
                .into_response()
        }
    }
}

fn sanitize_url(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    if url.password().is_some() {
        url.set_password(None).ok()?;
    }
    url.set_query(None);
    url.set_fragment(None);
    Some(url.into())
}

fn public_env() -> BTreeMap<String, String> {
    const PUBLIC: &[&str] = &[
        "PORT",
        "HOST",
        "RELOAD",
        "LOG_LEVEL",
        "LOG_TO_FILE",
        "PLUGINS_ENABLED",
        "OBSERVABILITY_ENABLED",
        "AUTH_REQUIRED",
        "ALLOWED_ORIGINS",
    ];
    const SENSITIVE: &[&str] = &[
        "SECRET",
        "TOKEN",
        "PASS",
        "KEY",
        "HEADER",
        "CREDENTIAL",
        "AUTHORIZATION",
    ];
    std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            let upper = name.to_ascii_uppercase();
            if (upper.starts_with("MCPGATEWAY_")
                || upper.starts_with("MCP_")
                || PUBLIC.contains(&upper.as_str()))
                && !SENSITIVE.iter().any(|word| upper.contains(word))
            {
                let value = value.into_string().ok()?;
                let value = if upper.ends_with("_URL") {
                    sanitize_url(&value)?
                } else {
                    value
                };
                Some((name, value))
            } else {
                None
            }
        })
        .collect()
}
