// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, future::Future, pin::pin, sync::Arc};

use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::CONNECTION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    serve::Listener,
};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use serde_json::json;
use tokio::net::TcpListener;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower::ServiceBuilder;
use tracing::Instrument;
use uuid::Uuid;

use crate::{
    access::Authorizer,
    config::{flag, parse, value},
    database::Database,
};

mod compression;
pub(crate) mod csrf;
mod proxy;
mod rate_limit;
mod response_policy;

pub(crate) use proxy::public_scheme;
pub(crate) use response_policy::allowed_origins;

// HeaderMap can hold 24,576 distinct names at its largest table capacity.
const HTTP1_HEADER_CAPACITY: usize = 24_576;

pub struct HttpBoundary {
    header_limits: Option<HeaderLimits>,
    correlation: Option<Correlation>,
    proxies: proxy::ProxyHeaders,
    responses: response_policy::ResponsePolicy,
    rate_limiter: Option<rate_limit::RateLimiter>,
    csrf: Option<csrf::Csrf>,
}

impl HttpBoundary {
    pub fn from_env(
        port: u16,
        auth: Arc<Authorizer>,
        database: Database,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let header_limits = if flag("HEADER_SIZE_VALIDATION_ENABLED")?.unwrap_or(true) {
            Some(HeaderLimits {
                total: parse("MAX_HEADER_TOTAL_SIZE_BYTES", 16_384)?,
                field: parse("MAX_HEADER_FIELD_SIZE_BYTES", 8_192)?,
                count: parse("MAX_HEADER_COUNT", 100)?,
            })
        } else {
            None
        };
        let correlation = if flag("CORRELATION_ID_ENABLED")?.unwrap_or(true) {
            let name = value("CORRELATION_ID_HEADER", "X-Correlation-ID")?;
            Some(Correlation {
                name: HeaderName::try_from(name).map_err(|_| "invalid CORRELATION_ID_HEADER")?,
                preserve: flag("CORRELATION_ID_PRESERVE")?.unwrap_or(true),
                respond: flag("CORRELATION_ID_RESPONSE_HEADER")?.unwrap_or(true),
            })
        } else {
            None
        };
        Ok(Self {
            header_limits,
            correlation,
            proxies: proxy::ProxyHeaders::from_env()?,
            responses: response_policy::ResponsePolicy::from_env(port)?,
            csrf: csrf::Csrf::from_env(auth.clone())?,
            rate_limiter: rate_limit::RateLimiter::from_env(auth, database)?,
        })
    }

    pub async fn serve(
        self,
        mut listener: TcpListener,
        router: Router,
        shutdown: CancellationToken,
    ) {
        let count = self.header_limits.map_or(HTTP1_HEADER_CAPACITY, |limits| {
            // Let the middleware describe ordinary excess counts in its JSON response.
            limits
                .count
                .max(100)
                .saturating_add(1)
                .min(HTTP1_HEADER_CAPACITY)
        });
        let mut http = http1::Builder::new();
        http.max_headers(count).timer(TokioTimer::new());
        let app = self.apply(router);
        let connections = TaskTracker::new();
        loop {
            let (socket, address) = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                accepted = Listener::accept(&mut listener) => accepted,
            };
            let service = ServiceBuilder::new()
                .layer(Extension(ConnectInfo(address)))
                .service(app.clone());
            let connection = http
                .serve_connection(TokioIo::new(socket), TowerToHyperService::new(service))
                .with_upgrades();
            let stop = shutdown.clone();
            connections.spawn(async move {
                let mut connection = pin!(connection);
                let result = tokio::select! {
                    result = connection.as_mut() => result,
                    () = stop.cancelled() => {
                        connection.as_mut().graceful_shutdown();
                        connection.await
                    }
                };
                if let Err(error) = result {
                    tracing::trace!(%error, "HTTP connection closed with an error");
                }
            });
        }
        drop(listener);
        connections.close();
        connections.wait().await;
    }

    fn apply(self, mut router: Router) -> Router {
        router = self.responses.apply(router);
        if let Some(limits) = self.header_limits {
            router = router.layer(middleware::from_fn_with_state(limits, limit_headers));
        }
        if let Some(limiter) = self.rate_limiter {
            router = limiter.apply(router);
        }
        router = self.proxies.apply(router);
        if let Some(correlation) = self.correlation {
            router = router.layer(middleware::from_fn_with_state(correlation, correlate));
        }
        if let Some(csrf) = self.csrf {
            router = csrf.apply(router);
        }
        router
    }
}

#[derive(Clone, Copy)]
struct HeaderLimits {
    total: usize,
    field: usize,
    count: usize,
}

impl HeaderLimits {
    fn rejection(self, headers: &HeaderMap) -> Option<Response> {
        let count = headers.len();
        if count > self.count {
            return Some(self.reject(
                "header_count",
                format!("Too many header fields ({count} > {})", self.count),
                None,
            ));
        }
        let mut total = 0;
        for (name, value) in headers {
            let size = name.as_str().len() + value.len() + 2;
            if size > self.field {
                return Some(self.reject(
                    "field_size",
                    format!(
                        "Header field '{name}' exceeds maximum size ({size} > {} bytes)",
                        self.field
                    ),
                    Some(name),
                ));
            }
            total += size;
        }
        (total > self.total).then(|| {
            self.reject(
                "total_size",
                format!(
                    "Total header size exceeds maximum ({total} > {} bytes)",
                    self.total
                ),
                None,
            )
        })
    }

    fn reject(self, violation_type: &str, message: String, field: Option<&HeaderName>) -> Response {
        tracing::warn!(violation_type, %message, "request header limit exceeded");
        let mut body = json!({
            "error": "Request Header Fields Too Large",
            "message": message,
            "violation_type": violation_type,
            "limits": {
                "max_total_size_bytes": self.total,
                "max_field_size_bytes": self.field,
                "max_header_count": self.count,
            },
        });
        if let Some(field) = field {
            body["field_name"] = json!(field.as_str());
        }
        (
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            [(CONNECTION, HeaderValue::from_static("close"))],
            Json(body),
        )
            .into_response()
    }
}

async fn limit_headers(
    State(limits): State<HeaderLimits>,
    request: Request,
    next: Next,
) -> Response {
    match limits.rejection(request.headers()) {
        Some(response) => response,
        None => next.run(request).await,
    }
}

#[derive(Clone)]
pub(crate) struct Correlation {
    name: HeaderName,
    preserve: bool,
    respond: bool,
}

impl Correlation {
    pub(crate) fn resolve(&self, headers: &HeaderMap) -> CorrelationId {
        let incoming = headers
            .get(&self.name)
            .filter(|_| self.preserve)
            .map(|value| value.as_bytes().trim_ascii())
            .filter(|value| !value.is_empty())
            .and_then(|value| HeaderValue::from_bytes(value).ok());
        CorrelationId(incoming.unwrap_or_else(|| {
            HeaderValue::from_str(&Uuid::new_v4().simple().to_string()).expect("UUID is ASCII")
        }))
    }
}

#[derive(Clone)]
pub(crate) struct CorrelationId(HeaderValue);

tokio::task_local! {
    static REQUEST_ID: Option<CorrelationId>;
}

impl CorrelationId {
    pub(crate) fn current() -> Option<Self> {
        REQUEST_ID.try_with(Clone::clone).ok().flatten()
    }

    pub(crate) fn write_header(self, headers: &mut HeaderMap) {
        headers.insert("x-correlation-id", self.0);
    }
}

pub(crate) fn with_correlation<T>(
    id: Option<CorrelationId>,
    operation: impl Future<Output = T>,
) -> impl Future<Output = T> {
    REQUEST_ID.scope(id, operation)
}

async fn correlate(
    State(settings): State<Correlation>,
    mut request: Request,
    next: Next,
) -> Response {
    let correlation = settings.resolve(request.headers());
    let id = correlation.0.clone();
    request.extensions_mut().insert(settings.clone());
    request.extensions_mut().insert(correlation.clone());
    let span = tracing::info_span!("request", request_id = ?id, method = %request.method());
    let mut response =
        with_correlation(Some(correlation), next.run(request).instrument(span)).await;
    if settings.respond && response.status() != StatusCode::SWITCHING_PROTOCOLS {
        response.headers_mut().insert(settings.name, id);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, body::to_bytes, routing::get};
    use std::net::SocketAddr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn configured_header_count_reaches_the_gateway_over_http() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        let boundary = HttpBoundary {
            header_limits: Some(HeaderLimits {
                total: 16_384,
                field: 8_192,
                count: 120,
            }),
            correlation: None,
            proxies: proxy::ProxyHeaders::parse("").unwrap(),
            responses: response_policy::ResponsePolicy::from_env(4444).unwrap(),
            rate_limiter: None,
            csrf: None,
        };
        let router = Router::new().route(
            "/",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
        );
        let gateway = tokio::spawn(boundary.serve(listener, router, stop.clone()));

        async fn response(address: SocketAddr, count: usize) -> String {
            let mut request =
                "GET / HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n".to_owned();
            for index in 0..count - 2 {
                request.push_str(&format!("X-Fixture-{index}: 1\r\n"));
            }
            request.push_str("\r\n");
            let mut socket = TcpStream::connect(address).await.unwrap();
            socket.write_all(request.as_bytes()).await.unwrap();
            let mut response = String::new();
            socket.read_to_string(&mut response).await.unwrap();
            response
        }

        let accepted = response(address, 120).await;
        assert!(accepted.starts_with("HTTP/1.1 200") && accepted.ends_with("127.0.0.1"));
        let rejected = response(address, 121).await;
        assert!(rejected.starts_with("HTTP/1.1 431"));
        assert!(rejected.contains("Too many header fields (121 > 120)"));

        stop.cancel();
        gateway.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_duplicate_fields_before_dispatch_with_the_request_id() {
        let router = HttpBoundary {
            header_limits: Some(HeaderLimits {
                total: 100,
                field: 40,
                count: 2,
            }),
            correlation: Some(Correlation {
                name: HeaderName::from_static("x-correlation-id"),
                preserve: true,
                respond: true,
            }),
            proxies: proxy::ProxyHeaders::parse("").unwrap(),
            responses: response_policy::ResponsePolicy::from_env(4444).unwrap(),
            rate_limiter: None,
            csrf: None,
        }
        .apply(Router::new().route("/", get(|| async { StatusCode::UNAUTHORIZED })));
        let request = || {
            Request::builder()
                .header("x-correlation-id", "fixture")
                .header("x-repeat", "first")
        };
        let response = router
            .clone()
            .oneshot(request().body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = router
            .oneshot(
                request()
                    .header("x-repeat", "second")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        assert_eq!(response.headers()["x-correlation-id"], "fixture");
        assert_eq!(response.headers()[CONNECTION], "close");
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["violation_type"], "header_count");
        assert_eq!(body["message"], "Too many header fields (3 > 2)");
    }
}
