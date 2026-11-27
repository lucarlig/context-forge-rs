// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::CONNECTION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use serde_json::json;
use tracing::Instrument;
use uuid::Uuid;

use crate::config::{flag, parse, value};

pub struct HttpBoundary {
    header_limits: Option<HeaderLimits>,
    correlation: Option<Correlation>,
}

impl HttpBoundary {
    pub fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
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
        })
    }

    pub fn apply(self, mut router: Router) -> Router {
        if let Some(limits) = self.header_limits {
            router = router.layer(middleware::from_fn_with_state(limits, limit_headers));
        }
        if let Some(correlation) = self.correlation {
            router = router.layer(middleware::from_fn_with_state(correlation, correlate));
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
struct Correlation {
    name: HeaderName,
    preserve: bool,
    respond: bool,
}

async fn correlate(State(settings): State<Correlation>, request: Request, next: Next) -> Response {
    let incoming = request
        .headers()
        .get(&settings.name)
        .filter(|_| settings.preserve)
        .map(|value| value.as_bytes().trim_ascii())
        .filter(|value| !value.is_empty())
        .and_then(|value| HeaderValue::from_bytes(value).ok());
    let id = incoming.unwrap_or_else(|| {
        HeaderValue::from_str(&Uuid::new_v4().simple().to_string()).expect("UUID is ASCII")
    });
    let span = tracing::info_span!("request", request_id = ?id, method = %request.method());
    let mut response = next.run(request).instrument(span).await;
    if settings.respond {
        response.headers_mut().insert(settings.name, id);
    }
    response
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, body::to_bytes, routing::get};
    use tower::ServiceExt;

    use super::*;

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
