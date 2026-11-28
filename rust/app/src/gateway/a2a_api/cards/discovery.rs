// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::sync::LazyLock;

use url::Url;

use super::{document, *};
use crate::upstream::read_bounded_body;

const MAX_CARD_BYTES: usize = 1024 * 1024;
const MAX_HEADERS: usize = 20;
const MAX_HEADER_BYTES: usize = 8192;
const MODERN_PATH: &str = "/.well-known/agent-card.json";
const LEGACY_PATH: &str = "/.well-known/agent.json";

pub(super) struct CardDocument {
    pub(super) normalized: Value,
    pub(super) raw: Option<Value>,
    pub(super) version: &'static str,
    pub(super) source: Url,
    pub(super) etag: Option<String>,
    pub(super) max_age: Option<i32>,
}

pub(in crate::gateway::a2a_api) struct FoundCard {
    pub(super) public: CardDocument,
    pub(super) extended: Option<Result<CardDocument, ExtendedFailure>>,
}

pub(super) enum ExtendedFailure {
    AuthRejected,
    Unavailable,
}

pub(super) enum FetchFailure {
    NoCard,
    AuthRequired(Option<String>),
    Unreachable,
}

pub(super) fn base_url(input: &str) -> Result<Url, CatalogApiError> {
    Url::parse(input.trim())
        .ok()
        .filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.as_str().len() <= 2048
        })
        .ok_or_else(|| invalid("Invalid Agent Card base URL"))
}

pub(super) fn headers(input: BTreeMap<String, String>) -> Result<HeaderMap, CatalogApiError> {
    if input.len() > MAX_HEADERS {
        return Err(invalid("Too many or too large headers"));
    }
    let mut headers = HeaderMap::new();
    for (name, value) in input {
        let value = Zeroizing::new(value);
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid("Invalid header name"))?;
        let value = HeaderValue::from_str(&value).map_err(|_| invalid("Invalid header value"))?;
        if headers.insert(name, value).is_some() {
            return Err(invalid("Invalid header name"));
        }
    }
    Ok(headers)
}

fn validate_headers(headers: &HeaderMap) -> Result<(), CatalogApiError> {
    if headers.len() > MAX_HEADERS
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>()
            > MAX_HEADER_BYTES
    {
        return Err(invalid("Too many or too large headers"));
    }
    for name in headers.keys() {
        if matches!(
            name.as_str(),
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "upgrade"
                | "te"
                | "trailer"
                | "keep-alive"
                | "expect"
                | "accept-encoding"
        ) || name.as_str().starts_with("proxy-")
        {
            return Err(invalid("Invalid header name"));
        }
    }
    Ok(())
}

pub(super) async fn fetch(
    app: &GatewayService,
    base: Url,
    path: Option<&str>,
    headers: &HeaderMap,
) -> Result<Result<FoundCard, FetchFailure>, CatalogApiError> {
    validate_headers(headers)?;
    let candidates = candidates(base, path)?;
    let timeout = app.a2a_card_timeout;
    let upstream = app.upstream.with_timeout(timeout);
    let public = tokio::time::timeout(timeout, search(&upstream, candidates, headers))
        .await
        .unwrap_or(Err(FetchFailure::Unreachable));
    let public = match public {
        Ok(card) => card,
        Err(error) => return Ok(Err(error)),
    };
    let extended = if !headers.is_empty()
        && public.normalized["capabilities"]["extendedAgentCard"].as_bool() == Some(true)
    {
        Some(
            tokio::time::timeout(timeout, extended(&upstream, &public, headers))
                .await
                .unwrap_or(Err(ExtendedFailure::Unavailable)),
        )
    } else {
        None
    };
    Ok(Ok(FoundCard { public, extended }))
}

fn candidates(base: Url, path: Option<&str>) -> Result<Vec<Url>, CatalogApiError> {
    let append = |suffix: &str| {
        let mut candidate = base.clone();
        let new_path = format!(
            "{}/{}",
            base.path().trim_end_matches('/'),
            suffix.trim_start_matches('/')
        );
        candidate.set_path(&new_path);
        candidate
    };
    if let Some(path) = path.filter(|path| !path.is_empty()) {
        if !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~!$&'()*+,;=:@/-".contains(&byte))
            || path.split('/').any(|segment| matches!(segment, "." | ".."))
        {
            return Err(invalid("Card path is not allowed"));
        }
        return Ok(vec![append(path)]);
    }
    if base.path().to_ascii_lowercase().ends_with(".json") {
        return Ok(vec![base]);
    }
    Ok(vec![append(MODERN_PATH), append(LEGACY_PATH)])
}

async fn search(
    upstream: &UpstreamClient,
    candidates: Vec<Url>,
    headers: &HeaderMap,
) -> Result<CardDocument, FetchFailure> {
    for url in candidates {
        let response = read(upstream, &url, headers, None)
            .await
            .map_err(|_| FetchFailure::Unreachable)?;
        if response.auth_required() {
            return Err(FetchFailure::AuthRequired(response.challenge));
        }
        if let Some(raw) = response.document
            && let Some(card) = from_wire(raw, url, response.etag, response.max_age)
        {
            return Ok(card);
        }
    }
    Err(FetchFailure::NoCard)
}

async fn extended(
    upstream: &UpstreamClient,
    card: &CardDocument,
    headers: &HeaderMap,
) -> Result<CardDocument, ExtendedFailure> {
    let interface = document::interface(&card.normalized).ok_or(ExtendedFailure::Unavailable)?;
    if !document::json_rpc(interface) {
        return Err(ExtendedFailure::Unavailable);
    }
    let url = Url::parse(interface["url"].as_str().unwrap_or_default())
        .map_err(|_| ExtendedFailure::Unavailable)?;
    if url.origin() != card.source.origin() {
        return Err(ExtendedFailure::Unavailable);
    }
    let method = if interface["protocolVersion"]
        .as_str()
        .is_some_and(|version| version.starts_with("0."))
    {
        "agent/getAuthenticatedExtendedCard"
    } else {
        "GetExtendedAgentCard"
    };
    let body = json!({"jsonrpc":"2.0","id":"1","method":method,"params":{}});
    let response = read(upstream, &url, headers, Some(body))
        .await
        .map_err(|_| ExtendedFailure::Unavailable)?;
    if response.auth_required() {
        return Err(ExtendedFailure::AuthRejected);
    }
    let mut root = response.document.ok_or(ExtendedFailure::Unavailable)?;
    let raw = root
        .get_mut("result")
        .map(Value::take)
        .ok_or(ExtendedFailure::Unavailable)?;
    from_wire(raw, url, response.etag, response.max_age).ok_or(ExtendedFailure::Unavailable)
}

fn from_wire(
    raw: Value,
    source: Url,
    etag: Option<String>,
    max_age: Option<i32>,
) -> Option<CardDocument> {
    let legacy = document::validate(&raw)?;
    let (normalized, raw, version) = if legacy {
        (document::normalize_legacy(&raw), Some(raw), "0.3")
    } else {
        (raw, None, "1.0")
    };
    Some(CardDocument {
        normalized,
        raw,
        version,
        source,
        etag,
        max_age,
    })
}

struct CardResponse {
    status: StatusCode,
    document: Option<Value>,
    challenge: Option<String>,
    etag: Option<String>,
    max_age: Option<i32>,
}

impl CardResponse {
    fn auth_required(&self) -> bool {
        matches!(
            self.status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        )
    }
}

async fn read(
    upstream: &UpstreamClient,
    target: &Url,
    headers: &HeaderMap,
    payload: Option<Value>,
) -> Result<CardResponse, UpstreamError> {
    let (client, url) = upstream.pinned_client(target.as_str(), None).await?;
    let mut builder = if let Some(payload) = payload {
        client
            .post(url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(payload.to_string())
    } else {
        client.get(url)
    };
    if !headers.contains_key(header::ACCEPT) {
        builder = builder.header(header::ACCEPT, "application/json");
    }
    let request = builder
        .header(header::ACCEPT_ENCODING, "identity")
        .headers(headers.clone())
        .build()?;
    let response = crate::observability::telemetry::client::execute(&client, request).await?;
    let headers = response.headers();
    let mut result = CardResponse {
        status: response.status(),
        document: None,
        challenge: headers.get(header::WWW_AUTHENTICATE).and_then(challenge),
        etag: headers
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        max_age: max_age(headers),
    };
    if result.status == StatusCode::OK
        && headers
            .get_all(header::CONTENT_ENCODING)
            .iter()
            .all(|encoding| {
                encoding.to_str().is_ok_and(|encoding| {
                    encoding.trim().is_empty() || encoding.trim().eq_ignore_ascii_case("identity")
                })
            })
    {
        match read_bounded_body(response, MAX_CARD_BYTES).await {
            Ok(bytes) => result.document = serde_json::from_slice(&bytes).ok(),
            Err(UpstreamError::LimitExceeded) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(result)
}

fn challenge(value: &HeaderValue) -> Option<String> {
    let scheme = value.to_str().ok()?.split_ascii_whitespace().next()?;
    (scheme.len() <= 32 && HeaderName::from_bytes(scheme.as_bytes()).is_ok())
        .then(|| scheme.to_owned())
}

fn max_age(headers: &HeaderMap) -> Option<i32> {
    static MAX_AGE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?i)(?:^|[,\s])max-age=([0-9]+)")
            .expect("valid cache directive pattern")
    });
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .find_map(|value| {
            MAX_AGE
                .captures(value.to_str().ok()?)?
                .get(1)?
                .as_str()
                .parse()
                .ok()
        })
}

pub(super) fn wire(result: Result<FoundCard, FetchFailure>) -> Value {
    let mut response = json!({
        "found":false, "outcome":"no_card", "reason":null, "authScheme":null,
        "sourceUrl":null, "detectedVersion":null, "card":null, "rawCard":null,
        "suggestedAgent":null, "warnings":[], "etag":null, "maxAge":null,
        "extendedOutcome":null, "extendedCard":null, "extendedRawCard":null,
        "extendedEtag":null, "extendedMaxAge":null, "extendedAdditions":[],
    });
    let found = match result {
        Ok(found) => found,
        Err(failure) => {
            let (outcome, reason) = match failure {
                FetchFailure::NoCard => (
                    "no_card",
                    "No A2A Agent Card was found at the given location.",
                ),
                FetchFailure::AuthRequired(scheme) => {
                    response["authScheme"] = json!(scheme);
                    (
                        "auth_required",
                        "The agent requires credentials to return its Agent Card.",
                    )
                }
                FetchFailure::Unreachable => ("unreachable", "The agent could not be reached."),
            };
            response["outcome"] = json!(outcome);
            response["reason"] = json!(reason);
            return response;
        }
    };
    let (suggestion, warnings) = document::suggest(&found.public.normalized);
    response["found"] = json!(true);
    response["outcome"] = json!("found");
    response["sourceUrl"] = json!(found.public.source.as_str());
    response["detectedVersion"] = json!(found.public.version);
    response["suggestedAgent"] = suggestion;
    response["warnings"] = json!(warnings);
    response["etag"] = json!(found.public.etag);
    response["maxAge"] = json!(found.public.max_age);
    if let Some(extended) = found.extended {
        response["extendedOutcome"] = match extended {
            Ok(card) => {
                response["extendedAdditions"] = json!(document::additions(
                    &found.public.normalized,
                    &card.normalized
                ));
                response["extendedCard"] = card.normalized;
                response["extendedRawCard"] = json!(card.raw);
                response["extendedEtag"] = json!(card.etag);
                response["extendedMaxAge"] = json!(card.max_age);
                json!("found")
            }
            Err(ExtendedFailure::AuthRejected) => json!("auth_rejected"),
            Err(ExtendedFailure::Unavailable) => json!("unavailable"),
        };
    }
    response["card"] = found.public.normalized;
    response["rawCard"] = json!(found.public.raw);
    response
}

fn invalid(message: &'static str) -> CatalogApiError {
    CatalogApiError::detail(StatusCode::UNPROCESSABLE_ENTITY, message)
}
