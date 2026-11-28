// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use percent_encoding::percent_decode_str;
use regex::Regex;
use serde_json::json;

use crate::{
    access::Authorizer,
    config::{allowlist, flag, parse, value},
    database::Database,
    environment,
};

const WINDOW: Duration = Duration::from_secs(60);

mod events;
mod redis;

pub(super) struct RateLimiter {
    auth: Arc<Authorizer>,
    database: Database,
    identify_actor: bool,
    limits: [usize; 9],
    root: String,
    lockout: Option<Lockout>,
    memory: Mutex<Memory>,
    redis: Option<redis::RedisBuckets>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tier {
    Auth,
    Sso,
    Invitation,
    SessionRefresh,
    High,
    AppBridge,
    GatewayHandshake,
    Medium,
    Low,
}

impl Tier {
    fn detect(path: &str, method: &Method) -> Self {
        static RULES: LazyLock<Vec<(Regex, Tier, bool)>> = LazyLock::new(|| {
            [
                (
                    r"^/auth/email/(login|register|forgot-password|reset-password)$",
                    Tier::Auth,
                    false,
                ),
                (r"^/auth/sso(/|$)", Tier::Sso, false),
                (r"^/teams/[^/]+/invitations/?$", Tier::Invitation, true),
                (r"^/auth/refresh$", Tier::SessionRefresh, false),
                (r"^/(tokens|oauth|rbac)(/|$)", Tier::High, false),
                (r"^/appbridge/sessions(/|$)", Tier::AppBridge, false),
                (
                    r"^/gateways/test-handshake/?$",
                    Tier::GatewayHandshake,
                    true,
                ),
                (
                    r"^/(mcp|tools|prompts|resources|servers|gateways|llmchat)(/|$)",
                    Tier::Medium,
                    false,
                ),
            ]
            .map(|(pattern, tier, post)| {
                (Regex::new(pattern).expect("valid tier path"), tier, post)
            })
            .into()
        });
        RULES
            .iter()
            .find(|(pattern, _, post)| (!post || method == Method::POST) && pattern.is_match(path))
            .map_or(Self::Low, |(_, tier, _)| *tier)
    }

    fn name(self) -> &'static str {
        match self {
            Self::Auth => "CRITICAL",
            Self::Sso => "CRITICAL_SSO",
            Self::Invitation => "CRITICAL_INVITATION",
            Self::SessionRefresh => "SESSION_REFRESH",
            Self::High => "HIGH",
            Self::AppBridge => "HIGH_APPBRIDGE",
            Self::GatewayHandshake => "GATEWAY_HANDSHAKE",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

#[derive(Clone, Copy)]
struct Lockout {
    threshold: usize,
    minutes: u64,
}

impl Lockout {
    fn period(self) -> Duration {
        Duration::from_secs(self.minutes.saturating_mul(60))
    }
}

impl RateLimiter {
    pub(super) fn from_env(
        auth: Arc<Authorizer>,
        database: Database,
    ) -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        if !flag("RATE_LIMITING_ENABLED")?.unwrap_or(true) {
            return Ok(None);
        }
        let critical = parse("RATE_LIMIT_CRITICAL_RPM", 10)?;
        let high = parse("RATE_LIMIT_HIGH_RPM", 30)?;
        let medium = parse("RATE_LIMIT_MEDIUM_RPM", 100)?;
        let low = parse("RATE_LIMIT_LOW_RPM", 500)?;
        let refresh = parse("SESSION_REFRESH_RATE_LIMIT", 10)?;
        let lockout = if flag("RATE_LIMIT_LOCKOUT_ENABLED")?.unwrap_or(true) {
            Some(Lockout {
                threshold: parse("RATE_LIMIT_LOCKOUT_THRESHOLD", 5)?,
                minutes: parse("RATE_LIMIT_LOCKOUT_DURATION_MINUTES", 15)?,
            })
        } else {
            None
        };
        Ok(Some(Self {
            auth,
            database,
            identify_actor: flag("PASSWORD_CHANGE_ENFORCEMENT_ENABLED")?.unwrap_or(true)
                || flag("SECURITY_LOGGING_ENABLED")?.unwrap_or(false)
                || flag("MCPGATEWAY_ADMIN_API_ENABLED")?.unwrap_or(false)
                || flag("SIEM_EXPORT_ENABLED")?.unwrap_or(false)
                    && (environment::var_os("SIEM_EXPORT_EVENT_SOURCES").is_none()
                        || allowlist("SIEM_EXPORT_EVENT_SOURCES")?
                            .iter()
                            .any(|source| source.eq_ignore_ascii_case("auth"))),
            limits: [
                critical, critical, critical, refresh, high, high, critical, medium, low,
            ],
            root: value("APP_ROOT_PATH", "")?.trim_end_matches('/').to_owned(),
            lockout,
            memory: Mutex::new(Memory::default()),
            redis: redis::RedisBuckets::from_env()?,
        }))
    }

    pub(super) fn apply(self, router: Router) -> Router {
        router.layer(middleware::from_fn_with_state(Arc::new(self), limit))
    }

    fn effective_rate_path(&self, path: &str) -> String {
        let path = path
            .strip_prefix(&self.root)
            .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
            .unwrap_or(path);
        if matches!(path, "" | "/v1") {
            return "/".to_owned();
        }
        let Some(path) = path
            .strip_prefix("/v1")
            .filter(|suffix| suffix.starts_with('/'))
        else {
            return path.to_owned();
        };
        for (alias, canonical) in [
            ("/virtual-servers", "/servers"),
            ("/mcp-servers", "/gateways"),
        ] {
            if let Some(suffix) = path
                .strip_prefix(alias)
                .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
            {
                return format!("{canonical}{suffix}");
            }
        }
        path.to_owned()
    }
}

fn lockout_exempt(path: &str) -> bool {
    matches!(
        path.strip_prefix('/')
            .and_then(|suffix| suffix.split('/').next()),
        Some(
            "health"
                | "ready"
                | "live"
                | "metrics"
                | "version"
                | "docs"
                | "redoc"
                | "openapi.json"
                | "static"
        )
    )
}

#[derive(Default)]
struct Memory {
    buckets: HashMap<String, Bucket>,
    last_cleanup: Option<Instant>,
}

#[derive(Default)]
struct Bucket {
    requests: VecDeque<Instant>,
    violations: usize,
    violation_at: Option<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
enum Admission {
    Allowed(usize),
    Exceeded(u8),
    Locked(u8),
}

impl Memory {
    fn check(
        &mut self,
        keys: &[String],
        now: Instant,
        limit: usize,
        lockout: Option<Lockout>,
        violation_period: Duration,
    ) -> Admission {
        if self
            .last_cleanup
            .is_none_or(|last| now.duration_since(last) >= WINDOW)
        {
            self.buckets.retain(|_, bucket| {
                bucket
                    .requests
                    .back()
                    .is_some_and(|time| now.duration_since(*time) < WINDOW)
                    || bucket
                        .violation_at
                        .is_some_and(|time| now.duration_since(time) < violation_period)
            });
            self.last_cleanup = Some(now);
        }
        if let Some(lockout) = lockout {
            let mut locked = 0;
            for (index, key) in keys.iter().enumerate() {
                let bucket = self.buckets.get(key);
                let violations = bucket
                    .filter(|bucket| {
                        bucket
                            .violation_at
                            .is_some_and(|time| now.duration_since(time) < violation_period)
                    })
                    .map_or(0, |bucket| bucket.violations);
                if violations >= lockout.threshold {
                    locked |= 1 << index;
                }
            }
            if locked != 0 {
                return Admission::Locked(locked);
            }
        }
        let mut remaining = 0;
        let mut exceeded = 0;
        for (index, key) in keys.iter().enumerate() {
            let bucket = self.buckets.entry(key.clone()).or_default();
            while bucket
                .requests
                .front()
                .is_some_and(|time| now.duration_since(*time) >= WINDOW)
            {
                bucket.requests.pop_front();
            }
            if bucket.requests.len() >= limit {
                exceeded |= 1 << index;
                if lockout.is_some() {
                    if bucket
                        .violation_at
                        .is_none_or(|time| now.duration_since(time) >= violation_period)
                    {
                        bucket.violations = 0;
                    }
                    bucket.violations = bucket.violations.saturating_add(1);
                    bucket.violation_at = Some(now);
                }
                continue;
            }
            bucket.requests.push_back(now);
            if index == 0 {
                remaining = limit - bucket.requests.len();
            }
        }
        if exceeded != 0 {
            Admission::Exceeded(exceeded)
        } else {
            Admission::Allowed(remaining)
        }
    }
}

async fn limit(State(limiter): State<Arc<RateLimiter>>, request: Request, next: Next) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| peer.0.ip());
    let ip = peer.map_or_else(|| "unknown".to_owned(), |address| address.to_string());
    let endpoint = percent_decode_str(request.uri().path()).decode_utf8_lossy();
    let path = limiter.effective_rate_path(&endpoint);
    if path == "/ws"
        && request
            .headers()
            .get(header::UPGRADE)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
    {
        return next.run(request).await;
    }
    let tier = Tier::detect(&path, request.method());
    let limit = limiter.limits[tier as usize];
    let mut dimensions = vec![format!("ip:{ip}")];
    let actor = if limiter.identify_actor
        && !matches!(
            path.as_str(),
            "/health" | "/healthz" | "/ready" | "/metrics"
        )
        && !path.starts_with("/static/")
    {
        limiter
            .auth
            .rate_limit_identity(request.headers(), peer)
            .await
    } else {
        None
    };
    if let Some((user, team)) = &actor {
        dimensions.push(format!("user:{user}"));
        if let Some(team) = team {
            dimensions.push(format!("team:{team}"));
        }
    }
    let keys = dimensions
        .iter()
        .map(|dimension| format!("ratelimit:{dimension}:{}", tier.name()))
        .collect::<Vec<_>>();
    let lockout = limiter.lockout.filter(|_| !lockout_exempt(&path));
    let violation_period = limiter.lockout.map_or(Duration::ZERO, Lockout::period);
    let admission = match &limiter.redis {
        Some(redis) => redis.check(&keys, limit, lockout).await,
        None => None,
    }
    .unwrap_or_else(|| {
        limiter.memory.lock().expect("rate limit state").check(
            &keys,
            Instant::now(),
            limit,
            lockout,
            violation_period,
        )
    });
    let (locked, denied) = match admission {
        Admission::Allowed(remaining) => {
            let mut response = next.run(request).await;
            set_number(response.headers_mut(), "x-ratelimit-limit", limit);
            set_number(response.headers_mut(), "x-ratelimit-remaining", remaining);
            return response;
        }
        Admission::Exceeded(denied) => (false, denied),
        Admission::Locked(denied) => (true, denied),
    };
    tracing::warn!(%ip, %path, tier = tier.name(), locked, "rate limit exceeded");
    let event = events::RateLimitEvent {
        ip: &ip,
        endpoint: &endpoint,
        method: request.method().as_str(),
        team: actor.as_ref().and_then(|(_, team)| team.as_deref()),
        tier,
        limit,
        locked,
    };
    for (index, dimension) in dimensions.iter().enumerate() {
        if denied & (1 << index) != 0
            && let Err(error) = event.record(&limiter.database, dimension).await
        {
            tracing::warn!(%error, "could not persist rate-limit security event");
        }
    }
    rejected(tier, limit, lockout.filter(|_| locked))
}

fn rejected(tier: Tier, limit: usize, lockout: Option<Lockout>) -> Response {
    let (body, retry) = if let Some(lockout) = lockout {
        let retry = lockout.period().as_secs();
        (
            json!({
                "error": "Rate limit lockout",
                "message": format!("Too many rate limit violations. Requests to {} tier endpoints are blocked for {} minutes.", tier.name(), lockout.minutes),
                "lockout_duration_minutes": lockout.minutes,
                "reset_in_seconds": retry,
            }),
            retry,
        )
    } else {
        (
            json!({
                "error": "Rate limit exceeded",
                "message": format!("Maximum {limit} requests per minute for {} tier endpoints.", tier.name()),
                "limit": limit,
                "reset_in_seconds": WINDOW.as_secs(),
            }),
            WINDOW.as_secs(),
        )
    };
    let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::RETRY_AFTER, HeaderValue::from(retry));
    set_number(headers, "x-ratelimit-limit", limit);
    set_number(headers, "x-ratelimit-remaining", 0_usize);
    let reset = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(WINDOW);
    set_number(headers, "x-ratelimit-reset", reset.as_secs());
    if lockout.is_some() {
        set_number(headers, "x-lockout-remaining", retry);
    }
    response
}

fn set_number(
    headers: &mut axum::http::HeaderMap,
    name: &'static str,
    value: impl Into<HeaderValue>,
) {
    headers.insert(name, value.into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_outlives_the_request_window_and_stays_with_its_tier() {
        let now = Instant::now();
        let lockout = Lockout {
            threshold: 1,
            minutes: 7,
        };
        let mut memory = Memory::default();
        let medium = ["ratelimit:ip:192.0.2.1:MEDIUM".to_owned()];
        let low = ["ratelimit:ip:192.0.2.1:LOW".to_owned()];
        let check = |memory: &mut Memory, keys: &[String], offset: Duration| {
            memory.check(keys, now + offset, 1, Some(lockout), lockout.period())
        };
        assert_eq!(
            check(&mut memory, &medium, Duration::ZERO),
            Admission::Allowed(0)
        );
        assert_eq!(
            check(&mut memory, &medium, Duration::ZERO),
            Admission::Exceeded(1)
        );
        assert_eq!(check(&mut memory, &medium, WINDOW), Admission::Locked(1));
        assert_eq!(check(&mut memory, &low, WINDOW), Admission::Allowed(0));
        assert_eq!(
            check(&mut memory, &medium, lockout.period()),
            Admission::Allowed(0)
        );
    }
}
