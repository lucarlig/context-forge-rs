// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use axum::{
    Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Uri, header::HOST, uri::Authority},
    middleware::{self, Next},
    response::Response,
};
use ipnet::IpNet;

use crate::config::value;

pub(super) struct ProxyHeaders {
    networks: Vec<IpNet>,
    trust_all: bool,
}

impl ProxyHeaders {
    pub(super) fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        Self::parse(&value("FORWARDED_ALLOW_IPS", "127.0.0.1,::1")?)
    }

    pub(super) fn parse(raw: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
        if raw.trim() == "*" {
            return Ok(Self {
                networks: Vec::new(),
                trust_all: true,
            });
        }
        let mut networks = Vec::new();
        for entry in raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let network = if let Ok(address) = entry.parse::<IpAddr>() {
                IpNet::from(address)
            } else {
                entry
                    .parse::<IpNet>()
                    .ok()
                    .filter(|net| net.addr() == net.network())
                    .ok_or_else(|| format!("invalid FORWARDED_ALLOW_IPS entry {entry:?}"))?
            };
            networks.push(network);
        }
        Ok(Self {
            networks,
            trust_all: false,
        })
    }

    pub(super) fn apply(self, router: Router) -> Router {
        router.layer(middleware::from_fn_with_state(Arc::new(self), forwarded))
    }

    fn trusts(&self, address: IpAddr) -> bool {
        self.trust_all
            || self
                .networks
                .iter()
                .any(|network| network.contains(&address))
    }

    fn client_address(&self, headers: &HeaderMap) -> Option<SocketAddr> {
        let values = headers.get_all("x-forwarded-for");
        let mut addresses = values
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|line| line.split(',').map(str::trim))
            .map(parse_address);
        let first = addresses.next()?;
        if self.trust_all {
            return first;
        }
        addresses
            .rev()
            .find(|address| address.is_none_or(|address| !self.trusts(address.ip())))
            .unwrap_or(first)
    }
}

async fn forwarded(
    State(policy): State<Arc<ProxyHeaders>>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(authority) = request
        .headers()
        .get("x-forwarded-host")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .and_then(parse_authority)
        && let Ok(value) = HeaderValue::from_str(authority.as_str())
    {
        request.headers_mut().insert(HOST, value);
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied();
    if peer.is_some_and(|peer| policy.trusts(peer.0.ip())) {
        if let Some(address) = policy.client_address(request.headers()) {
            request.extensions_mut().insert(ConnectInfo(address));
        }
        if let Some(scheme) = request
            .headers()
            .get_all("x-forwarded-proto")
            .iter()
            .next_back()
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| matches!(*value, "http" | "https"))
            && let Some(authority) = request
                .headers()
                .get(HOST)
                .and_then(|host| host.to_str().ok())
                .and_then(parse_authority)
                .or_else(|| request.uri().authority().cloned())
            && let Some(path) = request.uri().path_and_query()
            && let Ok(uri) = Uri::builder()
                .scheme(scheme)
                .authority(authority)
                .path_and_query(path.clone())
                .build()
        {
            *request.uri_mut() = uri;
        }
    }
    next.run(request).await
}

pub(crate) fn public_scheme(headers: &HeaderMap, uri: &Uri) -> &'static str {
    let forwarded = headers
        .get("x-forwarded-proto")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.split(',').next())
        .map(str::trim);
    match forwarded {
        Some(value) if value.eq_ignore_ascii_case("https") => "https",
        Some(value) if value.eq_ignore_ascii_case("http") => "http",
        _ if uri.scheme_str() == Some("https") => "https",
        _ => "http",
    }
}

fn parse_address(value: &str) -> Option<SocketAddr> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Some(SocketAddr::new(address, 0));
    }
    if let Some(address) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        return address
            .parse::<Ipv6Addr>()
            .ok()
            .map(|address| SocketAddr::new(address.into(), 0));
    }
    value.parse().ok()
}

fn parse_authority(value: &str) -> Option<Authority> {
    if let Ok(ip) = value.parse::<Ipv6Addr>() {
        return format!("[{ip}]").parse().ok();
    }
    let authority = value.parse::<Authority>().ok()?;
    let host = authority.host();
    if host.is_empty()
        || value.contains('@')
        || value.len() > host.len() && authority.port_u16().is_none_or(|port| port == 0)
    {
        return None;
    }
    if let Some(address) = host.strip_prefix('[') {
        address.strip_suffix(']')?.parse::<Ipv6Addr>().ok()?;
    }
    Some(authority)
}

#[cfg(test)]
mod tests {
    use axum::{Extension, body::Body, body::to_bytes, routing::get};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn only_trusted_peers_set_client_address_and_request_scheme() {
        async fn request(policy: &str) -> String {
            let handler = |ConnectInfo(client): ConnectInfo<SocketAddr>, uri: Uri| async move {
                format!("{client} {}", uri.scheme_str().unwrap_or("http"))
            };
            let peer = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
            let app = ProxyHeaders::parse(policy)
                .unwrap()
                .apply(Router::new().route("/", get(handler)))
                .layer(Extension(ConnectInfo(peer)));
            let request = Request::builder()
                .uri("/")
                .header(HOST, "fixture.test")
                .header("x-forwarded-for", "192.0.2.100, 198.51.100.5")
                .header("x-forwarded-for", "10.0.0.1")
                .header("x-forwarded-proto", "https")
                .body(Body::empty())
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            let body = to_bytes(response.into_body(), 100).await.unwrap();
            String::from_utf8(body.to_vec()).unwrap()
        }

        assert_eq!(request("10.0.0.0/8").await, "127.0.0.1:8080 http");
        assert_eq!(
            request("127.0.0.1,10.0.0.0/8").await,
            "198.51.100.5:0 https"
        );
        assert_eq!(request("*").await, "192.0.2.100:0 https");
        assert!(ProxyHeaders::parse("10.0.0.3/8").is_err());
    }
}
