// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, net::IpAddr};

use axum::http::{HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha384};
use url::{Host, Url};

pub(crate) const HOP_HEADER: &str = "x-contextforge-uaid-hop";

pub struct UaidSettings {
    domains: Vec<Authority>,
    pub(crate) allow_all_domains: bool,
    pub(crate) forward_auth: bool,
    pub(crate) max_length: usize,
    pub(crate) max_hops: u32,
}

impl Default for UaidSettings {
    fn default() -> Self {
        Self {
            domains: Vec::new(),
            allow_all_domains: false,
            forward_auth: true,
            max_length: 2048,
            max_hops: 5,
        }
    }
}

impl UaidSettings {
    pub(crate) fn configure(
        &mut self,
        domains: HashSet<String>,
        require_domains: bool,
    ) -> Result<(), &'static str> {
        self.domains = domains
            .iter()
            .map(|domain| {
                let authority = Authority::parse(domain)
                    .filter(Authority::public)
                    .ok_or("Invalid UAID_ALLOWED_DOMAINS entry")?;
                Ok(authority)
            })
            .collect::<Result<_, &'static str>>()?;
        if !(512..=2048).contains(&self.max_length) || !(1..=10).contains(&self.max_hops) {
            return Err("Invalid UAID length or federation hop limit");
        }
        if self.domains.is_empty() && !self.allow_all_domains && require_domains {
            return Err("UAID_ALLOWED_DOMAINS must contain a trusted domain");
        }
        Ok(())
    }

    pub(crate) fn permits_endpoint(&self, endpoint: &str) -> bool {
        extract_authority(endpoint)
            .and_then(Authority::parse)
            .is_some_and(|endpoint| self.permits(&endpoint))
    }

    fn permits(&self, endpoint: &Authority) -> bool {
        self.allow_all_domains || self.domains.iter().any(|domain| domain.matches(endpoint))
    }

    pub(crate) fn peer_destination(&self, id: &str) -> Result<Url, &'static str> {
        let routing = Routing::parse(id, self.max_length).ok_or("Invalid UAID format")?;
        let endpoint = Authority::parse(routing.native_id).ok_or("Invalid UAID endpoint")?;
        if !self.permits(&endpoint) {
            return Err("UAID endpoint is blocked by the domain allowlist");
        }
        let path = match routing.protocol {
            "a2a" => "/a2a/invoke",
            "mcp" => "/mcp/tools/call",
            _ => return Err("Unsupported protocol in UAID"),
        };
        let scheme = if endpoint.loopback() { "http" } else { "https" };
        let host = &endpoint.host;
        let origin = match endpoint.port {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}"),
        };
        Url::parse(&format!("{origin}{path}")).map_err(|_| "Invalid UAID endpoint")
    }
}

pub(crate) fn is_uaid(value: &str) -> bool {
    value.starts_with("uaid:aid:") || value.starts_with("uaid:did:")
}

struct Routing<'a> {
    native_id: &'a str,
    protocol: &'a str,
}

impl<'a> Routing<'a> {
    fn parse(value: &'a str, max_length: usize) -> Option<Self> {
        if !is_uaid(value)
            || value.chars().count() > max_length
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return None;
        }
        let (_, tail) = value.split_at(9);
        let mut parts = tail.split(';');
        if parts.next()?.is_empty() {
            return None;
        }
        let mut fields = std::collections::HashMap::new();
        for field in parts {
            let (key, value) = field.split_once('=')?;
            if fields.insert(key, value).is_some() {
                return None;
            }
        }
        if value.starts_with("uaid:aid:")
            && fields.get("registry").is_none_or(|value| value.is_empty())
            || !fields.contains_key("uid")
        {
            return None;
        }
        Some(Self {
            native_id: fields.get("nativeId")?,
            protocol: fields.get("proto")?,
        })
    }
}

#[derive(Clone, Debug)]
struct Authority {
    host: String,
    port: Option<u16>,
}

impl Authority {
    fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty()
            || !raw
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-:[]".contains(&byte))
        {
            return None;
        }
        let (host, port) = if let Some(end) = raw.find(']').filter(|_| raw.starts_with('[')) {
            let (host, port) = raw.split_at(end + 1);
            (host.to_owned(), parse_port(port)?)
        } else if let Ok(address) = raw.parse::<std::net::Ipv6Addr>() {
            return Some(Self {
                host: format!("[{address}]"),
                port: None,
            });
        } else if let Some((host, port)) = raw.rsplit_once(':') {
            if host.contains(':') {
                return None;
            }
            let port = port.parse::<u16>().ok().filter(|port| *port > 0)?;
            (host.to_owned(), Some(port))
        } else {
            (raw.to_owned(), None)
        };
        let host = Host::parse(host.trim_end_matches('.')).ok()?;
        if let Host::Domain(domain) = &host
            && (domain.len() > 253
                || domain.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                }))
        {
            return None;
        }
        Some(Self {
            host: host.to_string(),
            port,
        })
    }

    fn loopback(&self) -> bool {
        self.host == "localhost" || self.ip().is_some_and(|address| address.is_loopback())
    }

    fn ip(&self) -> Option<IpAddr> {
        self.host.trim_matches(['[', ']']).parse().ok()
    }

    fn public(&self) -> bool {
        if self.loopback() || self.host.ends_with(".localhost") {
            return false;
        }
        match self.ip() {
            Some(IpAddr::V4(ip)) => {
                !(ip.is_private()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_broadcast())
            }
            Some(IpAddr::V6(ip)) => {
                !(ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || ip.is_unspecified()
                    || ip.is_multicast())
            }
            None => true,
        }
    }

    fn matches(&self, endpoint: &Self) -> bool {
        self.port.is_none_or(|port| endpoint.port == Some(port))
            && (self.host == endpoint.host
                || self.ip().is_none()
                    && endpoint
                        .host
                        .strip_suffix(&self.host)
                        .is_some_and(|prefix| prefix.ends_with('.')))
    }
}

fn parse_port(suffix: &str) -> Option<Option<u16>> {
    if suffix.is_empty() {
        return Some(None);
    }
    let port = suffix.strip_prefix(':')?.parse::<u16>().ok()?;
    (port > 0).then_some(Some(port))
}

fn extract_authority(endpoint: &str) -> Option<&str> {
    endpoint_target(endpoint)?.split(['/', '?', '#']).next()
}

fn endpoint_target(endpoint: &str) -> Option<&str> {
    let endpoint = endpoint.trim();
    match endpoint.split_once("://") {
        Some((scheme, target))
            if matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") =>
        {
            Some(target)
        }
        Some(_) => None,
        None => Some(endpoint),
    }
}

#[derive(Default, Deserialize)]
pub(crate) struct UaidInput {
    generate_uaid: Option<bool>,
    uaid_registry: Option<String>,
    uaid_protocol: Option<String>,
    uaid_native_id_override: Option<String>,
    uaid_skills: Option<Vec<i64>>,
    version: Option<String>,
}

pub(crate) struct GeneratedUaid {
    pub(crate) identifier: String,
    pub(crate) registry: String,
    pub(crate) protocol: String,
    pub(crate) source: String,
}

impl UaidInput {
    pub(crate) fn generate(
        &self,
        settings: &UaidSettings,
        endpoint: &str,
        name: &str,
        include_skills: bool,
    ) -> Result<Option<GeneratedUaid>, &'static str> {
        if self.generate_uaid != Some(true) {
            return Ok(None);
        }
        if !settings.permits_endpoint(endpoint) {
            return Err("UAID agent endpoint is blocked by the domain allowlist");
        }
        let source = self
            .uaid_native_id_override
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(endpoint)
            .trim();
        let native = extract_authority(source).ok_or("Invalid UAID native ID")?;
        let suffix = endpoint_target(source).ok_or("Invalid UAID native ID")?;
        let authority = Authority::parse(native).ok_or("Invalid UAID native ID")?;
        if !settings.permits(&authority)
            || source.len() > 767
            || !matches!(&suffix[native.len()..], "" | "/")
        {
            return Err("Invalid or disallowed UAID native ID");
        }
        let registry = self
            .uaid_registry
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("context-forge");
        let protocol = self
            .uaid_protocol
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("a2a");
        let canonical_registry = registry.trim().to_ascii_lowercase();
        let canonical_protocol = protocol.trim().to_ascii_lowercase();
        let version = self
            .version
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("1.0.0")
            .trim();
        if canonical_registry.len() > 255
            || registry.len() > 255
            || protocol.len() > 20
            || version.len() > 255
            || !canonical_registry
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || !matches!(canonical_protocol.as_str(), "a2a" | "mcp" | "rest" | "grpc")
        {
            return Err("Invalid UAID registry, protocol, or version");
        }
        let mut skills = if include_skills {
            self.uaid_skills.clone().unwrap_or_default()
        } else {
            Vec::new()
        };
        skills.sort_unstable();
        let canonical = json!({"name":name.trim(),"nativeId":native,"protocol":canonical_protocol,
            "registry":canonical_registry,"skills":skills,"version":version})
        .to_string();
        let digest = Sha384::digest(ascii_json(&canonical));
        let hash = base58(&digest);
        let identifier = format!(
            "uaid:aid:{hash};uid=0;registry={canonical_registry};proto={canonical_protocol};nativeId={native}"
        );
        if identifier.chars().count() > settings.max_length {
            return Err("Generated UAID exceeds the configured length limit");
        }
        Ok(Some(GeneratedUaid {
            identifier,
            registry: registry.to_owned(),
            protocol: protocol.to_owned(),
            source: source.to_owned(),
        }))
    }
}

fn ascii_json(document: &str) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut ascii = String::with_capacity(document.len());
    for unit in document.encode_utf16() {
        if unit < 0x80 {
            ascii.push(char::from(unit as u8));
        } else {
            write!(ascii, "\\u{unit:04x}").expect("writing into a String");
        }
    }
    ascii.into_bytes()
}

fn base58(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits = Vec::<u8>::new();
    for byte in &bytes[zeros..] {
        let mut carry = u16::from(*byte);
        for digit in &mut digits {
            carry += u16::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    std::iter::repeat_n('1', zeros)
        .chain(
            digits
                .into_iter()
                .rev()
                .map(|digit| char::from(ALPHABET[usize::from(digit)])),
        )
        .collect()
}

pub(crate) fn hop_count(headers: &HeaderMap) -> u32 {
    headers
        .get_all(HOP_HEADER)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .map(|value| {
            if value.contains(',') {
                value
                    .split(',')
                    .map(|part| parse_hop(part.trim_matches([' ', '\t'])))
                    .max()
                    .unwrap_or(0)
            } else {
                parse_hop(value)
            }
        })
        .max()
        .unwrap_or(0)
}

fn parse_hop(input: &str) -> u32 {
    if !input.bytes().all(|byte| byte.is_ascii_digit()) {
        tracing::error!("Malformed UAID hop header");
        return 0;
    }
    input
        .bytes()
        .fold(0u32, |number, digit| {
            number
                .saturating_mul(10)
                .saturating_add(u32::from(digit - b'0'))
        })
        .min(i32::MAX as u32)
}

pub(crate) fn stamp(headers: &mut HeaderMap, hops: u32) {
    let next = hops.saturating_add(1).min(i32::MAX as u32);
    headers.insert(HOP_HEADER, HeaderValue::from(next));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uaid_peer_requires_a_matching_domain_and_safe_authority() {
        let mut settings = UaidSettings::default();
        settings
            .configure(HashSet::from(["example.test:8443".to_owned()]), true)
            .unwrap();
        let resolve = |host| {
            settings.peer_destination(&format!(
                "uaid:did:did:key:z;uid=0;proto=a2a;nativeId={host}"
            ))
        };
        assert_eq!(
            resolve("agent.example.test:8443").unwrap().as_str(),
            "https://agent.example.test:8443/a2a/invoke"
        );
        for host in [
            "agent.example.test",
            "agent.example.test:443",
            "otherexample.test:8443",
            "example.test:8443/extra",
            "example.test:8443?query=value",
            "example.test:8443#fragment",
            "example.test:8443;nativeId=example.test:8443",
        ] {
            assert!(resolve(host).is_err(), "{host}");
        }
        assert!(
            UaidSettings::default()
                .configure(HashSet::from(["[::1]:8080".to_owned()]), true)
                .is_err()
        );
    }

    #[test]
    fn uaid_hops_keep_the_highest_strict_ascii_value() {
        let mut headers = HeaderMap::new();
        headers.insert(HOP_HEADER, HeaderValue::from_static("5, 2, +0"));
        headers.append(HOP_HEADER, HeaderValue::from_static("0"));
        assert_eq!(hop_count(&headers), 5);
        headers.append(HOP_HEADER, HeaderValue::from_static("9999999999999999"));
        assert_eq!(hop_count(&headers), i32::MAX as u32);
        stamp(&mut headers, 2);
        assert_eq!(headers.get_all(HOP_HEADER).iter().count(), 1);
        assert_eq!(hop_count(&headers), 3);
    }
}
