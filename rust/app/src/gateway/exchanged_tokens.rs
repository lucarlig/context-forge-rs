// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, time::Instant};

use axum::http::HeaderValue;

use super::*;

const MAX_ENTRIES: usize = 1024;
const REFRESH_MARGIN: u64 = 300;

type Key = (String, i32, [u8; 32]);
type Entry = Arc<tokio::sync::Mutex<Option<(Instant, HeaderValue)>>>;

#[derive(Default)]
pub(super) struct ExchangedTokens(Mutex<HashMap<Key, Entry>>);

impl ExchangedTokens {
    pub(super) async fn authorization(
        &self,
        connection: ExchangeConnection<'_>,
        principal: &Principal,
        subject: &str,
    ) -> Result<HeaderValue, UpstreamError> {
        let subject_lifetime = || {
            principal
                .expires_at
                .and_then(|expiry| {
                    u64::try_from(expiry.saturating_sub(Timestamp::now().as_second())).ok()
                })
                .filter(|lifetime| *lifetime > 0)
                .ok_or(UpstreamError::InvalidCredentials)
        };
        let key = (
            connection.gateway_id.to_owned(),
            connection.version,
            principal.credential_hash(),
        );
        let entry = {
            let mut entries = self.0.lock().map_err(|_| UpstreamError::Transport)?;
            if entries.len() >= MAX_ENTRIES
                && !entries.contains_key(&key)
                && let Some(removable) = entries
                    .iter()
                    .find(|(_, entry)| Arc::strong_count(entry) == 1)
                    .map(|(key, _)| key.clone())
            {
                entries.remove(&removable);
            }
            if entries.len() >= MAX_ENTRIES && !entries.contains_key(&key) {
                Arc::new(tokio::sync::Mutex::new(None))
            } else {
                entries.entry(key).or_default().clone()
            }
        };
        let mut entry = entry.lock().await;
        subject_lifetime()?;
        if let Some((until, token)) = &*entry
            && *until > Instant::now()
        {
            return Ok(token.clone());
        }
        let token = connection
            .config
            .exchange_subject(connection.upstream, connection.tls, subject)
            .await?;
        let expiry = subject_lifetime()?;
        if let Some(lifetime) = token.expires_in.filter(|lifetime| *lifetime > 0) {
            let usable = lifetime - REFRESH_MARGIN.min(lifetime / 2);
            if let Some(until) = Instant::now().checked_add(Duration::from_secs(usable.min(expiry)))
            {
                *entry = Some((until, token.authorization.clone()));
            }
        }
        Ok(token.authorization)
    }
}

pub(super) struct ExchangeConnection<'a> {
    pub(super) gateway_id: &'a str,
    pub(super) version: i32,
    pub(super) upstream: &'a UpstreamClient,
    pub(super) config: &'a OAuthConfig,
    pub(super) tls: Option<&'a TlsMaterial>,
}
