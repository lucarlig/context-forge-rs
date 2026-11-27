// SPDX-License-Identifier: Apache-2.0

mod flow;
mod oidc;
mod providers;

use std::collections::HashSet;

use super::*;
use crate::{secret_envelope::SecretEnvelope, upstream::UpstreamClient};

pub(crate) struct SsoSettings {
    pub(crate) upstream: UpstreamClient,
    pub(crate) vault: Option<SecretEnvelope>,
    pub(crate) allowed_issuers: HashSet<String>,
    pub(crate) binding_key: Option<ring::hmac::Key>,
    pub(crate) app_domain: url::Url,
    pub(crate) allowed_origins: HashSet<String>,
    pub(crate) root_path: String,
    pub(crate) secure_cookies: bool,
    pub(crate) same_site: String,
}

pub(super) fn routers() -> (Router<Arc<Accounts>>, Router<Arc<Accounts>>) {
    let mut public = Router::new();
    let mut protected = Router::new();
    for base in ["/auth/sso", "/v1/auth/sso"] {
        public = public
            .route(&format!("{base}/providers"), get(providers::public_list))
            .route(&format!("{base}/login/{{id}}"), get(flow::login))
            .route(&format!("{base}/callback/{{id}}"), get(flow::callback));
        protected = protected
            .route(
                &format!("{base}/admin/providers"),
                get(providers::list).post(providers::create),
            )
            .route(
                &format!("{base}/admin/providers/{{id}}"),
                get(providers::read)
                    .put(providers::update)
                    .delete(providers::delete),
            );
    }
    (public, protected)
}

impl Accounts {
    fn sso(&self) -> Result<&SsoSettings, AccountError> {
        self.settings.sso.as_ref().ok_or_else(|| {
            AccountError::detail(StatusCode::NOT_FOUND, "SSO authentication is disabled")
        })
    }
}

impl SsoSettings {
    async fn encrypt(&self, secret: String) -> Result<String, AccountError> {
        let secret = Zeroizing::new(secret);
        self.vault
            .as_ref()
            .ok_or_else(AccountError::unavailable)?
            .seal(secret)
            .await
            .map_err(|_| AccountError::unavailable())
    }
}
