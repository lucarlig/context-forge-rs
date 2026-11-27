// SPDX-License-Identifier: Apache-2.0

mod approvals;
mod external;
mod flow;
mod grants;
mod identity;
mod oidc;
mod provider_claims;
mod providers;
mod provisioning;

use std::collections::HashSet;

use super::*;
use crate::{secret_envelope::SecretEnvelope, upstream::UpstreamClient};
pub use external::ExternalIdentitySettings;
pub(crate) use grants::SsoIdentityPolicy;
pub(crate) use oidc::{is_id_token, unverified_jwt_claims, verify as verify_oidc_jwt};
pub(super) use providers::bootstrap::bootstrap;

pub(super) const ID_TOKEN_HINT_COOKIE: &str = "sso_id_token_hint";

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
    pub(crate) identity_policy: SsoIdentityPolicy,
    pub(crate) admin_api_enabled: bool,
}

pub(super) fn routers(settings: &SsoSettings) -> (Router<Arc<Accounts>>, Router<Arc<Accounts>>) {
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
            )
            .route(&format!("{base}/pending-approvals"), get(approvals::list))
            .route(
                &format!("{base}/pending-approvals/{{id}}/action"),
                post(approvals::review),
            );
    }
    if settings.admin_api_enabled {
        protected = protected.route("/v1/admin/users/sso", post(provisioning::create_user));
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
