// SPDX-License-Identifier: Apache-2.0

use axum::http::request::Parts;
use url::Url;

use super::*;

pub(super) struct KeycloakLogout {
    endpoint: Url,
    app_domain: Url,
    client: String,
}

impl KeycloakLogout {
    pub(super) fn from_env() -> Result<Option<Self>, Box<dyn Error + Send + Sync>> {
        if !flag("SSO_KEYCLOAK_ENABLED")?.unwrap_or(false) {
            return Ok(None);
        }
        let base = value("SSO_KEYCLOAK_BASE_URL", "")?;
        let public = value("SSO_KEYCLOAK_PUBLIC_BASE_URL", "")?;
        let realm = value("SSO_KEYCLOAK_REALM", "master")?;
        if base.trim().is_empty() || realm.trim().is_empty() {
            return Ok(None);
        }
        let browser_base = if public.trim().is_empty() {
            &base
        } else {
            &public
        };
        let Some(mut endpoint) = http_url(browser_base) else {
            tracing::warn!("Keycloak sign-out URL is invalid");
            return Ok(None);
        };
        endpoint
            .path_segments_mut()
            .map_err(|_| "invalid Keycloak logout URL")?
            .pop_if_empty()
            .extend([
                "realms",
                realm.trim(),
                "protocol",
                "openid-connect",
                "logout",
            ]);
        let app_domain =
            http_url(&value("APP_DOMAIN", "http://localhost:4444")?).ok_or("invalid APP_DOMAIN")?;
        Ok(Some(Self {
            endpoint,
            app_domain,
            client: value("SSO_KEYCLOAK_CLIENT_ID", "")?,
        }))
    }

    pub(super) fn redirect(
        &self,
        auth: &Authorizer,
        session: &str,
        parts: &Parts,
        root: &str,
    ) -> Option<Response> {
        if let Ok(jwt) = auth.verify_gateway_token(session)
            && provider(jwt.payload()) != Some("keycloak")
        {
            return None;
        }
        let mut endpoint = self.endpoint.clone();
        let login_path = format!("{root}{LOGIN}");
        let return_url = login_url(parts, &self.app_domain, &login_path);
        {
            let mut query = endpoint.query_pairs_mut();
            query
                .append_pair("post_logout_redirect_uri", return_url.as_str())
                .append_pair("redirect_uri", return_url.as_str());
            if !self.client.is_empty() {
                query.append_pair("client_id", &self.client);
            }
            if let Some(hint) = cookie(&parts.headers, sso::ID_TOKEN_HINT_COOKIE)
                && unverified_jwt_claims(hint)
                    .and_then(|claims| claims.get("exp")?.as_i64())
                    .is_some_and(|expires| expires > Timestamp::now().as_second())
            {
                query.append_pair("id_token_hint", hint);
            }
        }
        let mut response = Redirect::to(endpoint.as_str()).into_response();
        if let Some(location) = response.headers_mut().get_mut(header::LOCATION) {
            location.set_sensitive(true);
        }
        Some(response)
    }
}

fn provider(payload: &Value) -> Option<&str> {
    [
        payload["user"]["auth_provider"].as_str(),
        payload["auth_provider"].as_str(),
    ]
    .into_iter()
    .flatten()
    .find(|provider| !provider.is_empty())
}

fn login_url(parts: &Parts, app_domain: &Url, path: &str) -> Url {
    let scheme = parts.uri.scheme_str().unwrap_or("http");
    if let Some(mut url) = forms::header_text(&parts.headers, header::HOST)
        .or_else(|| parts.uri.authority().map(|authority| authority.as_str()))
        .and_then(|host| http_url(&format!("{scheme}://{host}")))
        .filter(|url| url.path() == "/")
    {
        url.set_path(path);
        return url;
    }
    let mut url = app_domain.clone();
    url.set_path(&format!(
        "{}{path}",
        app_domain.path().trim_end_matches('/')
    ));
    url
}

fn http_url(raw: &str) -> Option<Url> {
    let url = Url::parse(raw).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}
