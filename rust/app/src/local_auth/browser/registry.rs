// SPDX-License-Identifier: Apache-2.0

use super::{catalog::AuthorizedForm, *};

pub(super) fn routes(router: Router<Arc<Accounts>>, path: &str) -> Router<Arc<Accounts>> {
    router
        .route(
            &format!("{path}/mcp-registry/{{id}}/register/form"),
            post(submit),
        )
        .route(
            &format!("{path}/mcp-registry/bulk-register/form"),
            post(submit),
        )
}

async fn submit(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    path: Option<Path<String>>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, "servers.create", request, peer.ip(), false).await
    {
        Ok(form) => form,
        Err(response) => return *response,
    };
    let settings = settings_for(&accounts);
    let field = |name| form.value(name).filter(|value| !value.is_empty());
    let back = format!("{}/admin/?section=registry", settings.root);
    let render_result = |result: Value| {
        render(context! {
            title => "MCP registry registration",
            page => "registry-result",
            back => &back,
            result => result,
        })
        .unwrap_or_else(IntoResponse::into_response)
    };
    let response = async {
        if let Some(Path(id)) = path {
            let oauth = [
                "issuer",
                "client_id",
                "client_secret",
                "authorization_url",
                "token_url",
                "scopes",
                "redirect_uri",
                "audience",
                "resource",
            ]
            .into_iter()
            .filter_map(|key| field(key).map(|value| (key.to_owned(), value.into())))
            .collect::<serde_json::Map<String, Value>>();
            let values = json!({
                "name":field("name"),"api_key":field("api_key"),"oauth_credentials":oauth,
                "visibility":field("visibility"),"team_id":field("team_id"),
            });
            match service
                .register_registry_form(&principal, &id, values)
                .await
            {
                Ok(result) if result["success"] == true => {
                    Redirect::to(&format!("{back}&message=registry_registered")).into_response()
                }
                Ok(result) => render_result(result),
                Err(error) => render_result(json!({"error":error.form_message()})),
            }
        } else {
            let values = json!({
                "server_ids":form.values("server_ids").collect::<Vec<_>>(), "skip_errors":field("skip_errors").is_some(),
                "visibility":field("visibility"),"team_id":field("team_id"),
            });
            match service
                .register_registry_batch_form(&principal, values)
                .await
            {
                Ok(result) => render_result(result),
                Err(error) => render_result(json!({"error":error.form_message()})),
            }
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}
