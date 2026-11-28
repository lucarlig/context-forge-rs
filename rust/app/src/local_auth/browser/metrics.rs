// SPDX-License-Identifier: Apache-2.0

use super::{catalog::AuthorizedForm, *};

pub(super) fn routes(router: Router<Arc<Accounts>>, path: &str) -> Router<Arc<Accounts>> {
    router.route(&format!("{path}/metrics/reset/form"), post(reset))
}

async fn reset(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal, parts, ..
    } = match catalog::authorized_form(&accounts, "admin.system_config", request, peer.ip(), false)
        .await
    {
        Ok(form) => form,
        Err(response) => return *response,
    };
    let response = async {
        match service.clear_execution_metrics(&principal).await {
            Ok(()) => {
                settings_for(&accounts).redirect("/admin/?section=metrics&message=metrics_reset")
            }
            Err(error) => error.into_response(),
        }
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}
