// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn routes(mut router: Router<Arc<Accounts>>, item: &str) -> Router<Arc<Accounts>> {
    let cancel_path = format!("{item}/join-request/{{request_id}}");
    router = router
        .route(&format!("{item}/join-request"), post(submit))
        .route(
            &cancel_path,
            delete(change_request).layer(Extension(Decision::Cancel)),
        )
        .route(
            &format!("{cancel_path}/cancel"),
            post(change_request).layer(Extension(Decision::Cancel)),
        )
        .route(&format!("{item}/join-requests"), get(queue))
        .route(&format!("{item}/leave"), post(leave));
    for (action, decision) in [("approve", Decision::Approve), ("reject", Decision::Reject)] {
        router = router.route(
            &format!("{item}/join-requests/{{request_id}}/{action}"),
            post(change_request).layer(Extension(decision)),
        );
    }
    router
}

async fn submit(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form(&accounts, dashboard::JOIN, request, peer.ip(), false).await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let result = async {
            let id = team_id(&id)?;
            dashboard::submit_join(&accounts, &principal, &id, form.get("message")).await
        }
        .await;
        let (record, created) = match result {
            Ok(result) => result,
            Err(error) => return error_page(&accounts, error),
        };
        if from_directory(&parts) {
            return public_teams_redirect(&accounts);
        }
        let status = if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        forms::render_template(
            "team_requests.html",
            context! {
                record, root => &settings_for(&accounts).root,
                proof => cookie(&parts.headers, CSRF_COOKIE).unwrap_or_default(),
            },
        )
        .map(|mut response| {
            *response.status_mut() = status;
            response
        })
        .into_response()
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

async fn queue(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorize(&accounts, request, peer).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let id = team_id(&id)?;
        let (team, records) = dashboard::join_queue(&accounts, &principal, &id).await?;
        let fragment = htmx(&parts);
        let template = if fragment {
            "team_requests.html"
        } else {
            "browser.html"
        };
        render_form(
            &accounts,
            template,
            context! {
                page => "team-requests", title => "Join requests", team, records,
                root => &settings_for(&accounts).root, proof,
            },
            &proof,
        )
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), async {
        response.await.into_response()
    })
    .await
}

#[derive(Clone, Copy)]
enum Decision {
    Cancel,
    Approve,
    Reject,
}

async fn change_request(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Extension(decision): Extension<Decision>,
    Path((id, request_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let id = match team_id(&id) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let cancel = matches!(decision, Decision::Cancel);
    let permission = if cancel {
        dashboard::JOIN
    } else {
        dashboard::MEMBERS
    };
    let AuthorizedForm {
        principal, parts, ..
    } = match catalog::authorized_form_for_team(
        &accounts,
        permission,
        request,
        peer.ip(),
        false,
        (!cancel).then_some(id.as_str()),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let result = if cancel {
            dashboard::cancel_join(&accounts, &principal, &id, &request_id).await
        } else {
            dashboard::review_join(
                &accounts,
                &principal,
                &id,
                &request_id,
                matches!(decision, Decision::Approve),
            )
            .await
        };
        if let Err(error) = result {
            return error_page(&accounts, error);
        }
        if from_directory(&parts) {
            return if cancel {
                public_teams_redirect(&accounts)
            } else {
                settings_for(&accounts).redirect(&format!("/admin/teams/{id}/join-requests"))
            };
        }
        let updates = if cancel {
            json!({"refreshUnifiedTeamsList":true,"delayMs":1000})
        } else {
            json!({"teamId":id, "refreshJoinRequests":true,"delayMs":1000})
        };
        let content = match decision {
            Decision::Cancel => forms::render_template(
                "team_requests.html",
                context! {
                    cancelled => true, team_id => id, root => &settings_for(&accounts).root,
                    can_join => accounts.settings.teams.allow_join_requests,
                    proof => cookie(&parts.headers, CSRF_COOKIE).unwrap_or_default(),
                },
            ),
            Decision::Approve => Ok(Html("<p>Join request approved</p>").into_response()),
            Decision::Reject => Ok(Html("<p>Join request rejected</p>").into_response()),
        };
        (
            [("HX-Trigger", json!({"adminTeamAction":updates}).to_string())],
            content,
        )
            .into_response()
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

async fn leave(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let id = match team_id(&id) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let AuthorizedForm {
        principal, parts, ..
    } = match catalog::authorized_form_for_team(
        &accounts,
        dashboard::JOIN,
        request,
        peer.ip(),
        false,
        Some(&id),
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        if let Err(error) = dashboard::leave_team(&accounts, &principal, &id).await {
            return error_page(&accounts, error);
        }
        if from_directory(&parts) {
            return teams_redirect(&accounts);
        }
        (
            [("HX-Trigger",r#"{"adminTeamAction":{"refreshUnifiedTeamsList":true,"closeAllModals":true,"delayMs":1500}}"#)],
            Html("<p>Successfully left the team</p>"),
        ).into_response()
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

fn from_directory(parts: &Parts) -> bool {
    forms::query(&parts.uri).contains_key("directory")
}

fn public_teams_redirect(accounts: &Accounts) -> Response {
    settings_for(accounts).redirect("/admin/?section=teams&relationship=public#teams")
}
