// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use super::*;
use dashboard::{MemberAction, MemberChange};

pub(super) fn routes(mut router: Router<Arc<Accounts>>, item: &str) -> Router<Arc<Accounts>> {
    for (path, view) in [
        ("members", MembersView::Full),
        ("members/add", MembersView::Add),
        ("members/partial", MembersView::Current),
        ("non-members/partial", MembersView::Available),
    ] {
        router = router.route(&format!("{item}/{path}"), get(show).layer(Extension(view)));
    }
    for (path, action) in [
        ("add-member", Change::Add),
        ("update-member-role", Change::Role),
        ("remove-member", Change::Remove),
    ] {
        router = router.route(
            &format!("{item}/{path}"),
            post(mutate).layer(Extension(action)),
        );
    }
    router
}

#[derive(Clone, Copy)]
enum MembersView {
    Full,
    Add,
    Current,
    Available,
}

#[derive(Deserialize)]
struct Search {
    page: Option<i64>,
    per_page: Option<i64>,
    search: Option<String>,
}

#[derive(Serialize)]
struct Page {
    rows: Vec<dashboard::DirectoryMember>,
    previous: Option<String>,
    next: Option<String>,
}

async fn show(
    State(accounts): State<Arc<Accounts>>,
    Extension(service): Extension<Arc<GatewayService>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Extension(view): Extension<MembersView>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let (principal, parts, proof) = match authorize(&accounts, request, peer).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let response = async {
        let id = team_id(&id).map_err(as_catalog_error)?;
        let team = dashboard::member_view(
            &accounts,
            &principal,
            &id,
            !matches!(view, MembersView::Full),
        )
        .await
        .map_err(as_catalog_error)?;
        let query: Search = parse_query(&parts.uri)?;
        let search = query.search.as_deref().unwrap_or_default();
        if search.chars().count() > 255 {
            return Err(CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid member search",
            ));
        }
        let search = search.trim();
        let current = matches!(view, MembersView::Full | MembersView::Current);
        let size = if matches!(view, MembersView::Available) {
            let size = query.per_page.unwrap_or(50);
            if !(1..=50).contains(&size) {
                return Err(CatalogApiError::detail(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Invalid member page size",
                ));
            }
            Some(size)
        } else {
            query.per_page
        };
        let (number, size) = service.admin_page_params(query.page, size)?;
        let settings = settings_for(&accounts);
        let endpoint = match view {
            MembersView::Full => "members",
            MembersView::Add => "members/add",
            MembersView::Current => "members/partial",
            MembersView::Available => "non-members/partial",
        };
        let required = !current && search.chars().count() < 2;
        let rows = if required {
            Vec::new()
        } else {
            dashboard::members(&accounts, &id, search, current).await?
        };
        let pagination = PaginationMeta::new(number, size, rows.len() as i64);
        let link = |number: i64| {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query
                .append_pair("page", &number.to_string())
                .append_pair("per_page", &size.to_string());
            if !search.is_empty() {
                query.append_pair("search", search);
            }
            format!(
                "{}/admin/teams/{id}/{endpoint}?{}",
                settings.root,
                query.finish()
            )
        };
        let page = Page {
            rows: rows
                .into_iter()
                .skip(service.admin_page_offset(&pagination) as usize)
                .take(size as usize)
                .collect(),
            previous: pagination.has_prev.then(|| link(pagination.page - 1)),
            next: pagination.has_next.then(|| link(pagination.page + 1)),
        };
        let manage = team["is_personal"] != true
            && dashboard::can_manage_members(&accounts, &principal, &id).await?;
        let full = matches!(view, MembersView::Full | MembersView::Add);
        let template = if full {
            "browser.html"
        } else {
            "team_members.html"
        };
        render_form(
            &accounts,
            template,
            context! {
                page => "team-members", title => "Team members", root => &settings.root,
                team, proof, members => page, endpoint, current, search, required, manage,
            },
            &proof,
        )
        .map_err(as_catalog_error)
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), async {
        response.await.into_response()
    })
    .await
}

#[derive(Clone, Copy)]
enum Change {
    Add,
    Role,
    Remove,
}

#[derive(Default, Serialize)]
struct ResultCounts {
    added: usize,
    updated: usize,
    removed: usize,
    errors: Vec<String>,
}

impl ResultCounts {
    fn record(&mut self, email: &str, result: Result<MemberChange, AccountError>) {
        match result {
            Ok(MemberChange::Added) => self.added += 1,
            Ok(MemberChange::Updated) => self.updated += 1,
            Ok(MemberChange::Removed) => self.removed += 1,
            Ok(MemberChange::Unchanged) => {}
            Err(error) => {
                let message = error.1["detail"].as_str().unwrap_or("Change failed");
                self.errors.push(format!("{email} ({message})"));
            }
        }
    }
}

async fn mutate(
    State(accounts): State<Arc<Accounts>>,
    Extension(ConnectInfo(peer)): Extension<ConnectInfo<SocketAddr>>,
    Extension(action): Extension<Change>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let id = match team_id(&id) {
        Ok(id) => id,
        Err(error) => return error.into_response(),
    };
    let AuthorizedForm {
        principal,
        parts,
        form,
        ..
    } = match catalog::authorized_form_for_team(
        &accounts,
        dashboard::MEMBERS,
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
        if let Err(error) = dashboard::member_view(&accounts, &principal, &id, true).await {
            return error_page(&accounts, error);
        }
        let mut counts = ResultCounts::default();
        let email = form.get("user_email");
        let role = form.value("role").unwrap_or("member");
        let result = match action {
            Change::Add if email.is_empty() => {
                add_selected(&accounts, &principal, &id, &form, &mut counts).await
            }
            Change::Add => {
                counts.record(
                    email,
                    dashboard::change_member(
                        &accounts,
                        &principal,
                        &id,
                        email,
                        MemberAction::AddOrUpdate(role),
                    )
                    .await,
                );
                Ok(())
            }
            Change::Role | Change::Remove => {
                let operation = match action {
                    Change::Role => MemberAction::Role(role),
                    _ => MemberAction::Remove,
                };
                dashboard::change_member(&accounts, &principal, &id, email, operation)
                    .await
                    .map(|change| counts.record(email, Ok(change)))
            }
        };
        if let Err(error) = result {
            return error_page(&accounts, error);
        }
        let settings = settings_for(&accounts);
        if counts.errors.is_empty() && forms::query(&parts.uri).contains_key("directory") {
            return settings.redirect(&format!("/admin/teams/{id}/members"));
        }
        let updates = match action {
            Change::Add => json!({"teamId":id,"refreshUnifiedTeamsList":true}),
            Change::Role => json!({"teamId":id,"refreshUnifiedTeamsList":true,
                "refreshTeamMembers":true,"closeRoleModal":true,"delayMs":1000}),
            Change::Remove => json!({"teamId":id,"refreshUnifiedTeamsList":true,
                "refreshTeamMembers":true,"delayMs":1000}),
        };
        let response = forms::render_template(
            "team_members.html",
            context! {
                result => counts, root => &settings.root, team_id => id,
            },
        );
        (
            [("HX-Trigger", json!({"adminTeamAction":updates}).to_string())],
            response,
        )
            .into_response()
    };
    catalog::with_usage(&accounts, &principal, &parts, peer.ip(), response).await
}

async fn add_selected(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    form: &Form,
    result: &mut ResultCounts,
) -> Result<(), AccountError> {
    let mut selected = HashSet::new();
    for email in form
        .values("associatedUsers")
        .map(str::trim)
        .filter(|email| !email.is_empty())
    {
        if !selected.insert(email.to_ascii_lowercase()) {
            continue;
        }
        let encoded = utf8_percent_encode(email, &forms::QUERY_ENCODE);
        let role = form.value(&format!("role_{encoded}")).unwrap_or("member");
        result.record(
            email,
            dashboard::change_member(
                accounts,
                principal,
                id,
                email,
                MemberAction::AddOrUpdate(role),
            )
            .await,
        );
    }
    if selected.is_empty() {
        return Err(AccountError::bad_request("No users selected"));
    }
    let mut removed = HashSet::new();
    for email in form
        .values("loadedMembers")
        .map(str::trim)
        .filter(|email| !email.is_empty())
    {
        let normalized = email.to_ascii_lowercase();
        if selected.contains(&normalized) || !removed.insert(normalized.clone()) {
            continue;
        }
        if normalized == principal.email {
            result
                .errors
                .push(format!("{email} (cannot remove yourself)"));
            continue;
        }
        result.record(
            email,
            dashboard::change_member(accounts, principal, id, email, MemberAction::Remove).await,
        );
    }
    Ok(())
}
