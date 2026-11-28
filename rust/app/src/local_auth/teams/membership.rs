// SPDX-License-Identifier: Apache-2.0

use super::*;
use storage::{Invitation, MemberMutation};

#[derive(Deserialize)]
pub(super) struct RoleInput {
    role: String,
}

#[derive(Deserialize)]
pub(super) struct JoinInput {
    message: Option<String>,
}

pub(super) async fn add(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(input): Json<MemberInput>,
) -> Result<(StatusCode, Json<Value>), AccountError> {
    access_team(
        &accounts,
        &principal,
        &id,
        "teams.manage_members",
        TeamAccess::Owner,
    )
    .await?;
    let email = checked_email(&input.email)?;
    let role = input.role.as_deref().unwrap_or("member");
    check_member_role(role)?;
    let member = accounts
        .database
        .write_team_member(
            &id,
            &email,
            &principal.email,
            MemberMutation::Add(role),
            &accounts.settings,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(member.metadata())))
}

pub(super) async fn change(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path((id, email)): Path<(String, String)>,
    Json(input): Json<RoleInput>,
) -> Result<Json<Value>, AccountError> {
    access_team(
        &accounts,
        &principal,
        &id,
        "teams.manage_members",
        TeamAccess::Owner,
    )
    .await?;
    check_member_role(&input.role)?;
    let member = accounts
        .database
        .write_team_member(
            &id,
            &checked_email(&email)?,
            &principal.email,
            MemberMutation::Role(&input.role),
            &accounts.settings,
        )
        .await?;
    Ok(Json(member.metadata()))
}

pub(super) async fn remove(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path((id, email)): Path<(String, String)>,
) -> Result<Json<Value>, AccountError> {
    let email = checked_email(&email)?;
    let rule = if email == principal.email {
        TeamAccess::Member
    } else {
        TeamAccess::Owner
    };
    access_team(&accounts, &principal, &id, "teams.manage_members", rule).await?;
    accounts
        .database
        .write_team_member(
            &id,
            &email,
            &principal.email,
            MemberMutation::Remove,
            &accounts.settings,
        )
        .await?;
    Ok(success("Team member removed successfully"))
}

pub(super) async fn leave(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AccountError> {
    access_team(&accounts, &principal, &id, "teams.join", TeamAccess::Member).await?;
    leave_team(&accounts, &principal, &id).await?;
    Ok(success("Successfully left the team"))
}

pub(super) async fn leave_team(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
) -> Result<(), AccountError> {
    accounts
        .database
        .write_team_member(
            id,
            &principal.email,
            &principal.email,
            MemberMutation::Remove,
            &accounts.settings,
        )
        .await?;
    Ok(())
}

pub(super) async fn list_invites(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Response, AccountError> {
    access_team(
        &accounts,
        &principal,
        &id,
        "teams.manage_members",
        TeamAccess::Owner,
    )
    .await?;
    let invitations = accounts.database.managed_invitations(&id).await?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!(
            invitations
                .iter()
                .map(Invitation::metadata)
                .collect::<Vec<_>>()
        )),
    )
        .into_response())
}

pub(super) async fn invite(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(input): Json<MemberInput>,
) -> Result<Response, AccountError> {
    access_team(
        &accounts,
        &principal,
        &id,
        "teams.manage_members",
        TeamAccess::Owner,
    )
    .await?;
    let email = checked_email(&input.email)?;
    let role = input.role.as_deref().unwrap_or("member");
    check_member_role(role)?;
    let invitation = accounts
        .database
        .create_team_invitation(&id, &email, role, &principal.email, &accounts.settings)
        .await?;
    let (delivery, warning) = send_invitation(&accounts, &invitation).await;
    let mut details = invitation.metadata();
    details["invitation_url"] = invitation_url(&accounts, &invitation).into();
    details["email_delivery_status"] = delivery.into();
    details["warning"] = json!(warning);
    Ok((
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(details),
    )
        .into_response())
}

pub(super) async fn send_invitation(
    accounts: &Accounts,
    invite: &Invitation,
) -> (&'static str, Option<&'static str>) {
    let Some(mailer) = accounts.settings.mailer.as_ref() else {
        return (
            "disabled",
            Some("Invitation created, but email delivery is disabled."),
        );
    };
    let link = invitation_url(accounts, invite);
    let body = format!(
        "You have been invited to join {} on ContextForge. Accept the invitation here:\n{link}",
        invite.team_name
    );
    let subject = format!("Invitation to join {} on ContextForge", invite.team_name);
    if mailer.send(&invite.email, &subject, body).await {
        ("sent", None)
    } else {
        (
            "failed",
            Some("Invitation created, but the email could not be delivered."),
        )
    }
}

fn invitation_url(accounts: &Accounts, invite: &Invitation) -> String {
    let base = &accounts.settings.reset.frontend;
    match base.strip_suffix("/admin") {
        Some(root) => format!("{root}/app/accept-invitation/{}", invite.token),
        None => format!("{base}/accept-invitation/{}", invite.token),
    }
}

pub(super) async fn accept(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(token): Path<String>,
) -> Result<Json<Value>, AccountError> {
    permit(&accounts, &principal, "teams.join", None).await?;
    let token = Zeroizing::new(token);
    let member = accounts
        .database
        .accept_team_invitation(&token, &principal.email, &accounts.settings)
        .await?;
    Ok(Json(member.metadata()))
}

pub(super) async fn decline(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(token): Path<String>,
) -> Result<Json<Value>, AccountError> {
    permit(&accounts, &principal, "teams.join", None).await?;
    let token = Zeroizing::new(token);
    accounts
        .database
        .decline_team_invitation(&token, &principal.email)
        .await?;
    Ok(success("Team invitation declined successfully"))
}

pub(super) async fn cancel_invite(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AccountError> {
    let invite = accounts
        .database
        .managed_invitation(&id)
        .await?
        .filter(|invite| in_token_scope(&principal, &invite.team_id))
        .ok_or_else(missing_invitation)?;
    permit(
        &accounts,
        &principal,
        "teams.manage_members",
        Some(&invite.team_id),
    )
    .await?;
    accounts
        .database
        .cancel_team_invitation(&id, &principal.email)
        .await?;
    Ok(success("Team invitation cancelled successfully"))
}

pub(super) async fn join(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(input): Json<JoinInput>,
) -> Result<Json<Value>, AccountError> {
    permit(&accounts, &principal, "teams.join", None).await?;
    let (record, created) =
        request_join(&accounts, &principal, &id, input.message.as_deref(), true).await?;
    if !created {
        return Err(AccountError::bad_request(
            "User already has a pending join request for this team",
        ));
    }
    Ok(Json(record.metadata()))
}

pub(super) async fn request_join(
    accounts: &Accounts,
    principal: &Principal,
    id: &str,
    message: Option<&str>,
    reopen_expired: bool,
) -> Result<(storage::JoinRequest, bool), AccountError> {
    if !accounts.settings.teams.allow_join_requests {
        return Err(denied("Team join requests are currently disabled"));
    }
    if message.is_some_and(|message| message.chars().count() > 500) {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Join request message is too long",
        ));
    }
    accounts
        .database
        .request_team_membership(
            id,
            &principal.email,
            message,
            &accounts.settings.teams,
            reopen_expired,
        )
        .await
}

pub(super) async fn list_requests(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AccountError> {
    access_team(
        &accounts,
        &principal,
        &id,
        "teams.manage_members",
        TeamAccess::Owner,
    )
    .await?;
    let records = accounts.database.team_join_requests(&id).await?;
    Ok(Json(json!(
        records
            .iter()
            .map(storage::JoinRequest::metadata)
            .collect::<Vec<_>>()
    )))
}

pub(super) async fn approve(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path((id, request)): Path<(String, String)>,
) -> Result<Json<Value>, AccountError> {
    access_team(
        &accounts,
        &principal,
        &id,
        "teams.manage_members",
        TeamAccess::Owner,
    )
    .await?;
    let member = accounts
        .database
        .review_team_membership(&id, &request, &principal.email, true, &accounts.settings)
        .await?;
    let member = member.ok_or_else(AccountError::unavailable)?;
    Ok(Json(member.metadata()))
}

pub(super) async fn reject(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path((id, request)): Path<(String, String)>,
) -> Result<Json<Value>, AccountError> {
    access_team(
        &accounts,
        &principal,
        &id,
        "teams.manage_members",
        TeamAccess::Owner,
    )
    .await?;
    accounts
        .database
        .review_team_membership(&id, &request, &principal.email, false, &accounts.settings)
        .await?;
    Ok(success("Join request rejected successfully"))
}

fn checked_email(email: &str) -> Result<String, AccountError> {
    let email = email.trim().to_ascii_lowercase();
    if !valid_email(&email) {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid email format",
        ));
    }
    Ok(email)
}

fn missing_invitation() -> AccountError {
    AccountError::detail(StatusCode::NOT_FOUND, "Invitation not found")
}
