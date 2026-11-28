// SPDX-License-Identifier: Apache-2.0

use sqlx::types::Json as DbJson;

use super::*;
use crate::database::observed;

#[derive(Deserialize)]
pub(super) struct ApprovalQuery {
    #[serde(default)]
    include_expired: bool,
}

#[derive(Deserialize)]
pub(super) struct Review {
    action: String,
    reason: Option<String>,
    notes: Option<String>,
}

pub(super) async fn list(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<ApprovalQuery>,
) -> Result<Json<Vec<Value>>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let rows = accounts
        .database
        .pending_sso_approvals(query.include_expired)
        .await?;
    Ok(Json(rows.into_iter().map(Approval::payload).collect()))
}

pub(super) async fn review(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(input): Json<Review>,
) -> Result<Json<Value>, AccountError> {
    require_user_admin(&accounts, &principal).await?;
    let email = accounts
        .database
        .review_sso_approval(&id, &principal.email, &input)
        .await?;
    let message = if input.action == "approve" {
        format!("User {email} approved successfully")
    } else {
        format!("User {email} rejected")
    };
    Ok(Json(json!({"message":message})))
}

#[derive(sqlx::FromRow)]
struct Approval {
    id: String,
    email: String,
    full_name: String,
    auth_provider: String,
    sso_metadata: Option<DbJson<Value>>,
    requested_at: String,
    expires_at: String,
    status: String,
}

impl Approval {
    fn payload(self) -> Value {
        json!({
            "id":self.id,"email":self.email,"full_name":self.full_name,"auth_provider":self.auth_provider,
            "sso_metadata":self.sso_metadata,"requested_at":self.requested_at.replacen(' ', "T", 1),
            "expires_at":self.expires_at.replacen(' ', "T", 1),"status":self.status,
        })
    }
}

impl Database {
    pub(super) async fn queue_sso_approval(
        &self,
        email: &str,
        name: &str,
        provider: &str,
        metadata: Value,
    ) -> Result<(), sqlx::Error> {
        macro_rules! queue {
            ($pool:expr, $expiry:literal, $expired:literal) => {{
                sqlx::query(concat!("INSERT INTO pending_user_approvals
                    (id,email,full_name,auth_provider,sso_metadata,expires_at)
                    VALUES($1,$2,$3,$4,$5,", $expiry, ")
                    ON CONFLICT(email) DO UPDATE SET
                    full_name=CASE WHEN pending_user_approvals.status='approved' THEN pending_user_approvals.full_name ELSE excluded.full_name END,
                    auth_provider=CASE WHEN pending_user_approvals.status='approved' THEN pending_user_approvals.auth_provider ELSE excluded.auth_provider END,
                    sso_metadata=CASE WHEN pending_user_approvals.status='approved' THEN pending_user_approvals.sso_metadata ELSE excluded.sso_metadata END,
                    requested_at=CURRENT_TIMESTAMP,expires_at=excluded.expires_at,
                    status=CASE WHEN pending_user_approvals.status='approved' THEN 'expired' ELSE 'pending' END,
                    approved_by=NULL,approved_at=NULL,rejection_reason=NULL,admin_notes=NULL
                    WHERE pending_user_approvals.status='expired'
                       OR (pending_user_approvals.status IN ('pending','approved') AND ", $expired, ")"))
                    .bind(Uuid::new_v4().to_string()).bind(email).bind(name).bind(provider)
                    .bind(DbJson(metadata)).execute(observed($pool)).await?;
            }};
        }
        match self {
            Self::Sqlite(pool) => queue!(
                pool,
                "datetime(CURRENT_TIMESTAMP,'+30 days')",
                "julianday(pending_user_approvals.expires_at)<=julianday(CURRENT_TIMESTAMP)"
            ),
            Self::Postgres(pool) => queue!(
                pool,
                "clock_timestamp()+INTERVAL '30 days'",
                "pending_user_approvals.expires_at<=clock_timestamp()"
            ),
        };
        Ok(())
    }

    async fn pending_sso_approvals(
        &self,
        include_expired: bool,
    ) -> Result<Vec<Approval>, sqlx::Error> {
        macro_rules! select {
            ($pool:expr, $fresh:literal) => {
                sqlx::query_as(concat!("SELECT id,email,full_name,auth_provider,sso_metadata,
                    CAST(requested_at AS TEXT) AS requested_at,CAST(expires_at AS TEXT) AS expires_at,status
                    FROM pending_user_approvals WHERE status='pending' AND ($1 OR ", $fresh,
                    ") ORDER BY requested_at DESC,id"))
                    .bind(include_expired).fetch_all(observed($pool)).await
            };
        }
        match self {
            Self::Sqlite(pool) => {
                select!(pool, "julianday(expires_at)>julianday(CURRENT_TIMESTAMP)")
            }
            Self::Postgres(pool) => select!(pool, "expires_at>clock_timestamp()"),
        }
    }

    async fn review_sso_approval(
        &self,
        id: &str,
        reviewer: &str,
        review: &Review,
    ) -> Result<String, AccountError> {
        macro_rules! review {
            ($tx:ident, $fresh:literal,$lock:literal) => {{
                let item = sqlx::query_as::<_,(String,String,bool)>(concat!(
                    "SELECT email,status,", $fresh,
                    " FROM pending_user_approvals WHERE id=$1",$lock))
                    .bind(id).fetch_optional(observed(&mut *$tx)).await?;
                let Some((email, status, fresh)) = item else {
                    return Err(AccountError::detail(StatusCode::NOT_FOUND, "Approval request not found"));
                };
                if status != "pending" {
                    return Err(AccountError::bad_request(format!("Approval request is already {status}")));
                }
                if !fresh {
                    sqlx::query("UPDATE pending_user_approvals SET status='expired' WHERE id=$1")
                        .bind(id).execute(observed(&mut *$tx)).await?;
                    $tx.commit().await?;
                    return Err(AccountError::bad_request("Approval request has expired"));
                }
                let (status, reason) = match review.action.as_str() {
                    "approve" => ("approved", None),
                    "reject" => ("rejected", Some(review.reason.as_deref().filter(|reason| !reason.is_empty())
                        .ok_or_else(||AccountError::bad_request("Rejection reason is required"))?)),
                    _ => return Err(AccountError::bad_request("Invalid action. Must be 'approve' or 'reject'")),
                };
                sqlx::query("UPDATE pending_user_approvals SET status=$2,approved_by=$3,approved_at=CURRENT_TIMESTAMP,
                    rejection_reason=$4,admin_notes=$5 WHERE id=$1")
                    .bind(id).bind(status).bind(reviewer).bind(reason).bind(review.notes.as_deref())
                    .execute(observed(&mut *$tx)).await?;
                $tx.commit().await?;
                Ok(email)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                review!(tx, "julianday(expires_at)>julianday(CURRENT_TIMESTAMP)", "")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                review!(tx, "expires_at>clock_timestamp()", " FOR UPDATE")
            }
        }
    }
}
