// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Map;

use super::{providers::Provider, *};
use crate::local_auth::storage::revoke_credentials;

pub(crate) struct SsoIdentityPolicy {
    pub(crate) approval_required: bool,
    pub(crate) allow_provider_linking: bool,
    pub(crate) teams: TeamSettings,
    pub(crate) admin_domains: HashSet<String>,
    pub(crate) github_admin_orgs: HashSet<String>,
    pub(crate) google_admin_domains: HashSet<String>,
    pub(crate) entra_admin_groups: HashSet<String>,
    pub(crate) generic_provider: String,
    pub(crate) generic_admin_groups: HashSet<String>,
}

pub(super) struct MappedAccess<'a> {
    pub(super) admin: bool,
    roles: BTreeSet<&'a str>,
    default_role: Option<&'a str>,
    sync_roles: bool,
    personal_scope: bool,
    pub(super) teams: Option<BTreeMap<String, String>>,
}

impl<'a> MappedAccess<'a> {
    pub(super) fn from_claims(
        provider: &'a Provider,
        policy: &SsoIdentityPolicy,
        defaults: &UserProvisioning,
        email: &str,
        groups: &[&str],
        claims: &Map<String, Value>,
    ) -> Self {
        let metadata = &provider.config.provider_metadata;
        let group_exists = |name: &str| {
            groups
                .iter()
                .any(|group| group.trim().eq_ignore_ascii_case(name.trim()))
        };
        let role_is_admin =
            |role: &str| matches!(role, "admin" | "platform_admin") || role == defaults.admin_role;
        let roles: BTreeSet<_> = metadata
            .get("role_mappings")
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|mapping| mapping.iter())
            .filter(|(group, _)| group_exists(group))
            .filter_map(|(_, role)| role.as_str().filter(|role| !role.is_empty()))
            .collect();
        let domain = email.rsplit_once('@').map_or("", |(_, domain)| domain);
        let in_domains = |domains: &HashSet<String>| {
            domains.iter().any(|name| domain.eq_ignore_ascii_case(name))
        };
        let admin = roles.iter().any(|role| role_is_admin(role))
            || in_domains(&policy.admin_domains)
            || provider.id == "google" && in_domains(&policy.google_admin_domains)
            || provider.id == "entra"
                && policy
                    .entra_admin_groups
                    .iter()
                    .any(|group| group_exists(group))
            || provider.id == policy.generic_provider
                && policy
                    .generic_admin_groups
                    .iter()
                    .any(|group| group_exists(group))
            || provider.id == "github"
                && claims
                    .get("organizations")
                    .and_then(Value::as_array)
                    .is_some_and(|orgs| {
                        orgs.iter().filter_map(Value::as_str).any(|org| {
                            policy
                                .github_admin_orgs
                                .iter()
                                .any(|name| name.eq_ignore_ascii_case(org))
                        })
                    })
            || metadata
                .get("admin_groups")
                .and_then(Value::as_array)
                .is_some_and(|admin_groups| {
                    admin_groups
                        .iter()
                        .filter_map(Value::as_str)
                        .any(group_exists)
                });
        let mapping = &provider.config.team_mapping;
        let teams = (!mapping.is_empty()).then(|| {
            mapping
                .iter()
                .filter(|(group, _)| !group.trim().is_empty() && group_exists(group))
                .filter_map(|(_, target)| {
                    let id = target
                        .as_str()
                        .or_else(|| target["team_id"].as_str())
                        .or_else(|| target["id"].as_str())?
                        .trim();
                    let role = target["role"]
                        .as_str()
                        .filter(|role| role.trim().eq_ignore_ascii_case("owner"))
                        .map_or("member", |_| "owner");
                    (!id.is_empty()).then(|| (id.to_owned(), role.to_owned()))
                })
                .collect()
        });
        Self {
            admin,
            roles,
            default_role: metadata
                .get("default_role")
                .and_then(Value::as_str)
                .filter(|role| !role.trim().is_empty()),
            sync_roles: metadata
                .get("sync_roles")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            personal_scope: metadata
                .get("resolve_team_scope_to_personal_team")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            teams,
        }
    }
}

type RoleAssignment = (String, String, Option<String>);

impl Database {
    pub(super) async fn sync_sso_roles_and_profile(
        &self,
        user: &storage::LocalUser,
        provider: &str,
        mapping: &MappedAccess<'_>,
        defaults: &UserProvisioning,
        name: Option<&str>,
        existing: bool,
    ) -> Result<bool, sqlx::Error> {
        let relinking = user.auth_provider != provider;
        macro_rules! sync {
            ($tx:ident,$lock:literal) => {{
                let Some((current_admin, origin)) = sqlx::query_as::<_,(bool,Option<String>)>(concat!(
                    "SELECT is_admin,admin_origin FROM email_users
                     WHERE id=$1 AND email=$2 AND auth_provider=$3 AND is_active", $lock))
                    .bind(&user.id).bind(&user.email).bind(&user.auth_provider)
                    .fetch_optional(&mut *$tx).await?
                else { return Ok(false); };
                let personal_team = if mapping.personal_scope {
                    sqlx::query_scalar::<_,String>("SELECT id FROM email_teams WHERE created_by=$1
                        AND is_personal AND is_active ORDER BY id LIMIT 1")
                        .bind(&user.email).fetch_optional(&mut *$tx).await?
                } else {
                    None
                };
                let mut desired = Vec::<RoleAssignment>::new();
                let mut matched = false;
                if mapping.sync_roles {
                    for role in &mapping.roles {
                        matched |= add_mapped_role!($tx, desired, role, defaults, mapping.personal_scope, personal_team);
                    }
                    if !matched && let Some(role) = mapping.default_role {
                        add_mapped_role!($tx, desired, role, defaults, mapping.personal_scope, personal_team);
                    }
                }
                let admin_role = sqlx::query_scalar::<_, String>(
                    "SELECT id FROM roles WHERE name=$1 AND scope='global' AND is_active")
                    .bind(&defaults.admin_role).fetch_optional(&mut *$tx).await?;
                let role_promotes = admin_role.as_ref().is_some_and(|role|
                    desired.iter().any(|(id,scope,_)| id==role && scope=="global"));
                let manual_admin = current_admin && !relinking && origin.as_deref()!=Some("sso");
                let admin = manual_admin || mapping.admin || role_promotes;
                let demoted = current_admin && !admin;
                let admin_origin = if manual_admin { origin.as_deref() } else { admin.then_some("sso") };
                sqlx::query("UPDATE email_users SET is_admin=$2,admin_origin=$3,full_name=COALESCE($4,full_name),
                    email_verified_at=CASE WHEN $5 THEN COALESCE(email_verified_at,CURRENT_TIMESTAMP) ELSE email_verified_at END,
                    last_login=CASE WHEN $5 THEN CURRENT_TIMESTAMP ELSE last_login END,
                    auth_provider=$6,updated_at=CURRENT_TIMESTAMP WHERE id=$1")
                    .bind(&user.id).bind(admin).bind(admin_origin).bind(name).bind(existing).bind(provider)
                    .execute(&mut *$tx).await?;
                if relinking {
                    revoke_credentials!($tx,&user.email,&user.email,"sso_provider_relinked");
                }
                if let Some(role) = admin_role {
                    if admin && !manual_admin {
                        desired.push((role,"global".to_owned(),None));
                    } else if demoted {
                        sqlx::query("UPDATE user_roles SET is_active=FALSE WHERE user_email=$1
                            AND role_id=$2 AND scope='global' AND scope_id IS NULL")
                            .bind(&user.email).bind(role).execute(&mut *$tx).await?;
                    }
                }
                if mapping.sync_roles || relinking {
                    let existing_roles = sqlx::query_as::<_, (String,String,String,Option<String>)>(
                        "SELECT id,role_id,scope,scope_id FROM user_roles
                         WHERE user_email=$1 AND is_active AND grant_source='sso'")
                        .bind(&user.email).fetch_all(&mut *$tx).await?;
                    for (id,role,scope,scope_id) in existing_roles {
                        if !desired.contains(&(role,scope,scope_id)) {
                            sqlx::query("UPDATE user_roles SET is_active=FALSE WHERE id=$1").bind(id)
                                .execute(&mut *$tx).await?;
                        }
                    }
                }
                for (id,scope,scope_id) in desired {
                    sqlx::query("INSERT INTO user_roles(id,user_email,role_id,scope,scope_id,granted_by,
                        granted_at,is_active,grant_source) VALUES($1,$2,$3,$4,$5,$2,CURRENT_TIMESTAMP,TRUE,'sso')
                        ON CONFLICT DO NOTHING")
                        .bind(Uuid::new_v4().to_string()).bind(&user.email).bind(id).bind(scope).bind(scope_id)
                        .execute(&mut *$tx).await?;
                }
                if demoted {
                    sqlx::query("INSERT INTO user_roles(id,user_email,role_id,scope,granted_by,granted_at,is_active)
                        SELECT $1,$2,id,'global',$2,CURRENT_TIMESTAMP,TRUE FROM roles
                        WHERE name=$3 AND scope='global' AND is_active ON CONFLICT DO NOTHING")
                        .bind(Uuid::new_v4().to_string()).bind(&user.email).bind(&defaults.user_role)
                        .execute(&mut *$tx).await?;
                }
                $tx.commit().await?;
                Ok(true)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                sync!(tx, "")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sync!(tx, " FOR UPDATE")
            }
        }
    }
}

macro_rules! add_mapped_role {
    ($tx:ident,$desired:ident,$role:expr,$defaults:ident,$personal:expr,$team:ident) => {{
        let role: &str = $role;
        let global = matches!(role, "admin" | "platform_admin") || role == $defaults.admin_role;
        let role = if global { $defaults.admin_role.as_str() } else {role};
        let found = sqlx::query_as::<_,(String,String)>(
            "SELECT id,scope FROM roles WHERE name=$1 AND is_active AND (scope='global' OR (NOT $2 AND scope='team'))
             ORDER BY CASE WHEN scope='team' THEN 0 ELSE 1 END LIMIT 1")
            .bind(role).bind(global).fetch_optional(&mut *$tx).await?;
        match found {
            Some((id, scope)) if scope == "team" && $personal => {
                if let Some(team) = &$team {
                    $desired.push((id,scope,Some(team.clone())));
                    true
                } else {false}
            }
            Some((id,scope)) => { $desired.push((id,scope,None)); true }
            None => false,
        }
    }};
}

use add_mapped_role;
