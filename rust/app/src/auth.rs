// SPDX-License-Identifier: Apache-2.0
//! Token visibility and permission scope for verified claims.

use std::collections::HashSet;
use std::fmt;

use serde_json::Value;

/// Resource visibility associated with a verified identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TeamVisibility {
    /// Public and team resources across the platform, plus the caller's own private resources.
    Admin,
    /// Public resources only.
    Public,
    /// Public resources, the specified teams, and the caller's own private resources.
    Teams(Vec<String>),
}

impl TeamVisibility {
    pub(crate) fn from_teams(teams: Vec<String>) -> Self {
        if teams.is_empty() {
            Self::Public
        } else {
            Self::Teams(teams)
        }
    }
}

/// A malformed claim that cannot select a visibility scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidClaim {
    Payload,
    Teams,
    Admin,
}

impl fmt::Display for InvalidClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Payload => "token payload must be an object",
            Self::Teams => "teams claim must be null or an array",
            Self::Admin => "is_admin claim must be a boolean",
        })
    }
}

impl std::error::Error for InvalidClaim {}

/// Resolve visibility for an API or legacy token after the caller verifies it.
///
/// Absent teams means public access. An explicit null teams claim permits admin
/// visibility when the verified token carries a boolean admin grant.
///
/// # Errors
///
/// Returns an error for an invalid payload, teams shape, or admin grant.
pub fn normalize_api_teams(payload: &Value) -> Result<TeamVisibility, InvalidClaim> {
    let claims = payload.as_object().ok_or(InvalidClaim::Payload)?;

    match claims.get("teams") {
        None => Ok(TeamVisibility::Public),
        Some(Value::Null) => {
            let nested_admin = claims.get("user").and_then(|user| user.get("is_admin"));
            let admin = admin_claim(claims.get("is_admin"))? || admin_claim(nested_admin)?;
            Ok(if admin {
                TeamVisibility::Admin
            } else {
                TeamVisibility::Public
            })
        }
        Some(Value::Array(teams)) => Ok(TeamVisibility::from_teams(
            teams
                .iter()
                .filter_map(team_id)
                .map(str::to_owned)
                .collect(),
        )),
        Some(_) => Err(InvalidClaim::Teams),
    }
}

/// Narrow database-resolved session visibility using claims from a verified token.
///
/// The caller resolves the authenticated email, active memberships, and admin
/// flag before supplying `db_visibility` from the database. An absent identity
/// gets public visibility. For team members, a nonempty teams claim limits
/// access to the intersection with database teams.
///
/// # Errors
///
/// Returns an error for an invalid payload or teams shape.
pub fn resolve_session_teams(
    payload: &Value,
    email: Option<&str>,
    db_visibility: &TeamVisibility,
) -> Result<TeamVisibility, InvalidClaim> {
    let claims = payload.as_object().ok_or(InvalidClaim::Payload)?;
    if email.is_none_or(|email| email.trim().is_empty()) {
        return Ok(TeamVisibility::Public);
    }

    let Some(requested) = session_team_claim(claims.get("teams"))? else {
        return Ok(db_visibility.clone());
    };

    let TeamVisibility::Teams(db_teams) = db_visibility else {
        return Ok(db_visibility.clone());
    };

    let requested_ids: HashSet<_> = requested.iter().filter_map(team_id).collect();
    let intersection = db_teams
        .iter()
        .filter(|id| requested_ids.contains(id.as_str()))
        .cloned()
        .collect();
    Ok(TeamVisibility::from_teams(intersection))
}

pub(crate) fn unrestricted_session_teams(payload: &Value) -> bool {
    payload
        .as_object()
        .is_some_and(|claims| matches!(session_team_claim(claims.get("teams")), Ok(None)))
}

fn session_team_claim(teams: Option<&Value>) -> Result<Option<&[Value]>, InvalidClaim> {
    match teams {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(teams)) if teams.is_empty() => Ok(None),
        Some(Value::Array(teams)) => Ok(Some(teams)),
        Some(_) => Err(InvalidClaim::Teams),
    }
}

/// Check whether a token's permission scope permits an RBAC check to proceed.
///
/// Absent or empty scope inherits the database policy. MCP method permissions
/// permit `servers.use` so the client can reach the transport.
pub fn token_scope_grants(scopes: Option<&[String]>, permission: &str) -> bool {
    let Some(scopes) = scopes.filter(|scopes| !scopes.is_empty()) else {
        return true;
    };
    let permission_category = permission.split_once('.').map(|(category, _)| category);

    scopes.iter().any(|scope| {
        scope == "*"
            || scope == permission
            || scope
                .strip_suffix(".*")
                .is_some_and(|category| Some(category) == permission_category)
            || (permission == "servers.use"
                && ["tools.", "resources.", "prompts."]
                    .iter()
                    .any(|prefix| scope.starts_with(prefix)))
    })
}

fn admin_claim(value: Option<&Value>) -> Result<bool, InvalidClaim> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(is_admin)) => Ok(*is_admin),
        Some(_) => Err(InvalidClaim::Admin),
    }
}

fn team_id(team: &Value) -> Option<&str> {
    let id = team.as_str().or_else(|| team.get("id")?.as_str())?;
    (!id.trim().is_empty()).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn api_admin_requires_explicit_null_teams() {
        for claims in [
            json!({"is_admin": true}),
            json!({"is_admin": true, "teams": []}),
            json!({"is_admin": false, "teams": null}),
            json!({"teams": null, "user": "invalid"}),
        ] {
            assert_eq!(normalize_api_teams(&claims), Ok(TeamVisibility::Public));
        }

        for claims in [
            json!({"is_admin": true, "teams": null}),
            json!({"user": {"is_admin": true}, "teams": null}),
            json!({"is_admin": false, "user": {"is_admin": true}, "teams": null}),
        ] {
            assert_eq!(normalize_api_teams(&claims), Ok(TeamVisibility::Admin));
        }

        assert_eq!(
            normalize_api_teams(&json!({"is_admin": true, "teams": ["a", {"id": "b"}]})),
            Ok(TeamVisibility::Teams(vec!["a".into(), "b".into()]))
        );
    }

    #[test]
    fn malformed_claims_grant_no_additional_visibility() {
        assert_eq!(normalize_api_teams(&json!([])), Err(InvalidClaim::Payload));
        assert_eq!(
            normalize_api_teams(&json!({"teams": "a", "is_admin": true})),
            Err(InvalidClaim::Teams)
        );
        assert_eq!(
            normalize_api_teams(&json!({"teams": null, "is_admin": "false"})),
            Err(InvalidClaim::Admin)
        );
        assert_eq!(
            normalize_api_teams(&json!({"teams": null, "user": {"is_admin": 1}})),
            Err(InvalidClaim::Admin)
        );
        assert_eq!(
            normalize_api_teams(&json!({"teams": [{"id": 7}, 8, {"name": "no id"}, " ", "a"]})),
            Ok(TeamVisibility::Teams(vec!["a".into()]))
        );
    }

    #[test]
    fn session_teams_intersect_db_membership_in_database_order() {
        let db = TeamVisibility::Teams(vec!["a".into(), "b".into(), "c".into()]);
        let email = Some("member@example.com");

        for claims in [json!({}), json!({"teams": null}), json!({"teams": []})] {
            assert_eq!(resolve_session_teams(&claims, email, &db), Ok(db.clone()));
        }

        assert_eq!(
            resolve_session_teams(&json!({"teams": ["c", "revoked", {"id": "a"}]}), email, &db),
            Ok(TeamVisibility::Teams(vec!["a".into(), "c".into()]))
        );
        for claims in [json!({"teams": ["revoked"]}), json!({"teams": [42]})] {
            assert_eq!(
                resolve_session_teams(&claims, email, &db),
                Ok(TeamVisibility::Public)
            );
        }
        assert_eq!(
            resolve_session_teams(&json!({"teams": "revoked"}), email, &db),
            Err(InvalidClaim::Teams)
        );
        assert_eq!(
            resolve_session_teams(
                &json!({"teams": [{"id": 42}]}),
                email,
                &TeamVisibility::Teams(vec!["42".into()]),
            ),
            Ok(TeamVisibility::Public)
        );
    }

    #[test]
    fn session_admin_depends_on_database_and_resolved_identity() {
        let email = Some("member@example.com");
        assert_eq!(
            resolve_session_teams(
                &json!({"teams": ["a"], "is_admin": false}),
                email,
                &TeamVisibility::Admin
            ),
            Ok(TeamVisibility::Admin)
        );
        assert_eq!(
            resolve_session_teams(
                &json!({"teams": null, "is_admin": true}),
                email,
                &TeamVisibility::Public
            ),
            Ok(TeamVisibility::Public)
        );
        for email in [None, Some("")] {
            assert_eq!(
                resolve_session_teams(&json!({"is_admin": true}), email, &TeamVisibility::Admin),
                Ok(TeamVisibility::Public)
            );
        }
    }

    #[test]
    fn permission_scopes_keep_transport_grants_narrow() {
        assert!(token_scope_grants(None, "tools.read"));
        assert!(token_scope_grants(Some(&[]), "tools.read"));
        for (scope, permission, allowed) in [
            ("*", "admin.system_config", true),
            ("tools.*", "tools.execute", true),
            ("tools.*", "resources.read", false),
            ("tools.*", "toolsomething.read", false),
            ("tools.read", "tools.read", true),
            ("tools.read", "tools.execute", false),
            ("tools.execute", "servers.use", true),
            ("resources.read", "servers.use", true),
            ("prompts.read", "servers.use", true),
            ("a2a.read", "servers.use", false),
            ("tools.execute", "servers.read", false),
            ("tools.execute", "admin.system_config", false),
        ] {
            assert_eq!(
                token_scope_grants(Some(&[scope.into()]), permission),
                allowed,
                "{scope} → {permission}"
            );
        }
    }
}
