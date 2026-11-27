// SPDX-License-Identifier: Apache-2.0

use axum::extract::rejection::JsonRejection;

use super::*;

const DEFAULT_TEST_QUERY: &str = "ContextForge A2A agent connectivity test";

pub(super) async fn metrics(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, CatalogApiError> {
    require(&app, &principal, "a2a.read").await?;
    if !app.a2a_metrics.enabled {
        return Err(CatalogApiError::detail(
            StatusCode::NOT_FOUND,
            "A2A metrics are disabled",
        ));
    }
    let result = app
        .database
        .scoped_agent_metrics(
            access::catalog_scope(Some(&principal)),
            app.a2a_metrics.raw_window,
        )
        .await?;
    Ok(Json(result.wire()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestInput {
    query: Option<String>,
}

pub(super) async fn test(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    input: Result<Option<Json<Option<TestInput>>>, JsonRejection>,
) -> Result<Json<Value>, CatalogApiError> {
    require(&app, &principal, "a2a.invoke").await?;
    let input = input.map_err(|_| CatalogApiError(
        StatusCode::UNPROCESSABLE_ENTITY,
        json!({"detail":[{"type":"value_error","loc":["body"],"msg":"Invalid A2A test request"}]}),
    ))?;
    let query = input
        .and_then(|Json(input)| input)
        .and_then(|input| input.query);
    if query
        .as_ref()
        .is_some_and(|query| query.chars().count() > 4096)
    {
        return Err(CatalogApiError(
            StatusCode::UNPROCESSABLE_ENTITY,
            json!({"detail":[{"type":"string_too_long","loc":["body","query"],
                "msg":"String should have at most 4096 characters"}]}),
        ));
    }
    let missing = || {
        failure(
            StatusCode::NOT_FOUND,
            "not_found",
            "A2A agent not found",
            &id,
        )
    };
    let agent = find(&app, Some(&principal), AgentLookup::Id(&id))
        .await
        .map_err(|error| {
            if error.0 == StatusCode::NOT_FOUND {
                missing()
            } else {
                error
            }
        })?;
    if !agent.enabled {
        return Err(failure(
            StatusCode::BAD_GATEWAY,
            "agent_disabled",
            "A2A agent is disabled",
            &id,
        ));
    }
    let query = query
        .as_deref()
        .filter(|query| !query.is_empty())
        .unwrap_or(DEFAULT_TEST_QUERY);
    let mut parameters = Map::from_iter([("query".into(), json!(query))]);
    if !matches!(agent.agent_type.as_str(), "generic" | "jsonrpc")
        && !agent.endpoint_url.ends_with('/')
    {
        parameters.insert("message".into(), json!(query));
        parameters.insert("test".into(), json!(true));
        parameters.insert("timestamp".into(), json!(Timestamp::now().as_second()));
    }
    let result = invoke_recorded(
        &app,
        &agent,
        Invocation {
            parameters,
            interaction_type: "test".into(),
        },
        &headers,
    )
    .await
    .map_err(|error| {
        if error.0 == StatusCode::NOT_FOUND {
            missing()
        } else if error.0.is_server_error() {
            failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "A2A agent test failed",
                &id,
            )
        } else {
            failure(StatusCode::BAD_GATEWAY, "agent_error", FAILURE, &id)
        }
    })?;
    Ok(Json(
        json!({"success":true,"result":result,"agent_name":agent.name,
        "test_timestamp":Timestamp::now().as_millisecond() as f64 / 1000.0}),
    ))
}

fn failure(status: StatusCode, kind: &str, message: &str, id: &str) -> CatalogApiError {
    CatalogApiError(
        status,
        json!({"detail":{"success":false,"error":message,"error_type":kind,"agent_id":id}}),
    )
}
