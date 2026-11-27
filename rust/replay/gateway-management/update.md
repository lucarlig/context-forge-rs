# Gateway metadata and endpoint updates

`PUT /gateways/{id}`, `PUT /v1/gateways/{id}`, and `PUT /v1/mcp-servers/{id}` share the same authorization checks. Gateway metadata and the discovered catalog commit together. Renames preserve item IDs and update inherited names. Scope changes preserve any child visibility that differs from the gateway's previous visibility.

The live pinned comparison covered tag normalization, renames, visibility, audit fields, refresh interval validation and clearing, unknown fields, and version increments. A bearer-authenticated fixture accepted a new URL and returned HTTP 503 from a second URL. Both gateways returned HTTP 502 for the failed change and kept the previous URL, transport, and version. The fixture also tested unsupported schemes and transports and an unavailable SSE endpoint. Rust passed on native SQLite, PostgreSQL, and SQLite populated by the pinned gateway.

Rust returned HTTP 409 when an update duplicated another gateway's destination and credentials in the same scope. The pinned gateway returned HTTP 500. Rust persisted the validated identity propagation setting. The pinned gateway ignored that field in the update fixture.

```sh
cargo test --locked --test gateway gateway_update_preserves_catalog_ids_and_rolls_back_a_failed_destination
```

## Credential updates

The pinned and Rust gateways both kept a masked bearer token, used a rotated token for discovery, rejected a bad token with HTTP 502, cleared authentication on request, and accepted a one-time token for discovery. The failed update preserved the last working token and version. Rust writes SQL NULL for cleared credential fields and verified that the one-time token is absent from storage.

The Basic fixture changed the username while keeping the masked password. Both made successful requests with the new username, and Rust returned it in the update response. Both gateways also rotated one custom header while retaining another masked header. The query fixture changed the parameter name while keeping its stored value. Rust authenticated to the upstream with the new name. The pinned gateway returned HTTP 200 even though discovery used a rejected credential.

Rust passed bearer, Basic, header, and query checks on SQLite and PostgreSQL, and the bearer rotation passed against SQLite populated by the pinned gateway. The integration test exercises rotation, rollback, and subsequent MCP invocation.

```sh
cargo test --locked --test gateway registration_encrypts_bearer_credentials_and_uses_them_for_mcp_requests
```
