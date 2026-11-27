# Gateway metadata and endpoint updates

`PUT /gateways/{id}`, `PUT /v1/gateways/{id}`, and `PUT /v1/mcp-servers/{id}` share the same authorization checks. Gateway metadata and the discovered catalog commit together. Renames preserve item IDs and update inherited names. Scope changes preserve any child visibility that differs from the gateway's previous visibility.

The live pinned comparison covered tag normalization, renames, visibility, audit fields, refresh interval validation and clearing, unknown fields, and version increments. A bearer-authenticated fixture accepted a new URL and returned HTTP 503 from a second URL. Both gateways returned HTTP 502 for the failed change and kept the previous URL, transport, and version. The fixture also tested unsupported schemes and transports and an unavailable SSE endpoint. Rust passed on native SQLite, PostgreSQL, and SQLite populated by the pinned gateway.

Rust returned HTTP 409 when an update duplicated another gateway's destination and credentials in the same scope. The pinned gateway returned HTTP 500. Rust persisted the validated identity propagation setting. The pinned gateway ignored that field in the update fixture.

```sh
cargo test --locked --test gateway gateway_update_preserves_catalog_ids_and_rolls_back_a_failed_destination
```
