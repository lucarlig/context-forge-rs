# Manual gateway refresh

`POST /v1/mcp-servers/{id}/tools/refresh` refreshes tools by default. The `include_resources` and `include_prompts` query flags include those catalogs. The route is also available under `/gateways` and `/v1/gateways`.

The pinned and Rust gateways registered a bearer-authenticated fixture, then refreshed its changing catalog. Both reported one tool added, one updated, and one removed during the tools-only refresh. The full refresh updated two retained tools and added, updated, and removed one resource and one prompt. Retained tools, resources, and prompts kept their IDs. Native verification passed on SQLite, PostgreSQL, and SQLite populated by the pinned gateway.

Both gateways rejected a concurrent refresh with HTTP 409 and kept the cached catalog when upstream discovery failed. A disabled gateway returned a successful response with zero changes. For an unchanged full catalog the pinned gateway reported some entries as updated. Rust reports zero item changes when metadata is unchanged.

The Rust integration test verifies requested catalog selection, retention of a virtual-server tool association, and preservation of cache entries after an upstream failure.

```sh
cargo test --locked --test gateway manual_refresh_keeps_retained_tool_ids_and_reconciles_requested_metadata
```
