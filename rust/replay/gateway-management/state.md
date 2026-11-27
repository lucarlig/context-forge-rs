# Gateway activation

`POST /v1/mcp-servers/{id}/state?activate=false` disables the gateway and its tools, resources, and prompts. The route also works under `/gateways` and `/v1/gateways`. The default value of `activate` is `true`.

Deactivation made no upstream request. On reactivation both gateways used the stored bearer credential and discovered the new tool, resource, and prompt catalog. After an upstream HTTP 503, both enabled the existing cached entries and returned a successful state response. The Rust checks passed on SQLite, PostgreSQL, and SQLite populated by the pinned gateway.

When reactivation discovered a changed catalog, the pinned gateway enabled its cached entries while leaving the gateway disabled. Rust commits the enabled state and catalog together. The legacy `/toggle` alias uses the same permission and ownership checks as `/state` in Rust. The pinned gateway returned HTTP 401 for the authenticated legacy request.
