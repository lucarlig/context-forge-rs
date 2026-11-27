# Direct-proxy MCP

Set `MCPGATEWAY_DIRECT_PROXY_ENABLED=true` and register an upstream with `gatewayMode: "direct_proxy"`. A request with `X-Context-Forge-Gateway-Id` can call a tool by its upstream name or read a resource by its upstream URI on root and virtual-server MCP routes. Registration still discovers and stores the catalog for requests that use cache mode.

On virtual-server MCP routes the same header selects live `tools/list` and `resources/list` catalogs. Both gateways return an error if the collected catalog requires multiple pages and Redis is unavailable. With shared Redis, both gateways replayed the same snapshot from a second worker after the upstream catalog changed. They rejected the continuation when the caller changed a forwarded tenant header.

The Rust gateway matched all seven recorded invocation, resource read, catalog, and cache fallback cases. The capture disables sunset headers by setting `LEGACY_API_SUNSET_DATE` to an empty string. Live requests also verified modern MCP results, a private gateway denial, and a rejected registration with the feature disabled.

For replay, use a public direct-proxy Streamable HTTP fixture with gateway ID `612ae0150afe4eed99756befc6cc0253` and a public virtual server with ID `v`. Register its cached tool as `proxy-cached`. The live upstream responds to `live-one` with `raw: live-one` and to `cached` with `raw: cached`. Both results include `structuredContent: {"fixture": true}`. It lists tools `live-one`, `live-two`, and `live-three`, and lists and serves `fixture://example/live` as `note` with the text `raw resource`.

```sh
MCPGATEWAY_DIRECT_PROXY_ENABLED=true MCP_REQUIRE_AUTH=false MCP_CLIENT_CONNECT_MODE=legacy \
  MCP_LIST_PAGE_SIZE=2 CACHE_TYPE=database \
  USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/upstream-auth/direct-proxy --build "$PWD/target/debug/context-forge-rs"
```
