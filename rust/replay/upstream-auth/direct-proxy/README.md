# Direct-proxy MCP

Set `MCPGATEWAY_DIRECT_PROXY_ENABLED=true` and register an upstream with `gatewayMode: "direct_proxy"`. A request with `X-Context-Forge-Gateway-Id` can call a tool by its upstream name or read a resource by its upstream URI on root and virtual-server MCP routes. Registration still discovers and stores the catalog for requests that use cache mode.

The Rust gateway matched all five recorded live invocation, resource read, and cache fallback cases. The capture disables sunset headers with `LEGACY_API_SUNSET_DATE`. Live requests also verified modern MCP results, a private gateway denial, and a rejected registration with the feature disabled. The private denial was checked outside the replay harness.

For replay, use a public direct-proxy Streamable HTTP fixture with gateway ID `612ae0150afe4eed99756befc6cc0253` and a public virtual server with ID `v`. Register its cached tool as `proxy-cached`. The live upstream responds to `live-one` with `raw: live-one` and to `cached` with `raw: cached`. Both results include `structuredContent: {"fixture": true}`. It serves `fixture://example/live` as the text `raw resource`.

```sh
MCPGATEWAY_DIRECT_PROXY_ENABLED=true MCP_REQUIRE_AUTH=false MCP_CLIENT_CONNECT_MODE=legacy \
  USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/upstream-auth/direct-proxy --build "$PWD/target/debug/context-forge-rs"
```
