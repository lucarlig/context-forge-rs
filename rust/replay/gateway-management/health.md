# Gateway health and automatic refresh

The health worker uses the gateway's stored connection settings. Streamable HTTP verifies MCP negotiation and legacy SSE checks the stream's HTTP status. Health failures update reachability and record a sanitized error after the configured threshold. Gateway and tool reachability change together. Cached tools remain in the list during an outage and invocation returns the same MCP tool error as the pinned gateway.

The pinned and Rust gateways both marked the bearer-authenticated fixture unreachable after it started returning HTTP 503. Both kept the gateway enabled and preserved its configuration version and cached catalog. When the fixture recovered with a changed catalog, both cleared the error and refreshed the tools. The Rust comparison passed on SQLite, PostgreSQL, and SQLite populated by the pinned gateway.

`HEALTH_CHECK_INTERVAL`, `GATEWAY_HEALTH_CHECK_TIMEOUT`, `UNHEALTHY_THRESHOLD`, and `MAX_CONCURRENT_HEALTH_CHECKS` control probes. `UNHEALTHY_THRESHOLD=-1` keeps probes running without marking gateways unreachable. Automatic refresh uses `AUTO_REFRESH_SERVERS` and `GATEWAY_AUTO_REFRESH_INTERVAL`, with a per-gateway interval if configured. Recovery reconciles the catalog independently of that interval.

```sh
cargo test --locked --test gateway gateway_health_preserves_enabled_state_and_recovers_the_catalog
```
