# Upstream header forwarding

The pinned and Rust gateways matched three recorded MCP tool calls. A per-gateway allowlist forwarded `X-Tenant-Id`. An explicit `X-Upstream-Authorization` became upstream `Authorization` on an uncredentialed gateway. A bearer-authenticated upstream kept its stored credential when the caller supplied the explicit upstream header. Live Rust registration and invocation passed on SQLite and PostgreSQL.

`ENABLE_HEADER_PASSTHROUGH=true` enables configured forwarding. A gateway's `passthroughHeaders` list overrides the global list. Use `PASSTHROUGH_HEADERS_SOURCE` to select `env`, `db`, or `merge`, with `DEFAULT_PASSTHROUGH_HEADERS` providing the environment list. Rust requires `ENABLE_SENSITIVE_HEADER_PASSTHROUGH=true` and an allowlist entry for sensitive headers on legacy and modern MCP. The pinned legacy route forwarded sensitive headers from a per-gateway allowlist with this flag disabled during a separate probe.

For replay, use the Streamable HTTP fixture described in the [authentication notes](../README.md). Register `forward` with `X-Tenant-Id` as its allowlist, `explicit` with caller-provided upstream authentication, and `bearer` with a stored bearer credential. Each fixture returns its gateway name followed by the tool argument.

```sh
ENABLE_HEADER_PASSTHROUGH=true MCP_REQUIRE_AUTH=false MCP_INBOUND_PROTOCOL_MODE=legacy \
  MCP_CLIENT_CONNECT_MODE=legacy USE_STATEFUL_SESSIONS=false SSRF_ALLOW_LOCALHOST=true \
  DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/upstream-auth/headers --build "$PWD/target/debug/context-forge-rs"
```
