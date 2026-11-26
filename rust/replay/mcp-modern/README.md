# Modern MCP reference cases

These rust-anything recordings use the pinned ContextForge v1.1.2 gateway. The three profiles use isolated SQLite databases.

| Profile | Cases | Reference settings |
| --- | ---: | --- |
| `public-auto` | 32 | Auto inbound negotiation. Anonymous MCP access. Public `fixture-echo` upstream. |
| `public-legacy` | 3 | Legacy-only inbound negotiation. Anonymous MCP access. |
| `required-auto` | 2 | Auto inbound negotiation. Authentication required. |

Use JSON responses and stateless sessions. Disable rate limits, correlation IDs, and security headers in the reference profile. Configure `context-forge-modern-reference-server` on PATH to launch the profile at the supplied `PORT`.

For the public auto fixture, register `fixture-echo` over Streamable HTTP. Its `echo` tool returns `echo: <message>`. Keep that upstream reachable and point the Rust binary at the fixture database.

```sh
cargo build --locked --workspace
MCP_INBOUND_PROTOCOL_MODE=auto MCP_REQUIRE_AUTH=false SSRF_ALLOW_LOCALHOST=true \
  DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/mcp-modern/public-auto --build "$PWD/target/debug/context-forge-rs"
MCP_INBOUND_PROTOCOL_MODE=legacy MCP_REQUIRE_AUTH=false DATABASE_URL=sqlite:///:memory: \
  rust-anything app replay rust/replay/mcp-modern/public-legacy --build "$PWD/target/debug/context-forge-rs"
MCP_INBOUND_PROTOCOL_MODE=auto MCP_REQUIRE_AUTH=true DATABASE_URL=sqlite:///:memory: \
  rust-anything app replay rust/replay/mcp-modern/required-auto --build "$PWD/target/debug/context-forge-rs"
```
