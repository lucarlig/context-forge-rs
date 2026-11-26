# Handoff

Start with [the port map](MAP.md). The source classifier found 77 units, including 11 blocked units. The root Python application and API package are among the blocked units. Port those by behavior using the existing HTTP and protocol tests.

The Rust workspace lives in `rust/app`. The probe and authentication-required cases are in `rust/app-cases`. Replay the original with rust-anything v5.0.1 and a reference launcher named `context-forge-reference-server` on PATH. Bind the original to the supplied `PORT` and use an isolated SQLite database. Set `RATE_LIMITING_ENABLED=false`, `CORRELATION_ID_ENABLED=false`, and `SECURITY_HEADERS_ENABLED=false` for both profiles.

Legacy MCP fixtures live under `rust/replay/mcp-legacy`. Enable legacy inbound mode and stateless JSON responses in the original launcher. Disable MCP authentication for the fixture. Register a deterministic public MCP gateway named `fixture-echo` with an `echo` tool that returns `echo: <message>`. Replay against a Rust gateway with the same fixture database and live upstream.

```sh
MCP_REQUIRE_AUTH=false SSRF_ALLOW_LOCALHOST=true DATABASE_URL="$FIXTURE_DATABASE_URL" \
  rust-anything app replay rust/replay/mcp-legacy --build "$PWD/target/debug/context-forge-rs"
```

The Rust binary matched eight of ten legacy cases, including tool listing and invocation. Both initialization cases differ in the advertised capabilities, instructions, and version. All three probe and authentication-required cases matched.

Next, wire modern MCP discovery and routing to the scoped catalog and test the status, headers, and metadata against the pinned gateway.
