# Resource and prompt catalogs

The pinned v1.1.2 gateway registered an unauthenticated Streamable HTTP fixture that exposed one resource, one URI template, and one prompt. The gateway prefixed the names with `fixture-` and preserved the resource URI and URI template. Modern list results also included a private cache scope, a 300-second TTL, and server metadata.

The pinned gateway matched all six recordings. The Rust binary matched all three legacy cases on SQLite and PostgreSQL. The three modern cases on both backends differ only in the server version. The live Rust gateway test covers pagination, virtual-server membership, team visibility, and cursor rejection across methods.

Start the Rust binary once against an isolated SQLite database to create the schema. Load [the fixture](fixture.sql) and point the replay at the same database. The list methods read stored metadata and need no running upstream.

```sh
sqlite3 "$FIXTURE_DATABASE" < rust/replay/mcp-catalog/fixture.sql
USE_STATEFUL_SESSIONS=false MCP_INBOUND_PROTOCOL_MODE=auto MCP_REQUIRE_AUTH=false \
  DATABASE_URL="sqlite:///$FIXTURE_DATABASE" \
  rust-anything app replay rust/replay/mcp-catalog --build "$PWD/target/debug/context-forge-rs"
```

Native registration discovers resources, URI templates, and prompts and stores them in the same transaction as the gateway and tools. Native registrations of the live fixture produced the recorded list results on SQLite and PostgreSQL. The registration response preserves the reference's zero component counts. A Rust integration test also covers discovery across resource pages and upstreams that omit the tools capability.

Both gateways route a resource URI matching a stored template when the exact URI is absent. Both resolve `fixture-welcome` to the upstream prompt `welcome` and reject an unprefixed downstream prompt lookup. The Rust test covers a modern resource input round trip and checks that callers must declare elicitation before receiving the request. Authenticated resource reads use a private cache scope.

The local content suite under `content/` uses [a separate SQLite fixture](content/fixture.sql) for plain text, binary content, and a rendered prompt. The pinned gateway matched all eight recordings. Rust matched five, including the four legacy requests and the modern missing-argument error. The three successful modern responses differ only in the server version. Load `content/fixture.sql` and change the replay path above to `rust/replay/mcp-catalog/content` to run this suite.

The logging suite under `logging/` exercises valid legacy log levels, invalid legacy parameters, and the modern method-not-found response. Both gateways matched all 12 recordings. The Rust integration test also verifies runtime filter changes and covers an authenticated token whose scopes exclude `admin.system_config`. In permissive MCP mode the reference accepts anonymous level changes. Replay this suite with an empty disposable SQLite database and the same environment as the list cases.

Completions and resource subscriptions remain open. Local prompt rendering currently validates required arguments and accepts strings. The renderer enforces an execution and output limit.
