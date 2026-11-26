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

Resource reads and prompt retrieval remain open. The reference routed a resource URI matching a stored template even when the exact URI was absent. It resolved `fixture-welcome` to the upstream prompt `welcome` and rejected an unprefixed downstream prompt lookup. New native registrations still populate the tool catalog only.
