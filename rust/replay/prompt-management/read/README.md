# Prompt management reads

The recordings exercise prompt listing, pagination, tag filters, ID and name lookup,
raw template retrieval, argument rendering, inactive prompts, and public token
scope. All 12 cases passed with native SQLite and with SQLite populated by pinned
ContextForge v1.1.2. Live PostgreSQL checks matched after normalizing timestamp
representations. The recordings omit the CORS `Vary` header.

Prompt audit fields and display names are added during startup for databases
created by earlier Rust builds. The REST list returns the pinned API's null
`title` field. MCP discovery continues to use titles stored in the catalog.

```sh
fixture_dir=$(mktemp -d)
sqlite3 "$fixture_dir/prompts.sqlite3" < rust/app/migrations/001_identity.sql
sqlite3 "$fixture_dir/prompts.sqlite3" < rust/app/migrations/002_catalog.sql
sqlite3 "$fixture_dir/prompts.sqlite3" < rust/replay/prompt-management/read/fixture.sql

DATABASE_URL="sqlite:///$fixture_dir/prompts.sqlite3" \
  JWT_SECRET_KEY=context-forge-auth-api-replay-fixture-key-4d414e4147454d454e54 \
  rust-anything app replay rust/replay/prompt-management/read --build "$PWD/target/debug/context-forge-rs"
```
