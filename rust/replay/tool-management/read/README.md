# Tool management reads

The 15 pinned ContextForge v1.1.2 recordings cover list and detail routes,
filters, pagination, inactive tools, header masking, and JSONPath projection.
The dry-run preview validates arguments and checks tool membership in a virtual
server. It returns the gateway name for federated tools. The replay fixture uses
local catalog tools and requires no upstream requests.

All cases passed with native SQLite, with the pinned SQLite schema, and in live
PostgreSQL comparisons after timezone normalization. The replay omits the CORS
`Vary` header. Invalid preview arguments produce an `invalid_arguments`
warning with the native JSON Schema diagnostic.

```sh
fixture_dir=$(mktemp -d)
sqlite3 "$fixture_dir/tools.sqlite3" < rust/app/migrations/001_identity.sql
sqlite3 "$fixture_dir/tools.sqlite3" < rust/app/migrations/002_catalog.sql
sqlite3 "$fixture_dir/tools.sqlite3" < rust/replay/tool-management/read/fixture.sql

DATABASE_URL="sqlite:///$fixture_dir/tools.sqlite3" \
  JWT_SECRET_KEY=context-forge-auth-api-replay-fixture-key-4d414e4147454d454e54 \
  rust-anything app replay rust/replay/tool-management/read --build "$PWD/target/debug/context-forge-rs"
```
