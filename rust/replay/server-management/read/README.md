# Virtual-server reads and OAuth metadata

The 16 pinned ContextForge v1.1.2 cases exercise the server API aliases,
pagination, scoped access, persisted interfaces, active tool, resource, and
prompt associations, and RFC 9728 Protected Resource Metadata. The metadata
endpoint hides disabled and private servers. The management response masks
OAuth secrets. The deprecated server-scoped metadata URI redirects to the
path-based endpoint.

All cases passed on native SQLite, on the pinned SQLite schema, and in live
PostgreSQL comparisons. The replays normalize the request authority in the
OAuth metadata and redirect because the runner sets its own HTTP host. Direct
requests compared the complete URLs, redirect location, and cache headers.
The comparisons omit CORS headers.

```sh
fixture_dir=$(mktemp -d)
sqlite3 "$fixture_dir/servers.sqlite3" < rust/app/migrations/001_identity.sql
sqlite3 "$fixture_dir/servers.sqlite3" < rust/app/migrations/002_catalog.sql
sqlite3 "$fixture_dir/servers.sqlite3" < rust/replay/server-management/read/fixture.sql

APP_DOMAIN="https://gateway.fixture.test" \
  DATABASE_URL="sqlite:///$fixture_dir/servers.sqlite3" \
  JWT_SECRET_KEY=context-forge-auth-api-replay-fixture-key-4d414e4147454d454e54 \
  rust-anything app replay rust/replay/server-management/read --build "$PWD/target/debug/context-forge-rs"
```
