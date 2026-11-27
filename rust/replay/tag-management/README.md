# Tag management

The 10 pinned HTTP cases check counts across gateways, tools, resources, prompts, and virtual servers. They cover optional entity details, exact tag matching, entity-type filters, public token scope, and exclusion of another user's private tags. Both native SQLite and PostgreSQL matched the responses. The recording omits the CORS `Vary` header. Direct requests to the pinned gateway established the authorization-sensitive response bodies.

```sh
fixture_dir=$(mktemp -d)
sqlite3 "$fixture_dir/tags.sqlite3" < rust/app/migrations/001_identity.sql
sqlite3 "$fixture_dir/tags.sqlite3" < rust/app/migrations/002_catalog.sql
sqlite3 "$fixture_dir/tags.sqlite3" < rust/replay/tag-management/fixture.sql

DATABASE_URL="sqlite:///$fixture_dir/tags.sqlite3" \
  JWT_SECRET_KEY=context-forge-auth-api-replay-fixture-key-4d414e4147454d454e54 \
  rust-anything app replay rust/replay/tag-management --build "$PWD/target/debug/context-forge-rs"
```
