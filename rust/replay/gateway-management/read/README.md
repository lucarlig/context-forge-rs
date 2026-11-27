# Gateway management reads

The fixtures cover the list and detail routes, including lookup by name, both versioned aliases, visibility filters, pagination response shape, missing records, and missing authentication. All eight recordings passed using SQLite initialized by Rust and SQLite initialized by the pinned gateway.

Live checks on SQLite and PostgreSQL covered cursor continuation, public-only visibility, and OAuth credential masking. Separate live checks matched the pinned Basic, bearer, custom-header, and query parameter masking fields. Rust signs continuation cursors and binds them to the caller and filters. Unknown cursors return the first page.

The recording disables response compression and omits the CORS `Vary` header from comparison. HTTP middleware is a separate milestone.

Initialize a disposable database with the migration files and fixture data. The token in the recording uses the synthetic JWT key below.

```sh
fixture_dir=$(mktemp -d)
sqlite3 "$fixture_dir/gateways.sqlite3" < rust/app/migrations/001_identity.sql
sqlite3 "$fixture_dir/gateways.sqlite3" < rust/app/migrations/002_catalog.sql
sqlite3 "$fixture_dir/gateways.sqlite3" < rust/replay/gateway-management/read/fixture.sql

DATABASE_URL="sqlite:///$fixture_dir/gateways.sqlite3" \
  JWT_SECRET_KEY=context-forge-auth-api-replay-fixture-key-4d414e4147454d454e54 \
  AUTH_ENCRYPTION_SECRET=context-forge-auth-api-encryption-fixture-key \
  rust-anything app replay rust/replay/gateway-management/read --build "$PWD/target/debug/context-forge-rs"
```
