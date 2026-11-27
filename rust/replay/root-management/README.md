# Root management

The 15 pinned HTTP recordings cover the unversioned and versioned routes, URI normalization, root creation, rename, deletion, lookup, file prefix checks, and the unrestricted administrator requirement. Rust matched all response bodies and statuses. The comparison omits the CORS `Vary` header, which is covered by the middleware milestone.

The live Rust fixture also checked default roots, export, and add, update, and remove events on the SSE changes stream. The pinned stream closed at its first event because its URI object could not be serialized. Rust emits the canonical URI as a string.

```sh
fixture_dir=$(mktemp -d)
sqlite3 "$fixture_dir/roots.sqlite3" < rust/app/migrations/001_identity.sql
sqlite3 "$fixture_dir/roots.sqlite3" < rust/app/migrations/002_catalog.sql
sqlite3 "$fixture_dir/roots.sqlite3" < rust/replay/root-management/fixture.sql

DATABASE_URL="sqlite:///$fixture_dir/roots.sqlite3" \
  JWT_SECRET_KEY=context-forge-auth-api-replay-fixture-key-4d414e4147454d454e54 \
  ROOT_ALLOWED_SCHEMES='["https"]' ROOT_ALLOW_FILE_SCHEME=true \
  ROOT_ALLOWED_FILE_PREFIXES='["/workspace/team"]' \
  rust-anything app replay rust/replay/root-management --build "$PWD/target/debug/context-forge-rs"
```
