# Resource management reads

The resource routes list metadata and templates, retrieve metadata by ID, and read content by ID or URI. The 11 pinned cases cover tag and gateway filters, versioned aliases, legacy tag casing, inactive resources, response shape, and public token scope. All recordings passed with native SQLite and with a database populated by the pinned gateway. The live PostgreSQL responses matched with timestamps normalized to UTC.

The resource audit columns are added to existing databases during catalog migration. A SQLite database initialized by the previous Rust version kept its existing resource and content, with a default version of 1. The HTTP comparison omits the CORS `Vary` header.

```sh
fixture_dir=$(mktemp -d)
sqlite3 "$fixture_dir/resources.sqlite3" < rust/app/migrations/001_identity.sql
sqlite3 "$fixture_dir/resources.sqlite3" < rust/app/migrations/002_catalog.sql
sqlite3 "$fixture_dir/resources.sqlite3" < rust/replay/resource-management/read/fixture.sql

DATABASE_URL="sqlite:///$fixture_dir/resources.sqlite3" \
  JWT_SECRET_KEY=context-forge-auth-api-replay-fixture-key-4d414e4147454d454e54 \
  rust-anything app replay rust/replay/resource-management/read --build "$PWD/target/debug/context-forge-rs"
```
