# Gateway impact and deletion

The impact response lists visible virtual servers connected through the gateway's tools, resources, or prompts. The recording includes the unversioned and current versioned routes, deletion of a missing gateway, successful deletion, and a subsequent read of both the deleted gateway and an unaffected gateway.

All six requests replayed using SQLite initialized by Rust and by the pinned gateway. Live checks verified cleanup of a tool and its virtual-server association on SQLite and PostgreSQL. The pinned-schema SQLite test also verified removal of a tool metric row. The PostgreSQL fixture confirmed that a caller with the delete permission also needed ownership authority.

The recording replays an ordered sequence that changes its fixture database. Use a fresh database for each run.

```sh
fixture_dir=$(mktemp -d)
sqlite3 "$fixture_dir/gateways.sqlite3" < rust/app/migrations/001_identity.sql
sqlite3 "$fixture_dir/gateways.sqlite3" < rust/app/migrations/002_catalog.sql
sqlite3 "$fixture_dir/gateways.sqlite3" < rust/replay/gateway-management/read/fixture.sql
sqlite3 "$fixture_dir/gateways.sqlite3" < rust/replay/gateway-management/delete/fixture.sql

DATABASE_URL="sqlite:///$fixture_dir/gateways.sqlite3" \
  JWT_SECRET_KEY=context-forge-auth-api-replay-fixture-key-4d414e4147454d454e54 \
  AUTH_ENCRYPTION_SECRET=context-forge-auth-api-encryption-fixture-key \
  rust-anything app replay rust/replay/gateway-management/delete --build "$PWD/target/debug/context-forge-rs"
```
