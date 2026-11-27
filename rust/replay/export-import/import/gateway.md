# Gateway configuration import

The six v1.1.2 recordings cover a dry run, creation, skipping a duplicate, failing on a duplicate, updating, and renaming. All six passed with Rust on SQLite and PostgreSQL. The capture seeds a public gateway and uses a loopback MCP fixture with an empty catalog. It normalizes job IDs, timestamps, and rename suffixes.

The Rust integration test compares status and progress with the records. It also verifies that the importer owns the gateway, that the caller's active personal team determines visibility, and that archived credentials work against an authenticated upstream. Imports use the configured key or the supplied source key to authenticate ciphertext and save credentials under the configured key. A wrong key and an attempt to update another owner's gateway are denied. Imports finish synchronously when async gateway lifecycle is enabled.

```sh
cargo test --locked --test gateway_import
```

Rust checks visible gateway name conflicts before upstream discovery. The pinned gateway can create duplicate team-scoped rows because it checks public scope before applying personal team ownership. It can also encounter upstream tool name conflicts before applying the requested gateway strategy. Rust resolves the strategy first and keeps the existing gateway's ownership and visibility on update.

Gateway import handles Basic, bearer, custom headers, and host-restricted query credentials. The export format omits OAuth and SigV4 secrets. Import rejects nonempty gateway tool validation policies until the Rust policy evaluator is available.
