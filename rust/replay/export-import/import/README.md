# Configuration import

The v1.1.2 reference capture exercised both API prefixes, validation, dry runs, conflicts, ownership, job status, and cleanup. The five stored unauthenticated recordings match the Rust status, authentication challenge, and JSON body. The reference also sends `Vary`; compression middleware remains pending.

```sh
cargo build --locked --bin context-forge-rs
DATABASE_URL=sqlite:///:memory: rust-anything app replay \
  rust/replay/export-import/import --build "$PWD/target/debug/context-forge-rs" --redact
```

The Rust import routes require global `admin.import`. Root imports also require an unrestricted platform administrator. Dry runs cover all six entity families. Imports preserve target ownership on updates and derive new record ownership from the caller. SQLite live checks cover all six families, conflicts, root guards, selection, and status cleanup. PostgreSQL live checks cover ownership, provenance, and credential rekeying from the supplied source key to the gateway's configured key.

Rust applies only the selected entities. Job status and cleanup are scoped to the importer for delegated callers. Resource imports apply supplied content on update and preserve the stored content when the bundle omits it. The pinned gateway reported successful resource replacement while retaining the original content in the captured update.

Virtual-server imports resolve visible tool IDs and names. Updates with no resolved tools preserve the existing links. An omitted instructions field preserves the override, and an explicit null clears it. [Pinned virtual-server outcomes](virtual-servers.expected.json)

Gateway imports resolve visible name conflicts before discovery and complete synchronously. The [gateway import notes](gateway.md) document credential handling and the reference replay.
