# Configuration import

The v1.1.2 reference capture exercised both API prefixes, validation, dry runs, conflicts, ownership, job status, and cleanup. The five stored unauthenticated recordings match the Rust status, authentication challenge, and JSON body. The reference also sends `Vary`; compression middleware remains pending.

```sh
cargo build --locked --bin context-forge-rs
DATABASE_URL=sqlite:///:memory: rust-anything app replay \
  rust/replay/export-import/import --build "$PWD/target/debug/context-forge-rs" --redact
```

The Rust import routes require global `admin.import`. Root imports also require an unrestricted platform administrator. Dry runs cover all six entity families and leave the catalog intact. This slice writes tools and roots. Tool imports preserve the target's ownership on updates and assign new records to the caller. SQLite live checks cover conflict handling, root guards, selection, and status cleanup. PostgreSQL live checks cover ownership, provenance, and credential rekeying from the supplied source key to the gateway's configured key.

Rust applies only the selected entities. Job status and cleanup are scoped to the importer for delegated callers. Gateway, resource, prompt, and virtual-server writes through import remain pending.
