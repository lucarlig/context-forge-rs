# Standing gateway catalog listeners

Set `GATEWAY_MODERN_LISTENERS_ENABLED=true` to open a standing
`subscriptions/listen` stream for each eligible Streamable HTTP upstream.
The gateway reconciles the full catalog when a stream is acknowledged. A tools
change refreshes all three lists. A resources or prompts change refreshes tools
and the affected list. Legacy upstreams use scheduled refresh, and the standing
listener skips OAuth and SigV4 configurations as the pinned service does.

Live tests used bearer-authenticated fixtures against ContextForge v1.1.2 and
Rust. They verified reconciliation on acknowledgment, preservation of prompts
during a resources-only update, and catalog refresh on change notifications.
SQLite and PostgreSQL passed with file-lock election. With Redis election, two
workers sharing a SQLite database kept one upstream stream and the second
worker took over after the first exited. The authenticated per-resource
subscription fixture also passed after the listener implementation was shared.

Set `PRIMARY_WORKER_ELECTION_BACKEND=redis` with `CACHE_TYPE=redis` and
`REDIS_URL` to elect one listener worker across hosts. File-lock election uses a
port-scoped path unless `PRIMARY_WORKER_LOCK_PATH` is configured.
