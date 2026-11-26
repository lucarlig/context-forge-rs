# ContextForge RS port map

Port all ContextForge gateway behavior to Rust. Ship a Rust binary and Rust-based build and test workflows with zero Python files or dependencies. The reference stays outside this repository.

Reference: IBM/mcp-context-forge `v1.1.2` (`ddc60dad6a825646bfb149c72d9d835fac80fceb`).

| Unit | State |
| --- | --- |
| HTTP health and readiness handlers | Implemented. Probe replay and Rust failure tests cover the handlers. |
| SQLite and PostgreSQL persistence | Connection pools and identity migration implemented. The remaining data and migration history are open. |
| First-party JWT, team visibility, and RBAC | Implemented for root MCP ingress. SQLite and PostgreSQL tests cover persisted roles and denial paths. |
| Request middleware | MCP Host and Origin allowlists implemented. Correlation IDs, security headers, rate limits, CORS, and trusted proxy headers are open. |
| Registry and control plane | Open. Includes catalog and ownership, users, teams, tokens, roles, imports, exports, audit, and migrations. |
| MCP data plane | Basic legacy stateless handshake and ping implemented. Catalog, execution, virtual servers, modern negotiation, streaming, replay, events, and other transports are open. |
| A2A, REST, and gRPC federation | Open. |
| Authentication providers and secrets | First-party bearer verification implemented. Login, issuance, token quotas, OAuth, SSO, and encrypted credentials are open. |
| Plugins | Open. Includes native implementations, lifecycle hooks, configuration, and out-of-process extensions. |
| Administration, observability, and operations | Open. Includes the UI backend, metrics, tracing, CLI commands, deployment, and migration verification. |

[Decisions](DECISIONS.md) · [Handoff](HANDOFF.md)
