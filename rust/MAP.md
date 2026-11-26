# ContextForge RS port map

Port all ContextForge gateway behavior to Rust. Ship a Rust binary and Rust-based build and test workflows with zero Python files or dependencies. The reference stays outside this repository.

Reference: IBM/mcp-context-forge `v1.1.2` (`ddc60dad6a825646bfb149c72d9d835fac80fceb`).

| Unit | State |
| --- | --- |
| HTTP health and readiness handlers | Implemented. Probe-profile replay and Rust failure tests cover the handlers. |
| SQLite and PostgreSQL connection pools | Implemented for connectivity. Schema and migrations are open. |
| Token team visibility and permission scope | Implemented as policy functions. JWT authentication, database identity and roles, and route enforcement are open. |
| Request middleware | Open. Includes correlation IDs, security headers, rate limits, CORS, and trusted proxy headers. |
| Registry and control plane | Open. Includes catalog and ownership, users, teams, tokens, roles, imports, exports, audit, and migrations. |
| MCP data plane | Open. Includes legacy and modern negotiation, discovery, virtual servers, catalog pagination, execution, streaming, replay, events, and all documented transports. |
| A2A, REST, and gRPC federation | Open. |
| Authentication providers and secrets | Open. Includes OAuth, SSO, API and session tokens, and encrypted credentials. |
| Plugins | Open. Includes native implementations, lifecycle hooks, configuration, and out-of-process extensions. |
| Administration, observability, and operations | Open. Includes the UI backend, metrics, tracing, CLI commands, deployment, and migration verification. |

[Decisions](DECISIONS.md) · [Handoff](HANDOFF.md)
