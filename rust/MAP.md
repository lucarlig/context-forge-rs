# ContextForge RS port map

Port all ContextForge gateway behavior to Rust. Ship a Rust binary and Rust-based build and test workflows with zero Python files or dependencies. Keep the reference outside this repository.

Reference release [v1.1.2](https://github.com/IBM/mcp-context-forge/releases/tag/v1.1.2), commit `ddc60dad6a825646bfb149c72d9d835fac80fceb`.

## Milestones

Mark a milestone complete after testing it through its normal entry point. The README percentage counts checked milestones divided by the total.

- [x] Health, readiness, and SQLite, PostgreSQL, and Redis connectivity probes
- [x] First-party bearer verification, database roles and team scopes, and MCP ingress gates
- [x] SQLite and PostgreSQL storage for gateway, tool, and virtual-server associations, with scoped pagination
- [x] Legacy stateless MCP registration, listing, and invocation for unauthenticated Streamable HTTP upstreams
- [x] Modern MCP negotiation, discovery, and standard routing headers
- [x] Stateful sessions, streaming, cancellation, and event resumption
- [x] Resources, prompts, completions, logging, and subscriptions
- [x] Legacy SSE, WebSocket, and stdio transports and translation
- [x] Authenticated MCP upstreams, identity forwarding, and direct proxy mode
- [x] Gateway update, delete, refresh, health lifecycle, and full catalog APIs
- [x] Virtual-server management and OAuth resource metadata
- [x] API token issuance, usage limits, and lifecycle
- [x] User, team, role, and local login management
- [x] OAuth, SSO, dynamic registration, and external identities
- [x] Encrypted credential storage and rotation
- [ ] Remaining database schema, migration history, import, and export
- [ ] REST tool federation
- [ ] gRPC tool federation
- [ ] A2A federation and task lifecycle
- [ ] Native plugins, policy evaluation, and external extensions
- [ ] Admin backend and UI integration
- [ ] HTTP security middleware, trusted proxies, correlation IDs, and rate limits
- [ ] Audit logging, metrics, and tracing
- [ ] CLI, packaging, and deployment
- [ ] Whole-gateway parity, conformance, and Python-free release verification

[Decisions](DECISIONS.md) · [Handoff and replay evidence](HANDOFF.md)
