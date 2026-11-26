# WebSocket relay

The relay accepts WebSocket connections at `/ws` when `MCPGATEWAY_WS_RELAY_ENABLED=true`. The pinned and Rust gateways reject upgrades with HTTP 403 when disabled, when required credentials are missing or invalid, and when a client supplies only a query-string token.

Live requests verified bearer authentication, initialization, ping, resource and prompt lists, method-not-found, invalid JSON, and the close frame for a binary message. Initialization reports the Rust version in the native gateway. Both gateways allow an anonymous connection when `AUTH_REQUIRED` and `MCP_CLIENT_AUTH_ENABLED` are false, with permission checks still applied to each RPC method. The Rust integration test verifies the upgrade and JSON-RPC error responses with a WebSocket client.

The static HTTP case verifies the route's response to an ordinary GET. Replay it with an isolated database and the same environment as [the SSE recordings](../legacy-sse/README.md), with the WebSocket relay disabled.
