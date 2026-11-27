# Virtual-server handshake and OAuth challenge

The handshake endpoint dispatches to the gateway's own MCP router. The live
fixture exercised initialization, capability and catalog counts, a rejected
authorization override, and a disabled server. Stateful SSE responses and
stateless JSON responses both worked. The probe reports the running binary's
version and counts the entries served by MCP. The pinned fixture included a
REST tool. Its execution and MCP exposure are tracked under REST federation.

Unauthenticated requests to an OAuth-enabled server return HTTP 401 with the
RFC 9728 discovery URL in `WWW-Authenticate`. The header and response body
matched the pinned gateway using an HTTPS proxy header. The challenge also
worked with global MCP authentication disabled. The resource metadata endpoint
remained limited to enabled public servers with approved OAuth settings.
