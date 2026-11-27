# Tool management writes

Live HTTP checks compared create, edit, activation, deactivation, and deletion
against ContextForge v1.1.2 on SQLite, PostgreSQL, and SQLite initialized by
the pinned gateway. Twenty-one of 23 requests matched after normalizing IDs,
timestamps, and the text of JSON Schema diagnostics. The two deprecation cases
verified the Rust behavior. A successful edit persists the deprecated flag,
and previews reject the deprecated tool immediately. The pinned fixture
returned a successful edit while leaving the flag false.

The credential fixture checked masked responses, bearer rotation, preservation
of masked fields, and ciphertext storage for bearer authentication and
sensitive request headers. The activation fixture also checked that enabling
and reachability change together without incrementing the tool revision.
Tool edits preserve the ID and update revision metadata.

Tool management stores the configuration for REST passthrough. Network
execution for REST, gRPC, and A2A has separate milestones. CEL policy evaluation
is tracked under native plugins and policy.
