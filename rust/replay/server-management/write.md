# Virtual-server writes

The 26-request comparison against ContextForge v1.1.2 passed on SQLite,
PostgreSQL, and SQLite initialized by the pinned release. The comparison
normalized timestamps, fixture IDs, and the loopback request authority.

The fixture creates a server with a UUID, a tool association, and a protocol
interface. An unknown association rejects the transaction, and the next
request can create the same server. Edits replace associations and preserve
unchanged interfaces. Setting instructions to an empty string and clearing
them produce distinct results. Activation changes preserve the current
revision. The metrics fixture reads both existing raw and hourly records.

OAuth configuration changes require an unrestricted administrator. The
fixture verified encrypted storage, masked reads, preservation of the
unchanged approval generation when a caller submits a masked value, rejection
of a stale review version, and discovery after approval.
