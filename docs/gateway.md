# MCP gateway

The gateway targets MCP Python SDK **1.28.0** and protocol **2025-11-25**.
The maintained v1 SDK line preserves ClientSession and FastMCP transport APIs.
Sources: [official SDK releases](https://pypi.org/project/mcp/1.28.0/),
[v1 SDK documentation](https://py.sdk.modelcontextprotocol.io/v1/),
[MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

Transport peers remain outside the trusted computing base. Running an untrusted
stdio executable requires operating-system isolation: this library does not
sandbox subprocesses or prevent a remote server from executing malicious code.

Description alerts are heuristics: paraphrases and encoded instructions bypass
them. They never grant permission. The planner sees a locally authored Contract,
never raw remote descriptions. The trusted host approves full canonical metadata
out of band; SHA-256 pins survive restart in SQLite. A changed pin remains
quarantined even if the peer later restores its old metadata.

Each upstream owns a separate ClientSession. JSON-RPC IDs are session-scoped;
downstream calls return through their awaiting handler instead of forwarding raw
upstream IDs. Two peers can both use request ID 1 without a routing collision.

Every allowed call re-fetches metadata immediately before dispatch and checks the
persistent pin. This closes stale cached-approval use, but **cannot atomically bind
a remote server's implementation to its metadata**. A malicious peer may change
behaviour after recheck or lie about its schema. Strong execution guarantees need
a trusted, versioned server implementation or an isolated capability-limited host.
Cancellation also cannot roll back effects already performed by a peer.
