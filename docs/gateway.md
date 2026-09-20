# MCP gateway

The gateway targets MCP Python SDK **1.28.0** and protocol **2025-11-25**.
The maintained v1 SDK line preserves ClientSession and FastMCP transport APIs.
Sources: [official SDK releases](https://pypi.org/project/mcp/1.28.0/),
[v1 SDK documentation](https://py.sdk.modelcontextprotocol.io/v1/),
[MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

Transport peers remain outside the trusted computing base. Running an untrusted
stdio executable requires operating-system isolation: this library does not
sandbox subprocesses or prevent a remote server from executing malicious code.
