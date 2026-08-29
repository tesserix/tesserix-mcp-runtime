# Architecture decisions

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-runtime-ownership-and-envelope.md) | Accepted | Runtime ownership and quantitative envelope |
| [0002](0002-python-and-mcp-compatibility.md) | Accepted | Python and MCP SDK compatibility policy |
| [0003](0003-public-api-and-dependency-layering.md) | Accepted | Public API, adapter direction, and dependency budgets |
| [0004](0004-cross-system-threat-model.md) | Accepted | Cross-system trust, threat, review, and incident model |
| [0005](0005-runtime-contracts-and-lifecycle.md) | Accepted | Typed runtime contracts, stable failures, and lifecycle ordering |
| [0006](0006-compositional-application-and-drain.md) | Accepted | Explicit application composition, signal ownership, and bounded drain |
| [0007](0007-typed-callable-authority-and-manifests.md) | Accepted | Typed callable schema authority, bounded metadata, and handler-free manifests |
| [0008](0008-streamable-http-and-bounded-sessions.md) | Accepted | Official Streamable HTTP adapter, private listener, finite envelopes, and tenant-bound sessions |
| [0009](0009-adk-exported-session-bridge.md) | Accepted | Exact optional ADK exported-session bridge, trusted context mapping, and attested compatibility |

Architecture decisions are append-only. A later decision supersedes an
accepted ADR instead of silently rewriting its history.
