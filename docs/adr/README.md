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
| [0010](0010-gateway-jwt-and-tenant-context.md) | Accepted | Gateway JWT verification, immutable tenant context, and bounded JWKS rotation |
| [0011](0011-default-deny-tool-policy.md) | Accepted | Default-deny tool activation, exact approvals, and backing-owned idempotency |
| [0012](0012-finite-execution-and-tenant-bulkheads.md) | Accepted | Finite JSON execution, tenant bulkheads, earliest deadlines, cancellation, and safe retries |
| [0013](0013-redaction-and-connection-pinned-egress.md) | Accepted | Final-boundary redaction and manifest-bound connection-pinned HTTPS egress |
| [0014](0014-observability-health-and-graceful-drain.md) | Accepted | Bounded observability, dependency-safe health, and readiness-first graceful drain |
| [0015](0015-reusable-conformance-and-fault-testkit.md) | Accepted | Versioned reusable conformance and deterministic fault testkit |
| [0016](0016-portable-and-agentic-registry-manifests.md) | Accepted | One deterministic source for official and Agentic Registry MCP manifests |
| [0017](0017-bounded-semantic-discovery-authoring.md) | Accepted | Bounded semantic authoring, safe Registry projections, and measurable progressive discovery |
| [0018](0018-identity-scoped-registry-discovery.md) | Accepted | Identity-scoped Registry search, one exact verified fetch, and ADK-ready policy projection |
| [0019](0019-delegated-immutable-registry-publication.md) | Accepted | Optional delegated immutable publication, exact verification, and explicit multi-Registry outcomes |
| [0020](0020-digest-bound-gateway-activation.md) | Accepted | Digest-bound Gateway activation, actor-owned status, and bounded observation |
| [0021](0021-identity-scoped-tenant-gateway-reconciliation.md) | Accepted | Identity-scoped tenant eligibility, collision-safe routes, and complete paginated reconciliation |
| [0022](0022-container-and-gitops-deployment.md) | Accepted | Digest-pinned core and ADK images, fail-closed Kubernetes contract, and one-revision GitOps rollback |
| [0023](0023-release-integration-journey.md) | Accepted | Hermetic and digest-pinned release journey with fail-closed sanitized evidence |
| [0024](0024-immutable-release-supply-chain.md) | Accepted | Tag-only protected publication with keyless signatures, SBOMs, provenance, and public smoke |

Architecture decisions are append-only. A later decision supersedes an
accepted ADR instead of silently rewriting its history.
