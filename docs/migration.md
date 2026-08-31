# Incremental MCP migration

This runbook moves one MCP surface at a time to the Tesserix runtime. It keeps
the server process stateless: every request supplies freshly authenticated
identity and tenant, the immutable tool/schema version, request and trace IDs,
deadline, retry budget, authorization context, and an idempotency key for a
write. PostgreSQL or the owning product remains the idempotency and domain
authority; Temporal owns durable multi-step workflow state; Qdrant is a
rebuildable tenant-filtered projection; Valkey is non-authoritative cache or
coordination only. Neither a pod's memory, local filesystem, nor
`Mcp-Session-Id` is a correctness dependency.

The planning utility, `compare_migration_surfaces`, generates the required
handler-free pre-cutover diff. It compares input and output schemas
directionally, descriptions, scopes, effect/approval/idempotency policy, tool
lifecycle labels, egress authorities, exact routes, and the stateless target
in a deterministic order. It never stores state or shifts traffic.

```python
from tesserix_mcp_runtime import compare_migration_surfaces

report = compare_migration_surfaces(legacy_surface, candidate_surface)
assert report.target_stateless
assert not report.requires_major_version
assert report.cutover_ready
```

`requires_major_version` is true for a removed tool, a breaking input/output
schema change, or changed effect, approval, or idempotency policy. Scope,
description, egress, lifecycle, and route changes remain explicit review
items even when they are not schema-major. A false `cutover_ready` means the
Gateway route must not move.

## Estate inventory and target pattern

The inventory is intentionally evidence-based: it distinguishes a known
implementation from a pattern that has not yet been located in a product
repository. A product owner fills in immutable version, route, and telemetry
evidence before the record can move from planned to canary.

| Source pattern | Known evidence and owner | Target pattern | Risk and prerequisite | Evidence, rollout, and rollback |
| --- | --- | --- | --- | --- |
| DevAI MCP SDK 1.28.1 | `devai.mcphub.downstream.DownstreamConnection` at pinned commit `850379a`; DevAI owner | MCP v2 Streamable HTTP behind AgentGateway, retain v1 client compatibility | First-page discovery limitation; exact compatibility lane must stay green | Run the DevAI lane, eval bundle, and sanitized canary telemetry. Keep the legacy route and immutable Registry version; revert the GitOps route target if the candidate fails. |
| Official SDK v1 or FastMCP server | Product owner and route are discovered per server; no broad estate-wide rewrite is assumed | Typed runtime catalog plus v2 Streamable HTTP | Hand-copied schemas or model-controlled tenant inputs | Capture `ToolManifest` snapshots, generate this diff, run v1 and v2 compatibility plus product eval. Retain old route until observed callers leave it. |
| Official SDK v2 bespoke server | Runtime's 2.1.1 compatibility lane; product owner supplies the candidate record | Native typed-callable/runtime application | Route or policy drift during direct transport replacement | Run full pagination, structured invocation, cancellation, authorization, and eval evidence. Roll back by restoring the prior immutable Registry/GitOps target. |
| ADK in-process `McpServer` export | `tesserix-adk.adapters.mcp_server.McpServer`; ADK owner | `ADKStreamableHTTPBridge` with an immutable export allowlist | Export set may widen or old session semantics may leak | Compare descriptors, exports, scopes, and lifecycle; run `compatibility/adk/test_bridge.py` and product eval. Keep the old ADK route during canary. |
| Platform template-generated server | `Sam123ben/platform-engineering/templates/product/mcp-server`; platform-engineering owner | Real `tesserix-mcp-runtime` package/image, Registry manifest, and AgentGateway contract | Template currently contains placeholder imports and Crossplane/IAM/KMS/AWS-era assumptions | Platform team must land and validate its template update before a generated server can cut over. Generated repos run compatibility/eval gates; template rollback is a version-pin reversal. |

## Pattern checklists

### Official SDK v1 or FastMCP

1. Freeze the old route, owner, transport, SDK version, backing API, scopes,
   egress hosts, tool schemas, descriptions, lifecycle, and current immutable
   Registry version.
2. Adapt each existing handler behind `ToolDefinition`; do not rewrite business
   behavior. Typed callable registration is the single schema authority.
3. Derive identity and tenant from verified Gateway context, never tool input.
   For writes, forward the caller's idempotency key and payload digest to the
   owning API. Never create a replica-local deduplication store.
4. Generate and review `MigrationDiff`. A breaking result publishes a new
   major version and leaves both exact versions active during migration.

### Official SDK v2

1. Keep the existing handler and produce a `ToolManifest` baseline before
   changing transport, policy, or route.
2. Use stateless `/mcp`; reject `Mcp-Session-Id`. Do not use session affinity,
   pod memory, or local disk for workflow, approval, or idempotency state.
3. Verify initialisation, pagination, invocation, cancellation, close/reopen,
   and safe error mapping under the supported v2 lane.

### ADK exports

1. Start from a named `AgentToolView` and explicit exports. The bridge must not
   publish more authority than the view can invoke.
2. Preserve trusted per-call tenant, subject, scopes, trace fields, deadline,
   and idempotency key through the bridge. The ADK session is a compatibility
   adapter, not a durable state owner.
3. Compare ADK descriptors with the candidate catalog. Treat an export,
   scope, effect, approval, idempotency, or schema mismatch as a cutover stop.

### Template-generated servers

1. Replace the template's placeholder runtime import and mutable or
   AWS-specific deployment assumptions with a digest-pinned Python 3.14 core
   or ADK image, Agentic Registry `MCPServer` manifest, GCP workload identity,
   AgentGateway route, Kubernetes NetworkPolicy, and GitOps delivery contract.
2. Derive backing-API credentials per call using workload identity or token
   exchange. No database connection, long-lived bearer token, or tenant field
   belongs in a tool body.
3. Generate the same manifest and migration diff as a handwritten server; a
   scaffold does not bypass semantic, policy, egress, or lifecycle review.

## Shadow, canary, promotion, and retirement

Only deterministic read probes may be mirrored. Never shadow a write,
external effect, approval consumption, workflow start, or any call whose
backing API cannot guarantee idempotent duplicate handling. Give each probe a
separate request ID and a non-production tenant or a backing-service dry-run
mode; do not replay production payloads into a candidate.

For a safe candidate, publish the exact immutable artifact and Registry
version, deploy it with zero Gateway traffic or an isolated smoke route, then
run compatibility and eval suites. Compare sanitized canary telemetry for
error ratio, p99 duration, saturation, route/client usage, authorization
denials, and output redaction. Promote by one reviewed GitOps route-target
change only after the diff, evidence, and health policy pass. Keep the prior
route and version through a complete observed usage window. Retire a stub or
route only after route and client telemetry show no callers for that window
and the owning product signs off.

Rollback is one Git revert that restores the previous exact route target and
immutable Registry version. Do not use imperative Kubernetes rollback: Argo CD
would reconcile the failed desired state again. A candidate that is not ready,
has a breaking diff without a new major version, reports non-stateless, or
fails probe/eval evidence receives no traffic.

## Required record for every product server

Before cutover, the owner attaches one record containing:

- server/repository and accountable owner;
- source and target pattern, old and candidate immutable versions, routes, and
  backing API;
- generated `MigrationDiff`, including schema fingerprints and every scope,
  egress, lifecycle, description, and route change;
- stateless request-envelope and idempotency evidence for every mutating tool;
- compatibility and eval results, sanitized canary comparison, rollout steps,
  and the single-revert rollback revision;
- explicit sunset criterion and the observed route/client usage evidence.

This migration does not make Registry or Gateway selection an authorization
decision. The runtime still authorizes the verified caller immediately before
each tool call, and the backing product system remains authoritative for
durable state and idempotent write results.
