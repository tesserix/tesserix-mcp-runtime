# ADR-0028: Incremental stateless MCP migration evidence

- Status: Accepted
- Date: 2026-08-31
- Tracking: [tesserix-mcp-runtime#31](https://github.com/tesserix/tesserix-mcp-runtime/issues/31)

## Context

The Tesserix estate contains supported MCP SDK v1 clients, v2 servers, ADK
exports, bespoke FastMCP implementations, and a platform template. Replacing
them in one route or one release would combine protocol, schema,
authorization, egress, lifecycle, and rollback risk. The runtime's production
data plane is stateless, so a migration must also prove that a different pod
can process the next call without server-owned session, idempotency, workflow,
or request state.

This is a build/review control, not another serving hop. It receives zero
runtime requests per second, adds zero production latency, persists zero bytes
at 12 and 36 months, and has no availability SLO. It operates on already
bounded handler-free `ToolManifest` objects: up to 128 tool names under the
runtime catalog limit, schemas up to 65,536 bytes each, 256 egress
destinations, and 512-byte exact route paths. The production runtime remains
qualified for 50 sustained and 200 burst calls/second with 99.9% monthly
availability; this decision must not reduce that envelope.

The assets are tenant authority, tool contracts, egress boundaries, immutable
Registry versions, Gateway routes, backing-service idempotency, and durable
workflow references. Threat actors include an unauthenticated caller, a caller
from another tenant, an accidental template adopter, and a maintainer who
changes a route or policy without reviewing the full tool surface. The trust
boundary is crossed at Gateway authentication, runtime authorization, every
backing API call, Registry/Gateway activation, and every external durable
state owner.

## Decision

Add a dependency-free, deterministic migration surface comparator and require
its report before cutover. `MigrationSurface` contains only immutable tool
manifests, exact egress authorities, exact public-to-upstream routes, and an
explicit stateless target. `compare_migration_surfaces` reports additions and
removals plus directional input/output schema compatibility, descriptions,
scopes, effect/approval/idempotency policy, discovery lifecycle, egress,
routes, and server statelessness.

A removed tool, breaking input or output schema, or changed effect, approval,
or idempotency policy requires a new major version. A target that is not
stateless is never cutover-ready. Other changes remain review-visible but do
not pretend to be schema-major. The report has no network, database, cache,
clock, handler, publication, or route mutation dependency.

The migration guide records the per-pattern inventory and gate for SDK v1 or
FastMCP, SDK v2, ADK exports, and template-generated servers. Each real server
must add its accountable owner, source and target pattern, precise versions and
routes, prerequisites, compatibility/eval evidence, sanitized canary
comparison, rollout, one-revert rollback, and route/client-usage sunset
criterion. No product tool body is rewritten merely to adopt this adapter.

The per-call state contract remains external: PostgreSQL or the owning product
is the idempotency and domain authority, Temporal owns durable multi-step
workflows, Qdrant is a rebuildable tenant-filtered semantic projection, and
Valkey is non-authoritative cache or coordination. Writes forward one
tenant/capability/version-scoped idempotency key and canonical request digest;
the same key with a changed digest conflicts. A later workflow/status call
carries an opaque reference with fresh identity, tenant, authorization,
request/trace ID, deadline, and policy context. `Mcp-Session-Id` is rejected.

Shadow traffic is only allowed for deterministic read probes under an isolated
tenant or downstream dry-run mode. Writes, external effects, approvals,
workflow starts, and any non-idempotent operation are never replayed. Canary
promotion is a reviewed GitOps change that retains the previous exact Registry
version and route through an observed usage window. Rollback is one Git revert
and Argo CD reconciliation; no imperative Kubernetes mutation is permitted.

## Failure behavior and consequences

An invalid or ambiguous route, duplicate normalized tool, malformed surface,
breaking diff without a major version, stateful candidate, failed
compatibility/eval, or adverse canary prevents route movement. Registry,
Gateway, and backing product systems retain their existing fail-closed
authorization and idempotency controls; the comparator cannot authorize a
call. If it crashes, no traffic or durable state changed.

The incremental path avoids a flag-day rewrite and makes every consequential
surface change reviewable. It costs one small pure-Python module and its tests,
with no container, cloud, database, queue, or operational spend. It does
require product owners to retain old exact versions temporarily and to collect
sanitized client/route telemetry before retirement.

Alternatives rejected:

- Handwritten per-product migration notes: rejected because schema, policy,
  egress, and route drift would not be mechanically comparable.
- Mirror all production calls: rejected because it can duplicate writes,
  approvals, workflow starts, and external effects.
- Flag-day replacement: rejected because an incompatible client or route would
  have no independently verified rollback target.
- Sticky sessions or pod-local state: rejected because they violate the
  cross-replica stateless reliability contract.
