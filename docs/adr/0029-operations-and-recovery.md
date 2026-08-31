# ADR-0029: Stateless MCP operations and recovery

- Status: Accepted
- Date: 2026-08-31
- Tracking: [tesserix-mcp-runtime#32](https://github.com/tesserix/tesserix-mcp-runtime/issues/32)

## Decision

Operate the runtime with one bounded, payload-free telemetry contract and
separate objectives for invocation, activation freshness, search, and probes.
Invocation availability is 99.9% monthly; failures are stable outcomes, not
log text. Fast (14.4x) and slow (6x) multi-window burn alerts page the MCP
runtime owner. Route staleness, reconcile/probe failure, authorization-denial
anomaly, and telemetry loss each have a named owner and runbook. CPU and a
single tool error are not pages.

An operator traces a call only through safe request/trace IDs, immutable
Registry ref/digests, activation/route generation, Kubernetes conditions,
Gateway trace, runtime outcome, and backing correlation ID. Inputs, outputs,
subjects, tenants, URLs, headers, tokens, and exception text remain excluded.

Runtime pods hold no authoritative state: PostgreSQL owns Registry/domain and
idempotency, Temporal owns workflow history, Qdrant is rebuildable search, and
Valkey is non-authoritative. Data-plane RPO is zero; approved GitOps revert to
ready has a five-minute RTO. Registry backup RPO/RTO is owned by its PostgreSQL
operator and is not claimed until an isolated restore verifies signatures,
versions, routes, and tenant boundaries.

## Consequences

Registry, Gateway, identity, backing API, and bad deployment failures have
distinct recovery paths. Existing last-known-good routes survive Registry
control-plane failure; identity fails closed; affected backing destinations are
isolated; bad deploys are reverted with one reviewed Git commit and Argo CD.
Capacity and cost are reviewed after measured load and first production use,
using saturation rather than CPU. This adds documentation and tests only—no
new serving dependency, datastore, dashboard service, or production mutation.
