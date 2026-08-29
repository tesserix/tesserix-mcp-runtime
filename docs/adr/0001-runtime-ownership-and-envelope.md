# ADR-0001: Runtime ownership and quantitative envelope

- Status: Accepted
- Date: 2026-08-30
- Decision owners: Tesserix MCP runtime maintainers
- Tracking: [tesserix-mcp-runtime#2](https://github.com/tesserix/tesserix-mcp-runtime/issues/2)

## Context

Tesserix already has the important MCP platform components:

- the official MCP Python SDK owns the wire protocol and Streamable HTTP
  implementation;
- the Tesserix ADK owns typed ADK tools, in-process MCP sessions, tenant-aware
  tool views, approvals, redaction, resilience, and MCP clients;
- Agentic Registry owns artifact metadata, immutable versions, signatures,
  visibility and RBAC, semantic ranking, exact resolution, and desired gateway
  exports;
- AgentGateway and tesserix-k8s own ingress, coarse route authorization,
  traffic policy, reconciliation, workload identity, and rollout;
- product repositories own tool business behavior and their backing data.

The missing component is a small reusable server host that composes those
contracts consistently for deployed Python MCP servers. Without it, each
product must rebuild identity extraction, per-tool authorization, bounded
transport behavior, health, telemetry, manifest generation, graceful drain,
and ADK bridging. Those copies will drift at the trust boundary.

The assets worth protecting are publishing authority, runtime and downstream
credentials, tenant identity, tool authority, tool inputs and results, private
catalog metadata, and provenance. Threat actors include an unauthenticated
internet caller, an authenticated caller from another tenant, a compromised
dependency or publisher, and an insider. The trust boundaries are developer
CI to Registry, Registry to the gateway reconciler, AgentGateway to the
runtime, and the runtime to each backing API. Every boundary validates and
authorizes independently; semantic relevance never grants execution
authority.

## Quantitative envelope

These are initial design assumptions and release targets. They are not
measured production facts. The committed benchmark contract is the source of
truth and GA work must replace assumptions with observed results.

### Catalog and deployment scale

| Measure | 12 months | 36 months |
|---|---:|---:|
| Deployed MCP servers | 100 | 500 |
| Typical tools per server | 12 | 12 |
| Typical aggregate tools | 1,200 | 6,000 |
| Maximum tools per server | 128 | 128 |
| Maximum aggregate tools | 12,800 | 64,000 |

Metadata at this scale is below a few hundred MiB. Agentic Registry's existing
Postgres and pgvector index remain sufficient; another datastore or vector
service is unjustified.

The planning invocation mix is 80% read-like tools and 20% idempotent write or
external-effect tools. Catalog use is expected to be roughly 1,000 searches or
exact resolutions per publish. Both ratios are assumptions to replace with
observed telemetry. The fleet grows fivefold from the 12-month to 36-month
case; the runtime itself stores no request history or business data.

### Per-pod request envelope

| Measure | Target |
|---|---:|
| Sustained tool calls | 50 calls/second |
| Short burst | 200 calls/second |
| Request ceiling | 64 KiB |
| Response ceiling | 512 KiB |
| Runtime-added direct-transport p99 | less than or equal to 15 ms |
| Process start to ready | less than or equal to 2 seconds |
| Idle resident memory | less than or equal to 128 MiB |

Two ready replicas give one GA server a nominal 100 calls/second sustained
capacity. This is an isolation target, not a forecast that every server peaks
at once. Gateway, mesh, downstream, and network budgets are measured
separately. The runtime never promises that a backing tool completes inside
15 ms; the target covers the no-op transport and policy overhead it owns.

### SLOs

- GA invocation availability: 99.9% per calendar month, allowing about
  43 minutes 50 seconds of unavailability in a 30.44-day month.
- Runtime-added direct-transport latency: p99 at or below 15 ms for the
  committed no-op benchmark profile.
- Activation freshness: 99% of eligible, deployed, healthy versions become
  active within 10 minutes of an immutable Registry publish; p95 is below
  6 minutes. This is a control-plane SLO and does not share the invocation
  availability budget.
- Semantic-index freshness is owned by Agentic Registry. The runtime consumes
  the Registry's published freshness contract and does not claim its SLO.

## Consistency by operation

| Operation | Required consistency |
|---|---|
| Publish immutable Registry version | Strong at the Registry transaction boundary |
| Resolve an exact version or digest | Strong and authorization scoped |
| Semantic candidate ranking | Eventual; exact fetch rechecks visibility and version |
| Gateway route activation | Eventual within the activation-freshness SLO |
| Per-call identity and authorization | Strong for that call; fail closed |
| Write-tool idempotency | Strong in the product's authoritative backing store |
| Metrics, traces, and logs | Best effort with bounded buffering |

Search candidates may be stale or approximate. A caller resolves an immutable,
authorized artifact before use. Registry and gateway reconciliation never sit
inside an active tool invocation.

## Decision

Build a standalone, thin Python package around the official MCP SDK. It owns
composition and Tesserix server policy but not protocol, agent, catalog, or
platform control-plane implementations.

The dependency direction is:

    product tool handlers
            |
    runtime core contracts
            |
    MCP SDK / ADK / Registry / telemetry adapters
            |
    AgentGateway and backing APIs

Core imports no adapter. Non-ADK servers install no ADK or agent-provider
dependencies. ADK servers opt into one bridge that delegates to ADK public
interfaces without rebuilding schemas, approval behavior, tenant lanes, or
result semantics.

Runtime pods do not self-register, hold Kubernetes credentials, create routes,
or become publicly reachable around AgentGateway. Publication and deployment
are separate, observable, idempotent steps. Agentic Registry remains a control
plane rather than an invocation proxy.

## Authoritative ownership

| Concern | Authoritative owner | Runtime responsibility |
|---|---|---|
| MCP protocol revisions and JSON-RPC shapes | MCP specification and official SDK | Negotiate and adapt through the SDK |
| Streamable HTTP implementation | Official MCP Python SDK | Configure, bound, and lifecycle-manage |
| Generic Python tool and call-context contract | Tesserix MCP Runtime | Define once and expose publicly |
| ADK tool descriptors, views, approvals, and results | Tesserix ADK | Delegate through the optional bridge |
| Official server.json schema | Official MCP Registry | Generate and validate the portable document |
| Tesserix artifact schema, versions, signatures, visibility | Agentic Registry | Generate an envelope and consume exact APIs |
| Semantic vocabulary, projection, embeddings, and ranking | Agentic Registry | Author validated metadata; never embed or rank |
| User and workload token issuance | Zitadel and platform identity | Verify the expected issuer, audience, and claims |
| Route-level traffic authorization | AgentGateway | Require the gateway path; do not weaken it |
| Per-tool scope, side-effect, and approval authorization | Tesserix MCP Runtime | Make the final default-deny decision |
| Runtime/downstream credentials | Secret Manager and workload identity | Resolve references at call time; never persist values |
| Tool business state and idempotency records | Product backing service | Propagate verified tenant and idempotency key |
| Gateway desired state | Agentic Registry | Publish metadata only |
| Kubernetes reconciliation and workload desired state | tesserix-k8s and product GitOps repositories | Expose probes and a deployment contract |
| Ephemeral sessions, queues, and in-flight calls | Tesserix MCP Runtime process | Bound, isolate, drain, and discard on restart |
| Telemetry schema and safe attributes | Tesserix MCP Runtime | Emit consistent signals without payloads |
| Telemetry storage, retention, dashboards, and paging | Platform observability | Export with bounded failure behavior |

No schema, policy, credential, or state has two write owners.

## Dependency failure behavior

| Dependency | Tier | Behavior when unavailable |
|---|---|---|
| Agentic Registry | Critical for publish, search, and new activation; absent from invocation | Existing active routes and calls continue. Publish, search, and activation fail visibly and retry idempotently. |
| AgentGateway data plane | Critical for invocation | Callers receive a bounded gateway failure. The runtime has no public bypass. |
| Gateway reconciler/control plane | Degradable for active routes, critical for route changes | Existing data-plane state continues. New activation and retirement become stale and alert on freshness. |
| Identity/JWKS | Critical for protected calls | Locally verify with a still-valid trusted key under the future cache policy; otherwise fail closed. |
| Secret Manager/workload credential source | Critical only for tools needing that credential | The affected call fails before the backing request. Other tools and health remain available. |
| Product backing API | Tool-specific critical dependency | Only that tool fails with a stable, scrubbed, retryability-aware error inside the caller deadline. Tenant bulkheads contain the failure. |
| Telemetry collector | Optional on the request path | Serve normally, bound buffers, drop overflow, and expose a dropped-telemetry counter. |
| Tesserix ADK | Optional package/runtime dependency | Only ADK-backed servers require it. Core servers remain installable and runnable. |

Retries apply only to transient reads or explicitly idempotent writes, use
jitter and a hard cap, and remain inside the original caller deadline. A
duplicate write returns the authoritative prior result rather than repeating
the effect. If a process crashes after the backing service commits but before
replying, the repeated idempotency key is the recovery mechanism; the runtime
does not pretend the two systems share a transaction.

## Capacity, cost, and blast radius

The first deployment contract will test 100 millicpu and 192 MiB requested per
pod, with two ready replicas for a GA server:

| Fleet | Pods | Requested vCPU | Requested memory |
|---|---:|---:|---:|
| 100 GA servers | 200 | 20 | 37.5 GiB |
| 500 GA servers | 1,000 | 100 | 187.5 GiB |

For a budgetary comparison only, at assumed rates of USD 0.04 per vCPU-hour
and USD 0.005 per GiB-hour over 730 hours, this is about USD 721/month at
100 servers and USD 3,604/month at 500 servers, before cluster overhead,
network, and discounts. Real GCP billing data replaces these assumptions
before production capacity is approved. Experimental servers may use a lower
replica policy only when their lifecycle SLO permits it.

At a 200 MiB compressed image, ten retained versions per server consume about
195 GiB for 100 servers and 977 GiB for 500. At an assumed USD 0.10/GiB-month,
that is about USD 20 and USD 98 per month.

For telemetry planning, assume one average call/second per server, 0.3 KiB of
payload-free logs and metrics per call, 2 KiB per sampled trace, 5% successful
trace sampling, and all failures retained. Before failure uplift, that is about
104 GB/month at 100 servers and 518 GB/month at 500. Payload logging is
forbidden; retention and real byte counts are measured before GA.

The current five-minute route poll runs 8,640 times in a 30-day month. Applying
approximately three resources per server every run is an upper bound of
2.59 million resource applies at 100 servers and 12.96 million at 500.
Digest-aware no-op behavior and measured Kubernetes API pressure determine
whether polling remains sufficient. Events are not introduced until that
baseline fails its freshness or cost target.

Blast radius is one tenant and one server wherever possible:

- concurrency and queues are bulkheaded by tenant and tool;
- product credentials and idempotency state never share tenants;
- a failed backing API affects its tools, not process health;
- a bad version cannot replace the last known-good route until its probe is
  accepted;
- a Registry or reconciler outage does not remove existing gateway state.

## Options considered

### Use the official SDK directly in every server

This is the simplest implementation and remains appropriate for a local or
unmanaged server. It is rejected as the platform pattern because every product
would reimplement the same identity boundary, per-tool authorization, tenant
bulkheads, limits, error mapping, telemetry, manifests, probes, and drain
behavior. The runtime exists only for those shared guarantees; protocol and
business logic still use the official SDK directly underneath.

### Put the network server into the Tesserix ADK

Rejected. Many MCP servers are deterministic facades over product APIs and do
not need an agent loop, model providers, memory, Temporal, or the ADK release
cadence. A bridge preserves ADK behavior for the servers that need it without
making the ADK the universal hosting dependency.

### Build one platform-hosted universal MCP proxy

Rejected. It centralizes product credentials and failure, makes the Registry
or proxy part of invocation, and couples unrelated tool release cycles. The
gateway remains the shared routing and coarse-policy layer; each server owns
its product boundary.

### Copy the Registry catalog or add a runtime vector store

Rejected. Agentic Registry already owns pgvector ranking, RBAC filtering, and
exact versions. A second index adds staleness, authorization leakage, another
backup story, and no correctness benefit.

### Build a multi-language abstraction now

Rejected until a second maintained implementation exists. The first concrete
runtime is Python 3.14. Protocol and manifest contracts remain portable, but
no speculative cross-language framework is introduced.

## One-way and two-way doors

One-way doors requiring explicit superseding ADRs:

- authoritative ownership and the rule that Registry is not on invocation;
- identity and tenant derivation only from verified transport context;
- default-deny per-tool authorization;
- public error, call-context, and manifest compatibility contracts;
- no runtime datastore and no runtime Kubernetes authority;
- the public Python package namespace and major-version policy.

Replaceable two-way doors behind typed boundaries:

- ASGI runner and HTTP implementation details beneath the official SDK;
- telemetry exporters and sampling configuration;
- in-memory queue and semaphore implementation;
- gateway reconciliation cadence and polling versus event trigger;
- core versus ADK base-image selection;
- exact supported SDK minor inside an accepted major.

## Migration and rollout

1. Inventory an existing server's tools, schemas, auth, egress, routes, and
   backing API behavior.
2. Run its tool handlers through the runtime contract or ADK bridge without
   changing business logic.
3. Compare schema fingerprints, tool names, results, errors, scopes, and
   semantic metadata.
4. Build an immutable image and publish an experimental Registry version.
5. Deploy through GitOps, probe directly inside the private network, and let
   the reconciler create a non-active candidate route.
6. Run conformance, evaluation, and tenant-isolation tests.
7. Canary traffic, then make the exact healthy version active.
8. Retain the prior immutable version and route until the observed rollback
   window passes; remove compatibility code after callers migrate.

There is no database migration in the runtime. Manifest changes are
additive within a version; a breaking contract uses a new major version.

## Rollback

Rollback is one GitOps revision to the previous image digest and one Registry
activation pointer to the previous immutable artifact. The reconciler
converges gateway resources; it does not delete the last known-good route
while a candidate is unready. In-flight calls drain under the old pod's
deadline. Because runtime state is ephemeral and product writes are
idempotent in the product store, no runtime data restore or compensation is
required.

## Explicit non-goals

- model execution, agent loops, memory, planning, or provider selection;
- Registry storage, embeddings, ranking, signatures, or authorization;
- identity issuance, refresh-token storage, or credential brokering;
- Kubernetes or AgentGateway control from runtime pods;
- product database access patterns or business transactions;
- a vector database, shared runtime cache, or new durable datastore;
- direct public runtime endpoints that bypass AgentGateway;
- production-performance claims before the benchmark and reliability work.

## Consequences

The platform gains one narrow place to harden deployed MCP server behavior and
one conformance suite products can reuse. The cost is another versioned public
package and an adapter compatibility matrix. Keeping core independent of ADK
and control-plane clients is therefore a release invariant, not an optional
cleanup.

## Architecture review checklist

- [x] Peak scale, payload, growth, latency, availability, and resource targets
  are stated.
- [x] Consistency is decided per operation.
- [x] Every dependency has an unavailable behavior and tier.
- [x] Tenant and bad-version blast radius is contained.
- [x] Migration and one-action rollback are described.
- [x] Compute, image, telemetry, and reconciliation costs have formulas and
  explicit assumptions.
- [x] The official-SDK-only alternative is considered first and rejected only
  for concrete shared platform guarantees.
- [x] Non-goals and one-way doors are explicit.

## References

- [ADK MCP server contract](https://github.com/tesserix/agent-development-kit/blob/main/docs/mcp-server.md)
- [ADK MCP authentication context](https://github.com/tesserix/agent-development-kit/blob/main/docs/mcp-auth-context.md)
- [Agentic Registry ownership](https://github.com/tesserix/agentic-registry/blob/main/README.md)
- [Registry semantic capability index](https://github.com/tesserix/agentic-registry/blob/main/docs/adr/0004-semantic-capability-index.md)
- [Registry gateway ownership](https://github.com/tesserix/agentic-registry/blob/main/docs/adr/0003-agentgateway-desired-state-ownership.md)
- [AgentGateway route reconciler](https://github.com/tesserix/tesserix-k8s/tree/main/charts/apps/agentgateway-route-sync)
- [Tesserix Python 3.14 base images](https://github.com/tesserix/base-docker-images/pull/24)
- [Official MCP Python SDK v2.1.1](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.1.1)
