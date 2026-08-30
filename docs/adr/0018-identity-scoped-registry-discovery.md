# ADR-0018: Identity-scoped Registry discovery

## Status

Accepted.

## Context

The runtime needs to turn an intent into one exact MCP server without copying the
Agentic Registry catalog or weakening the ADK tool surface. The shipped
Registry contract at commit `59a98273f693b5f9b87df41cb17f1c8af3139757` is
`GET /v0/search` with `q`, repeated or comma-separated `kinds`, `namespace`,
`limit`, and `view=stub`. It returns a bare array of authorized safe stubs. An
exact artifact is fetched through the stub's relative `fetchPath`. Registry
roadmap issues #69, #70, and #71 have not yet shipped ETags, `POST /v0/search`,
minimum-score budgets, runtime hashes, or progressive Registry MCP tools, so
the runtime cannot treat any of those as an available contract.

The design target inherited from ADR-0017 is 2,000 artifacts across 50
namespaces and 50 search requests/second at peak. Discovery is 100% reads. A
runtime request considers at most 20 stubs, fetches at most one artifact, and
accepts at most 128 KiB of search JSON plus 512 KiB of exact JSON. At roughly
40 tokens per stub this keeps the normal search projection below 800 tokens.
Local processing targets p99 below 10 ms; a cold two-hop resolution targets
p99 below 400 ms when each Registry read meets its 150 ms target. Registry
availability remains the limiting dependency for uncached discovery.

The assets are tenant catalog existence, immutable artifact integrity,
credentials used to call Registry, and the model-facing tool surface.
Attackers include another authenticated tenant, a malicious publisher, a
compromised Registry response, and prompt-injection text in artifact metadata.
The trust boundaries are the authenticated `CallContext`, Registry HTTP JSON,
the identity-scoped cache, and the handoff to ADK. Identity is never accepted
from search input; every boundary validates bounds and fails closed.

## Decision

### Registry remains the search and authorization authority

The core exposes a replaceable `RegistryDiscovery` protocol. Its HTTP adapter
issues only the shipped bounded stub search and a same-origin exact
`fetchPath`. Registry performs ranking and object authorization before stub
projection. The runtime never embeds artifacts, stores a catalog, adds a
vector database, reranks with a model, or treats relevance as authority.

The resolver preserves Registry order. It filters authorized stubs by the
declared kind, namespace, and capability contract, selects the first eligible
stub, and performs at most one exact fetch. It then verifies artifact identity,
canonical digest, lifecycle, MCP protocol overlap, caller scopes, tool
allow/deny rules, schema compatibility, and reviewed schema fingerprints. If
the selected exact artifact fails policy, the result is a typed no-match. A
race, corrupt digest, or dependency failure remains a typed error. The runtime
does not progressively disclose the rest of the catalog to a model.

Registry canonical hashing covers `kind`, `name`, `namespace`, `tag`, `labels`,
and `spec` using the compact deterministic JSON representation implemented by
Registry, yielding `sha256:<hex>`. A stub/exact tag, identity, or digest change
is a typed race and fails resolution. A moving `latest` hit is never executed
on trust: its returned content is digest-pinned after verification.

### Cache authorization, not just content

Search cache keys contain the canonical Registry origin, a SHA-256 scope hash,
the query-contract version, and a query digest. Exact keys additionally use
the artifact digest. The scope hash covers issuer, tenant, subject, and sorted
scopes; raw authority values, headers, and credentials never enter a key or
cached value.

Fresh search leases last 30 seconds. Exact authorization leases last 60
seconds. The default offline window is zero. A caller may explicitly allow a
stale immutable exact artifact for at most one hour; the resolver must still
have a fresh identity-scoped search stub and must recompute the exact digest
before use. Cache failure degrades to Registry. Registry failure without a
permitted verified entry raises `RegistryUnavailableError`, never a guessed
match.

The reusable memory cache is bounded to 128 search entries and 64 exact
entries. The corresponding response-content ceilings total 48 MiB before
Python object overhead, with ordinary safe stubs and manifests materially
below that ceiling. It is a cache-aside optimization, never a catalog or source
of truth. External cache adapters must implement the same typed protocol and
isolation rules.

### ADK owns the live model-facing surface

An accepted MCP artifact produces an ADK-ready projection containing a trusted
gateway endpoint, explicit tool allowlist and denylist, deterministic prefix,
tool/schema budgets, and Registry-reviewed input/output fingerprints. The
runtime does not copy ADK's name sanitization, collision resolution, live MCP
schema fingerprint algorithm, or `SurfacePin` drift checks. The optional ADK
adapter turns the projection into the existing `McpServerConfig`; ADK then
discovers the live server, rejects collisions, applies its bounds, and checks a
caller-supplied live `SurfacePin` before any accepted tool reaches model
context.

Only a relative `x-tesserix.routePolicy.gatewayPath` may be joined to an
operator-configured HTTPS gateway origin. A publisher-provided remote URL does
not grant egress authority. Direct artifact endpoints and package execution are
outside this issue.

Explanations contain only the ref of an already authorized stub plus stable
selection or rejection codes. They never include hidden candidates, artifact
bodies, credentials, policy internals, or Registry error payloads.

## Failure and dependency analysis

- Registry search times out with no fresh search lease: fail unavailable; do
  not browse or use a stale catalog.
- Exact fetch times out: use a same-identity immutable entry only when explicit
  offline policy permits it and its digest still verifies; otherwise fail.
- Search and exact identity, tag, or digest disagree: fail a typed race so the
  caller can restart resolution; never retry into a different capability in
  the same decision.
- Registry returns malformed, oversized, credential-bearing, or cross-contract
  JSON: reject it before cache or ADK projection.
- Cache lookup or write fails: continue against Registry; cache availability
  cannot reduce discovery availability.
- No candidate meets policy: return no-match with bounded safe reasons.
- The same operation is repeated: reads and canonical verification are
  deterministic and have no external mutation or idempotency requirement.

Memory and Postgres Registry modes share the HTTP contract, but this repository
cannot claim the open #69–#71 behavior until those Registry changes merge.
Contract fixtures and upstream tests therefore pin only the shipped GET and
exact-fetch behavior; later ETag/hybrid/bundle support requires a new additive
decision and cross-repository matrix evidence.

### Dependency envelope review

The Registry core, HTTP adapter, and optional ADK bridge use only the standard
library and dependencies already present in their respective profiles. The
universal core resolution therefore remains 34 distributions and the clean CI
installation is 31,395,397 bytes, below the existing 64 MiB ceiling. The
additive source raises the pure-Python runtime wheel from the previous 96 KiB
budget to 114,518 bytes in CI (114,640 bytes in the local reproducible build).

Following ADR-0003's measured-review rule, the wheel ceiling becomes 128 KiB
(131,072 bytes), leaving 16,432 bytes above the larger observation. No
dependency-count or installed-size budget changes, and this is not an
unbounded exemption. Splitting these runtime-owned protocols into a new
distribution would add release and compatibility coupling without reducing
installed code, while adding a Registry, vector, database, or ADK dependency
to core would violate the ownership boundary.

## Alternatives considered

- Add embeddings, Qdrant, or an in-memory full catalog: rejected because it
  duplicates ranking, tenancy, backups, and consistency ownership.
- Fetch every candidate until one passes: rejected because it expands private
  data access and latency beyond progressive disclosure's one exact choice.
- Cache by query or digest alone: rejected because content identity is not an
  authorization lease and would confirm artifacts across principals.
- Derive an ADK `SurfacePin` from Registry fields: rejected because ADK pins the
  live MCP input and output schemas with its own contract; a parallel algorithm
  would drift.
- Connect directly to a publisher-supplied remote URL: rejected because search
  relevance cannot authorize egress or bypass the gateway.

## Verification

- public-contract tests cover query bounds, immutable values, no-match
  explanations, compatibility, scope, lifecycle, allow/deny, schema budgets,
  and reviewed fingerprints;
- HTTP tests use `httpx.MockTransport`, make no default-suite network calls,
  and prove query encoding, exact same-origin fetch, payload bounds, and status
  mapping;
- cache tests prove issuer/tenant/subject/scope isolation, expiry, bounded
  eviction, explicit offline behavior, and digest re-verification;
- race tests cover moving tags, mismatched identity, and corrupt digests;
- ADK adapter tests prove the projection uses the existing config contract and
  does not expose rejected tools; and
- upstream Registry memory/Postgres tests are recorded separately from future
  roadmap assumptions.

## Rollout and rollback

The client and ADK projection are additive and opt-in. Roll out first with an
empty tool allowlist, observe no-match/unavailable metrics without payloads,
then enable reviewed artifact and live-surface pins per consumer. A canary can
revert to its static `McpServerConfig` without changing Registry or Gateway.

Rollback is one Git revert or removal of the optional discovery wiring. Cache
entries are process-local, bounded, and expire; there is no database migration,
queue, Kubernetes resource, credential rotation, or destructive operation.
No new cloud service or baseline cost is introduced. An SLO alert belongs to
the consuming service's Registry dependency dashboard, not this library.

## Consequences

Runtime consumers gain one reusable, testable path from authorized semantic
search to an exact ADK-ready MCP declaration. The price is deliberate
fail-closed behavior: stale permissions, incomplete metadata, moving tags, or
unreviewed tool schemas produce no capability rather than a best-effort tool.
