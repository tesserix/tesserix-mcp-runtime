# ADR-0017: Bounded semantic discovery authoring

## Status

Accepted.

## Context

MCP authors need describe why a server and each tool should be selected without
shipping a second search system inside the runtime. Agentic Registry owns the
catalog, pgvector index, lexical fallback, tenant authorization, lifecycle
filtering, result stubs, and exact fetch. The runtime owns typed authoring and
must produce the Registry contract without letting relevance become authority.

The Registry design target is about 2,000 artifacts across 50 namespaces,
50 search requests/second at peak, 40 tokens per discovery stub, and no more
than 1,500 tokens in a normal discovery turn. Registry search targets 99.9%
monthly availability and p99 below 150 ms. Manifest compilation remains local
build-time work and introduces no serving-path SLO.

The protected assets are credential material, tenant catalog existence,
authorization decisions, and the integrity of semantic ranking. Attackers are
malicious or compromised publishers, cross-tenant readers, and artifact text
attempting prompt injection. The trust boundary is crossed when authoring text
becomes Registry annotations or safe Tool attributes. Every value is bounded
and secret-checked there; Registry authorization is still required before
candidate projection and again on exact fetch.

## Decision

### One typed intent source

`SemanticMetadata` is the only authoring source for:

- a one-line summary;
- bounded `when_to_use`, `not_for`, and example phrases;
- namespaced capability identifiers;
- Agentic Registry artifact ARNs required by the server or tool;
- risk classification; and
- the existing domain and keyword routing hints.

Server lifecycle remains `ServerAuthoringManifest.lifecycle`. Each
`ToolSummary` may narrow the server intent and lifecycle and carries a bounded
safe input-schema projection derived from the runtime `ToolManifest`. The
projection contains only property name, JSON type, description, and
requiredness. It never contains defaults, examples, headers, environment
variables, executable bodies, or credential-shaped properties.

`ToolSummary.from_runtime` reuses compatible core `ToolDiscoveryMetadata`
summary, trigger, capabilities, examples, and lifecycle rather than asking an
author to copy them. The manifest-specific `SemanticMetadata` input is an
explicit override and carries fields the serving runtime does not own, such as
negative cues, Registry dependencies, and discovery risk.

Discovery strings are trimmed, single-line visible UTF-8. Individual values,
collection sizes, and aggregate annotation bytes have fixed ceilings. Secret
assignments, bearer values, private-key markers, token-shaped values, literal
runtime URLs, shell environment assignments, and code fences fail validation
without echoing the input. Capabilities use the controlled namespace grammar
`cap/<lower-kebab-name>`. Requirements use the Registry canonical ARN shape:

```text
arn:agentic:registry:<tenant>:<plural>/<namespace>/<name>
```

The compiler rechecks dynamic values immediately before serialization because
Pydantic model freezing does not deep-freeze dictionaries.

### Accepted Registry annotations

The Agentic Registry #68 contract reserves exactly these publisher annotations:

| Annotation | Canonical value |
|---|---|
| `discovery.agentic.dev/summary` | one summary string, at most 200 characters |
| `discovery.agentic.dev/when-to-use` | sorted trigger phrases joined by `; ` |
| `discovery.agentic.dev/capabilities` | sorted capability identifiers joined by `, ` |
| `discovery.agentic.dev/requires` | sorted canonical ARNs joined by `, ` |

`registry.agentic.dev/body-tokens` is server-computed and cannot be authored.
User-provided annotations may not claim either reserved namespace. Optional
`not_for`, examples, risk, domains, and keywords remain structured under
`spec.x-tesserix.semantic` until Agentic Registry accepts additional annotation
keys; the runtime does not manufacture unofficial discovery annotations.

Tool entries compile the same typed source into Agentic safe attribute names:
`description`, `inputSchema`, `capabilities`, `requires`, `riskLevel`, and
`status`. These are a projection for Registry indexing and later Tool
publication, not an executable Tool body. Required scopes and schema
fingerprints remain outside discovery text.

### Linting is stricter than compatibility

The Registry contract permits missing annotations and falls back to
`spec.description`. Compilation therefore remains backward compatible with the
issue #18 manifests. `lint_semantic_manifest` separately returns stable typed
findings for missing or vague triggers, description duplication, marketing
language, model-control instructions, tool intent wider than its server, and
aggregate token-budget excess. CI and the future publisher treat lint findings
as author corrections; runtime invocation never runs the linter.

### Evaluation measures results, not an in-process index

The package provides metric-only evaluation types. It accepts ranked candidate
identifiers produced by a Registry implementation and measures precision at K,
no-good-match behavior, deprecated or incompatible recommendations, and any
forbidden tenant exposure. It does not embed, rank, store vectors, or cache a
catalog.

The checked-in intent dataset covers ambiguous requests, near-duplicate tools,
wrong-tenant artifacts, deprecated candidates, incompatible candidates, and
no-good-match queries. A result is invalid if a forbidden artifact appears at
any rank, count, or stub position even when the relevant result also appears.

### Progressive disclosure and authority

The sequence is fixed:

```text
intent -> authorized Registry search -> bounded stubs -> exact authorized fetch
       -> compatibility check -> policy authorization -> runtime invocation
```

Semantic relevance only chooses candidates. It cannot grant tenant access,
scope, approval, egress, or execution permission. Search failure never falls
back to an unfiltered catalog. Exact fetch reauthorizes the selected object so
stale or forged stubs cannot become authority.

## Dependency and failure analysis

- Agentic Registry #68 changes annotation parsing or encoding: compatibility
  tests fail against generated goldens before publication; update the compiler
  and ADR together.
- Unsafe authoring text: model validation fails with a payload-free package
  error before artifact bytes are produced.
- Style lint fails: CI reports only stable code and field path, never the text.
- Registry unavailable: discovery is unavailable or an already authorized
  content-addressed cache may be used; the runtime does not build a shadow
  index.
- Search returns a wrong-tenant, deprecated, or incompatible candidate: the
  evaluation fails and the exact-fetch/compatibility boundary still prevents
  invocation.
- Duplicate delivery or retries: compilation and evaluation are pure and
  deterministic, so repetition produces the same bytes and metrics.

No process, queue, database, vector store, cache, container, network route, or
cloud resource is added. The only cost is a small build-time wheel increase and
offline test CPU. No alert is required because there is no new serving path.

## Alternatives considered

- Index only `description`: rejected because near-duplicate tools remain
  ambiguous and descriptions mix interface documentation with intent.
- Add Qdrant or an embedding model to the runtime: rejected because it creates
  a second catalog, tenancy boundary, backup path, and consistency failure.
- Put every semantic field in a new annotation: rejected because unaccepted
  keys drift from the Registry contract and may enter unsafe projections.
- Return complete artifacts from search: rejected because it defeats the token
  budget and exposes data before exact authorization.
- Let relevance bypass compatibility or policy checks: rejected because a
  probabilistic score is not authorization.

## Verification

- public model and linter tests cover every bound, secret shape, reserved key,
  canonical annotation, and server/tool narrowing rule;
- generated examples pass manifest lint and Agentic safe-document projection;
- the intent dataset records precision at K, no-match accuracy, incompatible
  recommendation count, and forbidden exposure count;
- all generated artifacts remain canonical and schema-compatible; and
- the runtime core dependency and wheel ceilings remain unchanged.

## Rollout and rollback

Rollout is additive: authors populate the typed fields, run lint and evaluation,
review the generated annotation diff, and publish only through the later issue
#21 workflow. Existing manifests without the fields continue to compile using
Registry description fallback.

Rollback is one Git revert. Generated artifacts from this version remain
readable because all fields are additive and the accepted annotation values are
plain strings. No Registry row, Gateway route, credential, database migration,
or deployment requires compensation in this issue.

## Consequences

Discovery metadata becomes bounded, reviewable, reusable, and measurable while
the serving runtime stays free of Registry and vector dependencies. Annotation
vocabulary evolution now requires explicit cross-repository compatibility
evidence, which is deliberate: that contract affects ranking and tenant-safe
projection across every consumer.
