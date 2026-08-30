# Tesserix MCP Runtime

Reusable, policy-aware hosting for Model Context Protocol servers on the
Tesserix platform.

The repository is in its pre-release runtime phase. The checked-in package
provides typed contracts, an explicit application composition root,
deterministic bounded lifecycle, stable safe errors, a validated tool catalog,
typed-callable schema generation, handler-free manifest snapshots,
process-signal handling, reusable in-process conformance support, and the
official MCP v2 Streamable HTTP transport with a private bounded listener,
finite execution, tenant bulkheads, deadlines, cancellation, safe retries, and
identity-scoped bounded Registry discovery, and opt-in immutable Registry
publication with exact read-back and signature verification. It also provides
a read-only, digest-bound Gateway activation status contract and bounded CLI
waiter; the Registry/Gateway producer rollout remains external and does not yet
activate routes automatically. No stable package release is implied by
interfaces described as planned below.

The accepted ownership boundary and measurable design envelope are recorded
in [ADR-0001](docs/adr/0001-runtime-ownership-and-envelope.md).

## Current versus planned behavior

| Capability | Status |
| --- | --- |
| Importable typed package and VCS-derived version command | Implemented in source; pre-release |
| [Runtime contracts](docs/contracts.md) and [reusable conformance testkit](docs/conformance.md) | Implemented in source; pre-release |
| Explicit application composition, in-process transport, signals, and bounded drain | Implemented in source; pre-release |
| Typed callable authoring, schema fingerprints, compatibility classification, and handler-free metadata export | Implemented in source; pre-release |
| MCP v2 Streamable HTTP serving, compatibility matrix, and bounded sessions | Implemented in source; pre-release |
| ADK `AgentToolView` and `McpServer` bridge | Implemented as an exact optional profile |
| Default-deny per-tool scopes, effects, approvals, idempotency, and audit | Implemented in source; pre-release |
| Bounded JSON, concurrency, deadlines, cancellation, and safe retries | Implemented in source; pre-release |
| [Bounded telemetry, health, and graceful drain](docs/observability.md) | Implemented in source; pre-release |
| [Registry manifests](packages/tesserix-mcp-manifest/README.md) | Compilation is opt-in; pre-release |
| [Registry publication](docs/registry-publication.md) | Implemented as opt-in delegated tooling; pre-release |
| [Registry-backed semantic discovery and progressive disclosure](docs/registry-discovery.md) | Implemented as an opt-in bounded client; pre-release |
| [Gateway activation status](docs/gateway-activation.md) | Typed contract and bounded observer implemented; producer rollout tracked externally |

The version can be inspected without starting runtime behavior:

    uv run --frozen tesserix-mcp-runtime --version

## Design intent

The runtime will add the Tesserix deployment boundary around the official MCP
Python SDK:

- typed server composition and lifecycle;
- authenticated tenant context and per-tool policy;
- bounded requests, concurrency, deadlines, and results;
- common telemetry, health, and graceful drain behavior;
- portable server.json and Agentic Registry manifest generation;
- an optional bridge to the existing Tesserix ADK tool surface.

It will not own semantic ranking, Registry state, gateway routes, identity
issuance, credentials, or product tool behavior. Those remain with their
existing authoritative systems.

## Architecture verification

The initial targets are machine-readable in
[benchmarks/envelope-targets.json](benchmarks/envelope-targets.json). The
small checker in [benchmarks/check_envelope.py](benchmarks/check_envelope.py)
lets later runtime benchmarks report whether an observation meets that
contract without rewriting thresholds in each test.

    python3 benchmarks/check_envelope.py benchmarks/example-observations.json

These targets are assumptions to validate before GA, not claims about current
production performance.

## Reproducible development

Use Python 3.14 and uv 0.12.x. The default tests deny network sockets while
allowing the Unix socket pairs required by asyncio.

    uv sync --frozen
    uv run --frozen ruff format --check .
    uv run --frozen ruff check .
    uv run --frozen mypy --strict src tests packages/*/src packages/*/tests
    uv run --frozen pyright src tests packages/*/src packages/*/tests
    uv run --frozen pytest
    uv run --frozen lint-imports --config pyproject.toml --no-cache --no-logo
    uv run --frozen python architecture/check_layers.py
    uv run --frozen python architecture/check_public_api.py
    uv run --frozen python architecture/check_dependencies.py
    uv run --frozen python security/check_licenses.py

Build validation is also offline after the frozen environment has been
installed. The artifact smoke step installs only the distribution itself;
`uv sync --frozen` and the dependency checks above verify its locked closure.

    uv build --all-packages --clear --offline --no-create-gitignore
    uv run --frozen twine check --strict dist/*
    uv run --frozen python architecture/check_artifacts.py dist
    uv run --frozen python architecture/smoke_install_artifacts.py --offline --no-deps dist

The security workflow exports hash-pinned runtime requirements from `uv.lock`
for `pip-audit`, verifies the license path of every reachable runtime
dependency, scans Git history with a checksum-verified Gitleaks binary, and
runs CodeQL and dependency review with least-privilege tokens.

## Compatibility baseline

Production images use Python 3.14. The library supports Python 3.12 through
3.14 and declares MCP Python SDK v2.1.1 or newer within major version 2.
Frozen compatibility lanes exercise DevAI's 1.28.1 client, maintained v1
1.29.1, and current v2 2.1.1 against the same server.

There is no MCP Python SDK 1.34 release. The evidence, upgrade policy, and
protocol-versus-package distinction are recorded in
[ADR-0002](docs/adr/0002-python-and-mcp-compatibility.md).

## Public API and dependency boundaries

The distribution is library-first. Stable runtime contracts are imported from
`tesserix_mcp_runtime`; integrations live under the explicit adapter namespace
and point inward to those contracts. Core never imports SDK, ADK, Registry,
Kubernetes, database, orchestration, or provider implementations.

[ADR-0003](docs/adr/0003-public-api-and-dependency-layering.md) records the
dependency arrows, authoritative schema owners, ADK source strategy,
deprecation policy, and measured package budgets. CI executes all three
architecture invariants:

    uv run --frozen lint-imports --config pyproject.toml --no-cache --no-logo
    uv run --frozen python architecture/check_public_api.py
    uv run --frozen python architecture/check_dependencies.py

## Security model

Publication, semantic discovery, activation, Gateway routing, runtime
invocation, and backing API access are separate default-deny trust boundaries.
Semantic ranking returns tenant-filtered candidates only; an exact immutable
Registry version is authorized again before activation or use. Neither search
metadata nor AgentGateway replaces runtime per-tool authorization.

[ADR-0004](docs/adr/0004-cross-system-threat-model.md) records the data flows,
claim trust contract, non-disclosing failures, write-capability review, secret
lifecycle, incident response, current gaps, and fake request walkthroughs. Its
machine-readable review and 50-test implementation inventory are enforced with:

    uv run --frozen python security/check_threat_model.py --model security/threat-model.json

## Runtime contracts

The first reusable foundation defines one typed tool and call-context contract,
stable payload-free errors, deterministic lifecycle ordering, and an
adapter-neutral conformance suite. The same example is exercised in-process
and through the official MCP SDK's in-memory client/server path.

See the [runtime contract guide](docs/contracts.md) for authoring and adapter
examples. [ADR-0005](docs/adr/0005-runtime-contracts-and-lifecycle.md) records
the authority boundary, supported schema policy, failure semantics, lifecycle
ordering, compatibility impact, and rollback.

The [application guide](docs/application.md) shows explicit dependency
composition, deterministic in-process invocation, manual lifecycle control,
and SIGINT/SIGTERM process orchestration. [ADR-0006](docs/adr/0006-compositional-application-and-drain.md)
records admission ordering, global deadline behavior, dependency failures,
performance cost, alternatives, rollout, and rollback. The installed-wheel
benchmark supervisor checks startup and idle RSS against the committed M0
targets:

    uv run --frozen python benchmarks/measure_application.py \
      /path/to/installed/python tests/fixtures/application_smoke.py

## Typed callable authoring

The runtime can now adapt an explicitly registered typed Python callable using
the official MCP SDK as the single schema and validation authority. Registration
enforces closed and bounded schemas, rejects model-controlled identity fields,
attaches immutable semantic metadata, and emits handler-free schema snapshots
with deterministic fingerprints. Directional compatibility classification
provides evidence for later Registry publication without publishing or
activating anything itself.

See the [typed callable guide](docs/authoring.md) for a complete authoring
example, semantic metadata rules, schema limits, manifest shape, and change
classification. [ADR-0007](docs/adr/0007-typed-callable-authority-and-manifests.md)
records the schema authority, trust boundary, dependency failures, quantitative
ceilings, alternatives, rollout, and rollback.

## Streamable HTTP

The runtime now serves its compositional `Application` through the official MCP
SDK v2 Streamable HTTP server. The default listener is loopback-only and
stateless, waits for ASGI readiness, normalizes one stable route, enforces
finite headers, bodies, responses, schemas, tools, pages, and optional legacy
sessions, and propagates trusted call context plus cancellation without leaking
SDK types into core handlers.

Stateful compatibility mode binds each opaque session to tenant, issuer, and
subject with a finite absolute lifetime. Non-loopback binding requires explicit
host and origin allowlists. AgentGateway remains the supported public ingress
and may rewrite `/gateway/runtime/mcp` to the stable upstream `/mcp` path.

See the [Streamable HTTP guide](docs/streamable-http.md) for composition,
limits, gateway routing, failure responses, and verification commands.
[ADR-0008](docs/adr/0008-streamable-http-and-bounded-sessions.md) records the
protocol authority, session model, cancellation ordering, SDK upgrade risk,
alternatives, rollout, and rollback.

## Gateway identity

The runtime includes a fail-closed gateway JWT context provider. It requires a
direct peer from an explicit trusted-proxy CIDR, independently verifies a
fixed-algorithm runtime-audience token, derives immutable tenant, subject, and
scope authority per request, and rejects forwarded-header or MCP-metadata
disagreement before a tool runs. Bounded single-flight JWKS rotation supports a
15-minute fresh window and an explicit one-hour maximum stale window for known
keys only.

See the [Gateway identity guide](docs/gateway-identity.md) for composition,
claim and header contracts, JWKS outage behavior, network prerequisites, and
verification commands. [ADR-0010](docs/adr/0010-gateway-jwt-and-tenant-context.md)
records the trust hierarchy, quantitative tradeoffs, residual DNS and network
risk, dependency cost, rollout, and safe rollback.

## Tool policy

Non-ADK servers can now compose `ToolPolicy` as the final default-deny
authorizer. Only exact active reviewed rules are listed or invocable. Verified
caller scopes are intersected with server and tool ceilings; writes require a
trusted idempotency key; external effects always require an exact expiring
approval. One-time approvals are atomically consumed through an injected
store. Allowed and denied decisions append payload-free audit events.

Product backing services remain authoritative for mutation idempotency and the
original result. The runtime passes the same tenant and key rather than adding
a replica-local store. Unknown and unexported tools are indistinguishable to
callers. Policy or audit dependency failure stops the handler; a failed denial
audit never changes the caller-visible denial code.

See the [tool policy guide](docs/tool-policy.md) for composition, review,
approval-store, idempotency, header, audit, and failure contracts.
[ADR-0011](docs/adr/0011-default-deny-tool-policy.md) records the trust
boundary, exact digest decision, distributed failure behavior, alternatives,
cost, rollout, and rollback.

## Runtime resource safety

`ExecutionLimits` applies transport-independent byte, JSON structure, tool,
process, server, tool, tenant, deadline, cancellation, attempt, and backoff
ceilings. Saturated work is shed immediately without an internal queue. The
earliest authenticated caller, gateway, runtime, and tool deadline reaches the
handler; work that ignores cancellation remains counted after detachment.
Reads and explicitly idempotent mutations retry only transient failures inside
the original deadline.

See the [runtime safety guide](docs/runtime-safety.md) for every default and
hard maximum, handler and downstream cancellation contract, retry matrix,
stable outcomes, and the checked-in memory/latency observation.
[ADR-0012](docs/adr/0012-finite-execution-and-tenant-bulkheads.md) records the
threat boundary, quantitative tradeoffs, failure behavior, alternatives,
rollout, and rollback.

## Data safety and outbound HTTP

`SecretValue` renders redacted by construction, while the replaceable
`SecretRedactor` applies bounded exact-value and secret-shape redaction to final
results, stable errors, protocol telemetry, and policy audit. A redaction error
fails closed and the raw result is never returned.

`EgressManifest` declares exact HTTPS host-port authorities. The provided
`OutboundHTTPClient` resolves and validates every DNS answer at connection
time, connects to a pinned address with the original TLS name, verifies the
actual peer before sending bytes, and repeats the policy for bounded redirects.
Private and special-purpose networks are denied unless a separate operator
CIDR policy explicitly permits them.

See [data safety and outbound HTTP](docs/data-safety-and-egress.md) and
[ADR-0013](docs/adr/0013-redaction-and-connection-pinned-egress.md) for
composition, limits, stable errors, residual risks, the isolated SSRF harness,
rollout, and rollback.

## Registry discovery

An optional bounded client now consumes Agentic Registry's shipped authorized
stub search, fetches at most one exact artifact, verifies its canonical digest,
and projects only reviewed tools to the existing ADK MCP configuration. Search
and exact caches are finite and partitioned by Registry origin plus a hash of
issuer, tenant, subject, and scopes. Offline reuse is disabled by default.

See the [Registry discovery guide](docs/registry-discovery.md) for the current
Registry contract, composition, cache leases, typed failure behavior, exact
dependency evidence, ADK ownership boundary, and publication/Gateway
limitations. [ADR-0018](docs/adr/0018-identity-scoped-registry-discovery.md)
records the decision, failure analysis, rollout, and rollback.

## ADK bridge

An optional adapter now binds an existing ADK `AgentToolView` and explicit
export allowlist to the Streamable HTTP transport. It delegates descriptors,
fingerprints, validation, approvals, tenant lanes, ceilings, redaction, and
result codes to the exact attested ADK 0.53.1 release. Core installation and
tests remain ADK-free.

See the [ADK bridge guide](docs/adk-bridge.md) for composition, trusted context
mapping, exact dependency and image choices, and the isolated compatibility
command. [ADR-0009](docs/adr/0009-adk-exported-session-bridge.md) records the
SDK-neutral session boundary, security behavior, measured size tradeoff,
release verification, rollout, and rollback.

## License

Apache-2.0.
