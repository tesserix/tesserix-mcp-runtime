# Tesserix MCP Runtime

Reusable, policy-aware hosting for Model Context Protocol servers on the
Tesserix platform.

The repository is in its pre-release foundation phase. The checked-in package
provides typed contracts, deterministic lifecycle primitives, stable safe
errors, a validated tool catalog, and reusable adapter conformance tests. It
does not yet start a network listener or serve MCP requests. No stable package
release is implied by interfaces described as planned below.

The accepted ownership boundary and measurable design envelope are recorded
in [ADR-0001](docs/adr/0001-runtime-ownership-and-envelope.md).

## Current versus planned behavior

| Capability | Status |
| --- | --- |
| Importable typed package and VCS-derived version command | Implemented in source; pre-release |
| Runtime contracts, lifecycle, tool schema policy, and conformance helpers | Implemented in source; pre-release |
| MCP v2 Streamable HTTP serving and bounded sessions | Planned; not implemented |
| ADK `ToolRegistry` bridge | Planned; not implemented |
| Registry manifests, signing, publication, and verification | Planned; not implemented |
| Registry-backed semantic discovery and progressive disclosure | Planned; not implemented |
| Automatic Gateway route pickup and activation status | Planned; not implemented |

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
    uv run --frozen mypy --strict src tests
    uv run --frozen pyright src tests
    uv run --frozen pytest
    uv run --frozen lint-imports --config pyproject.toml --no-cache --no-logo
    uv run --frozen python architecture/check_layers.py
    uv run --frozen python architecture/check_public_api.py
    uv run --frozen python architecture/check_dependencies.py
    uv run --frozen python security/check_licenses.py

Build validation is also offline after the frozen environment has been
installed:

    uv build --offline
    uv run --frozen twine check --strict dist/*
    uv run --frozen python architecture/check_artifacts.py dist
    uv run --frozen python architecture/smoke_install_artifacts.py --offline dist

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

## License

Apache-2.0.
