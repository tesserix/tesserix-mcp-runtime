# Tesserix MCP Runtime

Reusable, policy-aware hosting for Model Context Protocol servers on the
Tesserix platform.

The repository is in its architecture phase. It does not yet contain a
released runtime package. The accepted ownership boundary and measurable
design envelope are recorded in
[ADR-0001](docs/adr/0001-runtime-ownership-and-envelope.md).

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

## License

Apache-2.0.
