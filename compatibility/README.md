# MCP SDK compatibility matrix

This directory proves that one MCP SDK v2.1.1 Streamable HTTP server can serve
the exact Python clients the project supports.

Run it from the repository root:

    uv lock --check
    uv lock --check --script compatibility/client_1_28.py
    uv lock --check --script compatibility/client_1_29.py
    uv lock --check --script compatibility/client_2_1.py
    uv run --frozen python compatibility/run_matrix.py
    uv run --frozen python compatibility/run_inspector.py
    uv run --isolated --frozen --extra adk pytest -q -o addopts='' \
      compatibility/adk/test_bridge.py

The runner starts one loopback-only `tesserix-mcp-runtime` server process,
executes every client lane against its endpoint, repeats the v2 lane through a
local proxy that rewrites `/gateway/runtime/mcp` to `/mcp`, terminates every
process it owns, and emits one JSON report.
Each lane verifies:

- the exact installed SDK version;
- protocol negotiation or initialization;
- tool listing across two cursor pages;
- a successful tool call;
- disconnect cancellation reaching an active handler;
- a tool failure result;
- clean client closure.

`server.py` runs in the frozen project environment so the matrix exercises the
runtime implementation rather than a generic SDK fixture. The three executable
clients use PEP 723 dependency declarations with adjacent uv locks. The v1
executables share client_v1.py because their API behavior is identical; their
environments remain separate.

`run_inspector.py` pins official MCP Inspector CLI 2.4.0 and verifies strict,
multi-page tool listing, structured tool invocation, and cancellation of an
active handler when the Inspector connection closes. A cold npm cache requires
network access; the default pytest suite does not invoke it.

This fixture is intentionally unauthenticated and must never be deployed.
It is not a production identity fixture. Production gateway identity
verification is implemented by issue #12's context provider.

The separate ADK lane downloads only the exact optional release pinned in
`pyproject.toml`. CI verifies that wheel's checksum and GitHub artifact
attestation before creating the isolated extra environment. It ports ADK's
same-tool local-versus-MCP behavior through the actual runtime transport and
also covers export narrowing, tenant mismatch, approvals, redaction, and the
modern protocol revision.

## Updating a lane

Change the exact dependency in the script, run uv lock --script for that one
file, update support-matrix.json and ADR-0002, then run the entire matrix. Never
hand-edit a generated lock and never change a support claim without executable
evidence.
