# MCP SDK compatibility matrix

This directory proves that one MCP SDK v2.1.1 Streamable HTTP server can serve
the exact Python clients the project supports.

Run it from the repository root:

    uv lock --check
    uv lock --check --script compatibility/server.py
    uv lock --check --script compatibility/client_1_28.py
    uv lock --check --script compatibility/client_1_29.py
    uv lock --check --script compatibility/client_2_1.py
    uv run --frozen python compatibility/run_matrix.py

The runner starts one loopback-only server process, executes every client lane
against its endpoint, terminates the server it owns, and emits one JSON report.
Each lane verifies:

- the exact installed SDK version;
- protocol negotiation or initialization;
- tool listing;
- a successful tool call;
- a tool failure result;
- clean client closure.

server.py and the three executable clients use PEP 723 dependency declarations
with adjacent uv locks. The v1 executables share client_v1.py because their API
behavior is identical; their environments remain separate.

This fixture is intentionally unauthenticated and must never be deployed.
Production transport security, limits, sessions, and gateway behavior are
implemented and tested by their owning issues.

## Updating a lane

Change the exact dependency in the script, run uv lock --script for that one
file, update support-matrix.json and ADR-0002, then run the entire matrix. Never
hand-edit a generated lock and never change a support claim without executable
evidence.
