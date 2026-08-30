# MCP SDK compatibility matrix

This directory is the executable release gate for the runtime's supported MCP
clients. It tests installed artifacts across a real process and gateway
boundary; importing the source tree is not accepted as release evidence.

## Proven surfaces

| Runtime artifact | Route | Clients | Expected behavior |
|---|---|---|---|
| built wheel | direct `/mcp` | SDK 1.28.1, 1.29.1, 2.1.1 | full two-page catalog |
| built core image | direct `/mcp` | SDK 1.28.1, 1.29.1, 2.1.1 | full two-page catalog |
| built core image | AgentGateway `/gateway/runtime/mcp` | SDK 1.28.1, 1.29.1, 2.1.1 | first catalog page; page-two tools remain callable |
| built core image | AgentGateway `/gateway/runtime/mcp` | DevAI `DownstreamConnection` | discover, invoke, close, reconnect |
| built core image | direct and AgentGateway | Inspector 2.4.0 | structured call and disconnect cancellation |

Every exact SDK lane verifies its installed version, initialization, negotiated
capabilities, listing, structured invocation, cancellation, a tool error,
clean closure, and reconnect. SDK 2.1.1 additionally proves modern 2026-07-28
and legacy 2025-11-25 modes. A raw probe proves that protocol 1900-01-01 is
rejected during modern initialization with the standard `-32022` error.

AgentGateway v1.4.1 deliberately merges the first page returned by each MCP
target and emits no aggregate cursor. The gateway lanes therefore record
`agentgateway_pagination` as a feature gap. They still invoke a tool placed on
the hidden second page, proving AgentGateway's bounded target resolver follows
upstream cursors for calls. Direct wheel and image lanes remain the canonical
full-pagination evidence.

The DevAI lane uses the real
`devai.mcphub.downstream.DownstreamConnection` from commit
`850379a833bb5740c82eb2a16cac452ff93695f0`. CI verifies the adapter file's
SHA-256, installs DevAI from its frozen lock, and confirms `mcp==1.28.1` before
running it through AgentGateway. DevAI's adapter exposes only its first
`list_tools()` page, so that independent pagination gap is also explicit.

## Canonical run

The complete, pinned sequence lives in
[compatibility.yml](../.github/workflows/compatibility.yml). It:

1. validates all uv locks and the pinned DevAI source;
2. builds the runtime wheel and installs it into an isolated Python 3.14
   environment;
3. builds and verifies `deploy/container/core.Dockerfile` with provenance;
4. starts the hardened two-service Compose stack with the digest-pinned
   AgentGateway image;
5. runs the 13 JSON/JUnit matrix cases and both Inspector surfaces;
6. scans every retained artifact for bearer tokens, secret assignments, and
   bounded-size violations before a seven-day upload.

Once those environments and the stack are prepared, the matrix command is:

```text
uv run --frozen python compatibility/run_matrix.py \
  --wheel-python <wheel-venv>/bin/python \
  --image-endpoint http://127.0.0.1:38080/mcp \
  --gateway-endpoint http://127.0.0.1:33000/gateway/runtime/mcp \
  --devai-python <devai-checkout>/.venv/bin/python \
  --devai-root <devai-checkout> \
  --report <evidence>/matrix.json \
  --junit <evidence>/junit.xml
```

`run_inspector.py` takes `--endpoint` and `--report`; CI invokes it once for
each image route. A cold npm cache requires network access. Default pytest is
networkless and tests the evidence, stack, workflow, and adapter contracts with
fakes.

## Trust boundary

The fixture is intentionally unauthenticated and must never be deployed. Both
published ports bind only to loopback. Containers run read-only, non-root,
without Linux capabilities or host credentials. Child client environments
receive an allowlisted environment rather than CI tokens. Retained evidence
contains client, SDK, protocol, operation, artifact, transport, and safe error
class/code only; it excludes endpoints with credentials, tool payloads, auth
tokens, and raw session logs.

The Compose network must be non-internal for Docker to honor host port
publication. That permits egress, but neither service receives credentials or
secrets. The stack is destroyed after each run and has no persistent volumes.

## Updating a lane

Change the exact dependency in one PEP 723 script, regenerate only its adjacent
lock with `uv lock --script`, update `support-matrix.json` and ADR-0002, then
run the complete artifact matrix. Never hand-edit generated locks or remove a
lane without the downstream and release-candidate evidence required by the
deprecation policy.
