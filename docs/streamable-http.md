# Streamable HTTP transport

`StreamableHTTPTransport` serves an `Application` through the official MCP
Python SDK v2 server. It is a thin adapter: tool contracts and policy remain in
the runtime core, while MCP request and response types remain under
`tesserix_mcp_runtime.adapters`.

## Compose the transport

Create the tool catalog as shown in the [authoring guide](authoring.md), then
inject a request-context provider and protocol telemetry sink:

```python
from tesserix_mcp_runtime.adapters.streamable_http import (
    StreamableHTTPConfig,
    StreamableHTTPLimits,
    StreamableHTTPTransport,
)

transport = StreamableHTTPTransport(
    config=StreamableHTTPConfig(),
    limits=StreamableHTTPLimits(),
    context_provider=my_context_provider,
    telemetry=my_protocol_telemetry,
)
```

The default listener is included. Pass a custom object implementing
`StreamableHTTPListener` only when another process supervisor owns the ASGI
server. Add `transport` to `Application`; the application's existing
`start()`, `drain()`, and `stop()` ordering owns listener lifecycle.

`HTTPCallContextProvider.create()` receives `HTTPRequestMetadata` and the
request cancellation object. It must authenticate and validate the gateway
metadata, then return a `CallContext` containing the authoritative identity,
request/run IDs, trace context, deadline, idempotency key, and approval lookup
reference. Header values are available through `header_values()` but are
always redacted from `repr()`.
Header presence alone is not authentication. Use the concrete
`GatewayJWTContextProvider` described in the
[Gateway identity guide](gateway-identity.md) to verify the direct peer, token,
claims, forwarded attribution, and bounded rotating JWKS before body parsing.

## Defaults and limits

The safe default is loopback-only, stateless, and finite:

| Setting | Default |
|---|---:|
| Host | `127.0.0.1` |
| Port | `8000` |
| Path | `/mcp` |
| Startup path | `/startupz` |
| Liveness path | `/livez` |
| Readiness path | `/readyz` |
| Metrics path | `/metrics` |
| Stateful sessions | disabled |
| Request body | 65,536 bytes |
| Request headers | 128 / 32,768 bytes |
| Response body | 524,288 bytes |
| Aggregate schema JSON | 262,144 bytes |
| Tool catalog | 128 tools |
| Tool page | 32 tools, at most four pages |
| Optional sessions | 128, 1,800-second absolute lifetime |
| Startup readiness | 2 seconds |
| Request/response stream | 300 seconds |

Tool and aggregate schema limits are checked before the listener binds. Request
bodies are limited before SDK parsing. Responses are buffered and committed
atomically, so overflow or serialization failure cannot leak a prefix of the
tool result.

## Gateway topology

Keep the default loopback bind when AgentGateway runs beside the runtime. The
gateway may expose a longer external route, but it must rewrite to the exact
upstream path:

```text
client /gateway/runtime/mcp  ->  AgentGateway  ->  runtime /mcp
```

One trailing slash is accepted. Operational paths are explicit and must be
distinct from the MCP path and from each other. Other paths return a generic 404. The listener
does not trust `Forwarded` or `X-Forwarded-*` headers and does not infer an
upstream path from them.

For a deliberate non-loopback bind, configure both allowlists:

```python
StreamableHTTPConfig(
    host="0.0.0.0",
    allowed_hosts=("runtime.internal.example:8443",),
    allowed_origins=("https://gateway.internal.example",),
)
```

AgentGateway must send an allowed upstream `Host` and origin. This does not make
direct public access supported; network policy and gateway authentication still
apply.

## Session modes

Stateless mode rejects every `Mcp-Session-Id`. It is the recommended mode for
the 2026-07-28 protocol and horizontally scaled runtimes.

Set `stateless=False` only for a named handshake-era compatibility requirement.
The runtime then:

- reserves capacity before SDK session creation;
- binds the opaque ID to tenant, issuer, and subject;
- rejects missing, forged, expired, and cross-owner IDs identically;
- uses an absolute lifetime rather than an extendable idle timeout;
- releases capacity on DELETE or expiry;
- includes concurrent pending initializations in the cap.

The 2026-07-28 path remains sessionless when compatibility mode is enabled.
State is process-local; do not route one legacy session across replicas unless
the gateway provides session affinity to the owning instance.

## Cancellation and drain

HTTP disconnects and legacy cancellation notifications signal the same
request-scoped `Cancellation` object before handler cleanup. Handlers and
downstream adapters should await or poll that object and release resources in a
`finally` block.

Every SDK request/response stream has a 300-second default and hard maximum.
At expiry the runtime signals cancellation before cancelling SDK work, aborts
the session lease, discards any uncommitted buffered response, and prevents a
detached SDK task from sending late output. If no response was committed, the
caller receives one bounded 504 with stable `timeout` data.

`Application.drain()` stops new admission immediately. Existing application
calls receive the application's bounded drain window; `stop()` then asks
Uvicorn to exit gracefully and force-cancels it only after the listener grace
period. Uvicorn signal handlers are disabled so the application remains the
single process-signal owner.

Lifecycle enters `draining` before transport admission closes, so `/readyz`
returns 503 first. `/livez` and `/metrics` remain available until listener
stop, and the in-flight metrics show accepted calls reaching zero. Startup and
liveness never call dependencies. Readiness runs only configured application
checks inside `ApplicationLimits.readiness_timeout`.

Operational routes accept GET and HEAD without gateway identity, return no
dependency or caller detail, and disable caching. Keep the listener private:
the metrics contract contains registered tool names. See the
[observability guide](observability.md) for the complete endpoint, metric,
dashboard, and alert contract.

## Failure responses

Boundary failures are deliberately non-disclosing:

- 404 for hidden paths and invalid sessions;
- 429 for stateful session capacity;
- 431 for malformed or over-limit headers;
- 413 for over-limit request bodies;
- 500 for atomic serialization or response overflow;
- 504 when the finite stream duration expires;
- 503 after drain begins.

Malformed JSON-RPC, unknown methods, invalid IDs, bad parameters, and
unsupported revisions use the official SDK's standard bounded errors. Client
responses never include an SDK version, credential, tenant value, tool result
prefix, or Python validation detail.

Authentication failures from `GatewayJWTContextProvider` return 401 with only
a safe request ID. MCP `_meta` under `tesserix/runtime/*` or `tesserix/adk/*`
cannot replace verified context; a supplied mismatch returns the stable
`authority_mismatch` code before tool execution.

## Compatibility evidence

Run the in-memory suite without network access:

```bash
uv run --frozen pytest tests/protocol/test_streamable_http.py
```

Run the real loopback listener against every locked client and the local path-
rewriting proxy:

```bash
uv run --frozen python compatibility/run_matrix.py
```

Run the pinned official Inspector CLI smoke test (Node/npm and network access
to the npm registry are required on a cold cache):

```bash
uv run --frozen python compatibility/run_inspector.py
```

See [ADR-0008](adr/0008-streamable-http-and-bounded-sessions.md) for the
decision, failure analysis, SDK-private session cleanup risk, and rollback.
