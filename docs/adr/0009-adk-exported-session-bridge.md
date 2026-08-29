# ADR-0009: ADK exported-session bridge

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#11](https://github.com/tesserix/tesserix-mcp-runtime/issues/11)

## Context

Tesserix ADK 0.53.1 already owns `AgentToolView`, export narrowing,
per-tenant lanes, tool validation and ceilings, approval-pending results,
result redaction, stable refusal and failure codes, and MCP descriptor
generation. It deliberately exposes `McpServer` and `ExportedSession` rather
than a network listener. Rebuilding those behaviors in this runtime would
create a second schema, authorization, approval, and error implementation that
could drift from local ADK execution.

The runtime envelope remains 50 sustained and 200 burst calls per second per
pod, 64 KiB requests, 512 KiB responses, at most 15 ms p99 runtime-added
latency, 99.9% monthly invocation availability, and an expected 12-tool catalog
with a reviewed maximum of 128. The bridge adds no network hop, queue,
datastore, or durable state. Production p99 and saturation evidence remains
owned by issue #29 rather than inferred from unit tests.

The optional installed profile measured 30,760,274 file bytes and 33 active
distributions on Python 3.14.7 arm64, versus 26,371,197 bytes and 29 for core:
a 4,389,077-byte (16.64%) increase. The digest-pinned ADK base image carries
the ADK `all` extras and is intentionally larger. Its compressed increase over
the Python 3.14 runtime image is 92,115,060 bytes on amd64 and 92,866,888 bytes
on arm64. Exact manifests and methodology are recorded in
`architecture/adk-bridge-size-report.json`.

The assets at risk are tenant authority, tool export authority, approval
records, tool results, and secrets a tool could accidentally return. Attackers
include an unauthenticated caller, an authenticated caller claiming another
tenant, a caller probing unexported names, and a compromised or incompatible
optional dependency. The HTTP context provider and the ADK exported session
are separate trust boundaries: identity is accepted only from the immutable
`CallContext`, every ADK call revalidates that identity, and caller-controlled
MCP metadata is not promoted to authority.

## Decision

### Add a protocol-native, SDK-neutral endpoint contract

`StreamableHTTPProtocolEndpoint` and `StreamableHTTPProtocolSession` sit beside
the core `ApplicationEndpoint`. They carry protocol descriptors and results
without forcing ADK approval, refusal, content-block, or structured-result
semantics through the core `InvocationResult` error vocabulary. Core
application contracts remain unchanged and cannot import ADK.

The transport opens, initializes, and closes one native session for each
official initialize, list, or call operation. Startup descriptors are held as
the immutable surface. Every later list must match it exactly; an addition,
removal, reorder, schema change, or fingerprint change fails generically rather
than widening a live model-visible catalog. Sessions close in `finally` paths.
Unexpected adapter exceptions become generic internal errors without their
messages, while already-safe `MCPError` values keep their stable protocol code.

### Delegate to the exact public ADK surface

`ADKStreamableHTTPBridge` accepts an actual `AgentToolView` and an explicit
export sequence. It constructs ADK `McpServer` with authenticated tenants
required and all revisions in the official SDK's
`SUPPORTED_PROTOCOL_VERSIONS`, including 2026-07-28. ADK rejects any export
outside the view before the listener starts.

Descriptors come from ADK `published`; fingerprints come from ADK
`fingerprint`. Calls delegate directly to `ExportedSession.initialize`,
`list_tools`, `call_tool`, and `close`. The bridge converts only the
transport-neutral data boundary. It does not derive schemas from callables,
reimplement validation, execute tool bodies itself, interpret approval
records, or map ADK result codes into a second vocabulary.

The adapter dynamically loads exactly `tesserix-adk==0.53.1`. Importing core or
the adapter module does not import ADK. A missing dependency or any other ADK
version fails bridge construction with `ADKBridgeDependencyError`; the core
runtime remains installable, buildable, and testable. The optional dependency
is the GitHub release wheel pinned by SHA-256 until trusted PyPI publishing
exists.

### Derive ADK authority only from `CallContext`

The bridge supplies the authenticated tenant separately and builds ADK session
metadata from the trusted tenant, subject, run ID, scopes, W3C trace fields,
and idempotency key. HTTP headers are not forwarded to ADK. Of the remote
request `_meta`, only `tesserix/adk/tenant` is forwarded, solely so ADK can
reject a claim that differs from the authenticated tenant. Remote subject,
run, scopes, trace, and idempotency values are discarded.

Missing transport authentication is rejected before an ADK session is opened.
A mismatched tenant becomes a generic unauthorized MCP error carrying only the
stable ADK reason. Unknown and unexported tools both become the same generic
tool-refused error and `not_found` data code. Tool names, tenant values, ADK
messages, approval reasons, and body failure text are not returned or chained
into protocol logs.

ADK `GatewayToolResult` content, structured content, error flag, approval
record, refusal code, failure code, redaction, registry timeout, and tenant-lane
behavior pass through unchanged. The runtime validates official MCP content
blocks and still enforces its 512 KiB atomic response ceiling.

### Verify the release before the compatibility lane

The `adk` dependency profile permits `tesserix-adk` while the core profile
continues to forbid it. CI downloads the 0.53.1 wheel, verifies its SHA-256 and
GitHub artifact attestation, proves the core environment contains no ADK, then
runs the cross-package suite in an isolated exact-extra environment. The
compatibility workflow accepts the `adk-release` repository-dispatch event; a
new unreviewed release deliberately fails until its pin, attestation, API, and
behavior are reviewed.

## Failure behavior

| Failure | Behavior |
|---|---|
| ADK extra is absent | Bridge construction fails; core import, build, and tests continue |
| ADK version or required public API differs | Construction or downstream compatibility fails before readiness |
| Export is outside `AgentToolView` | ADK construction fails; no listener binds |
| Live descriptor differs from startup | Generic internal discovery error; no widened list is returned |
| Missing authenticated context | Generic HTTP 401 before ADK session use |
| Remote tenant differs from authenticated tenant | Generic unauthorized MCP error before the tool body |
| Unknown or unexported tool | Identical generic error with stable `not_found` data |
| Approval is required | Original ADK pending result; body is not executed |
| Tool refuses, fails, times out, or leaks a configured secret | Original safe ADK code and redacted result; no body message |
| Session initialization, call, content validation, or close fails unexpectedly | Session cleanup is attempted and a generic internal error is returned |
| ADK base image is unavailable | Build from the digest-pinned core image and install the attested optional wheel |

The bridge performs no automatic retry. A client can disconnect after a tool
side effect but before receiving its answer; ADK and the tool remain the owners
of idempotency and compensation. The trusted runtime idempotency key reaches
ADK, but a mutating tool without an idempotency contract is not made safe by
this adapter.

## Alternatives considered

- Copy ADK tools into runtime-native handlers: rejected because schemas,
  validation, approvals, lanes, redaction, and result semantics would have two
  owners.
- Make ADK a core dependency: rejected because non-ADK servers would pay the
  package and image cost and core would acquire the wrong dependency arrow.
- Trust all remote `_meta`: rejected because a caller could replace the
  authenticated subject, scopes, run, trace, or idempotency key.
- Force ADK results through `InvocationResult`: rejected because approval and
  refusal records would be lossy or would change the core contract for one
  optional integration.
- Hold one ADK session across HTTP requests: rejected because ephemeral
  exported sessions have no owned resources and per-operation construction
  keeps authority and protocol revision explicit with a smaller cross-tenant
  state surface.
- Use only the ADK `all` base image: rejected as the universal default because
  its measured compressed cost is about 88 MiB more; it remains supported for
  agent processes that already need those extras.

## Verification

The default suite uses fake public ADK contracts and never installs ADK. The
isolated compatibility suite uses the exact attested release and proves local
versus HTTP structured success, refusal and failure codes, approval pending,
redaction, trusted context, tenant mismatch, unknown versus unexported tools,
descriptor fingerprints, export narrowing, and modern protocol support.

    uv run --frozen pytest tests/adapters/test_adk.py \
      tests/protocol/test_streamable_http.py
    uv run --isolated --frozen --extra adk pytest -q -o addopts='' \
      compatibility/adk/test_bridge.py

## Consequences, rollout, and rollback

The default install gains no ADK distribution and no additional running
service. ADK servers opt into the extra and choose either the core Python 3.14
base plus the exact wheel or the larger ADK base image when its preinstalled
extras are already useful. No database migration, Registry mutation, Gateway
activation, or Kubernetes rollout is performed by this issue.

Rollout begins behind the existing loopback-only, stateless Streamable HTTP
listener. Compatibility and negative tests must pass before a Registry version
or Gateway route can reference the image. Rollback drains the instance and
restores the previous image or removes the optional bridge composition. There
is no persisted bridge state to migrate or compensate.
