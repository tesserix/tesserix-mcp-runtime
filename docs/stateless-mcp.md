# Stateless MCP production contract

This guide records the Tesserix interpretation of stateless MCP for runtime,
product-server, Registry, Gateway, and Kubernetes owners. The authoritative
source is [SEP-2575](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2575-stateless-mcp.md),
including its post-final changes. The Solo article is useful deployment
context. The Medium article describes the older stateful/stateless trade-off
but predates the stateless protocol revision. The MCPMarket page is a catalog
entry, not a protocol authority.

## Mental model

A request is stateless when any healthy replica can process it correctly
without a previous request, a pod-local session, or sticky routing. Connection
pools, immutable indexes, and bounded caches are allowed: they improve
efficiency but do not own correctness. Durable workflow state, pagination
cursors, resumability, and write deduplication belong in an external authority
such as the product database, object storage, or a workflow engine.

Stateless does not mean pure or read-only. A tool may mutate state when the
product API owns the transaction and an idempotency record keyed by tenant,
operation, and idempotency key. It also does not mean authentication material
belongs in tool arguments. Gateway identity is verified on every request and
becomes trusted `CallContext`; tokens never pass through the model.

## Protocol 2026-07-28

The modern request path has no `initialize` or
`notifications/initialized` handshake. Every HTTP operation uses POST and
supplies all routing and capability context for that request:

- `MCP-Protocol-Version: 2026-07-28` is required and must match
  `params._meta["io.modelcontextprotocol/protocolVersion"]`.
- `MCP-Method` must match the JSON-RPC method. Method-specific routing headers,
  such as `MCP-Name`, must agree with the body.
- `params._meta["io.modelcontextprotocol/clientCapabilities"]` carries the
  capabilities available for this request. A server must not infer them from
  an earlier request. Client information is optional, though clients should
  send it.
- Servers implement `server/discover`. A client may call it before invoking
  other methods; it is discovery, not session creation.
- An unsupported revision returns HTTP 400 and JSON-RPC `-32022`, including
  requested and supported versions.

The old HTTP GET event stream and `Last-Event-ID` resumption are removed.
Where notification capabilities are advertised, `subscriptions/listen` uses
POST and every notification class is explicitly opted in. A server that does
not advertise subscriptions returns the standard method-not-found response;
it must not emit unsolicited notifications. Closing an HTTP response cancels
the request. Durable or resumable work uses MCP tasks or an external workflow
reference, never a hidden transport session.

Legacy revisions may remain behind an explicitly named compatibility lane.
They may use initialization and bounded sessions, but they are not the
approved Tesserix production topology and must never make `2026-07-28`
sessionful.

## Runtime and platform requirements

The runtime defaults to stateless Streamable HTTP and rejects every
`Mcp-Session-Id`. Production listeners remain loopback-only behind
AgentGateway unless exact host and origin allowlists are configured. Identity,
authorization, tenant isolation, deadlines, limits, and cancellation are
re-established for every request.

Kubernetes deployments use at least two replicas for qualification, ordinary
round-robin routing, and `sessionAffinity: None`. Pods keep no request or
workflow state in memory or on their filesystem. Reliability evidence must
alternate replicas, show zero pod-local request state, and prove one external
effect under duplicate delivery. A rollout cannot be promoted from a legacy
initialize-only probe: for modern artifacts it must complete authenticated
`server/discover` and a self-contained bounded operation using `2026-07-28`.

Registry publication records exact protocol versions and immutable artifact,
SBOM, and provenance digests. Registry metadata is a declaration, not proof;
Gateway activation and reliability qualification must bind their observations
to the same artifact digest. Unsupported capabilities are not advertised.

## Product MCP acceptance checklist

Every Tesserix product MCP must satisfy all of these before registration and
Gateway synchronization:

1. Declare and test `2026-07-28`, `server/discover`, `tools/list`, valid and
   invalid `tools/call`, header/body mismatches, unsupported versions, request
   cancellation, and the absence of legacy GET behavior.
2. Keep tool schemas closed and bounded. Classify read versus write effects,
   required scopes, egress authorities, timeouts, and response-size limits.
3. Take identity and tenant only from verified request context. Never accept
   credentials, tenant overrides, or policy claims as model-controlled tool
   arguments.
4. Put workflow state in the owning product service. Return opaque,
   tenant-bound state or task references for pagination and long-running work;
   never retain correctness-critical state in an MCP pod.
5. Make writes idempotent in an external authority and test retries across
   replicas. Do not use an in-process set or cache as the deduplication record.
6. Publish immutable manifests and supply-chain evidence, then require a
   digest-bound modern protocol probe before the Gateway exposes the route.
7. Deploy without cookie affinity or MCP sessions, with bounded resources,
   graceful drain, telemetry redaction, egress allowlists, and default-deny
   authorization.

## Source reconciliation

- SEP-2575 and the current specification define required behavior. Its final
  follow-up makes client information optional and refines discovery and
  subscription results.
- Solo correctly emphasizes round-robin scaling, failover, routing headers,
  and the removal of handshake-era coupling. Its overview is secondary to the
  normative SEP.
- Medium's examples of session cleanup, concurrency, and affinity risks remain
  useful. Its advice to keep authentication tokens, pagination state, clones,
  or multi-step workflow state in an implicit MCP session is not the Tesserix
  design. Use verified per-request identity, opaque cursors, tasks, and durable
  external state instead.
- MCPMarket can help discover implementations. Catalog claims never replace
  conformance, security, reliability, provenance, or activation evidence.

