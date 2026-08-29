# ADR-0005: Runtime contracts and lifecycle

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#6](https://github.com/tesserix/tesserix-mcp-runtime/issues/6)
- Supersedes: the provisional `Tool` protocol in ADR-0003

## Context

One tool must retain the same authority, policy metadata, schema, failure
meaning, and lifecycle behavior in-process, through the official MCP SDK, and
through a future ADK bridge. Model-controlled arguments are untrusted. Tenant
identity, authorization state, exception details, and idempotency state are
security assets. The trust boundary is each adapter that validates external
data and constructs runtime contracts.

ADR-0001 assumes 50 sustained and 200 burst calls per second per pod, 64 KiB
requests, 512 KiB responses, 99.9% monthly invocation availability, and at
most 15 ms p99 runtime-added latency. These contracts add no network hop or
datastore. Registration validation runs at startup; per-call contract work is
constant-size context construction and failure mapping.

## Decision

### Tool contract

`ToolDefinition[InputT, OutputT]` is the only tool definition protocol. It
contains immutable `ToolMetadata`, input and output schemas, a typed
`ToolHandler`, and explicit parse/serialize functions. The older provisional
`Tool` protocol is removed before the first release because two overlapping
contracts would let adapters diverge.

Metadata distinguishes read, write, and external effects; explicit approval;
required scopes; and idempotency. Write or external-effect metadata without a
required idempotency contract is invalid. `ToolCatalog` rejects malformed
definitions, duplicate names, open objects, unbounded strings or arrays, and
policy limit breaches before serving traffic.

The initial validator uses a closed JSON Schema subset. Unsupported keywords
are rejected rather than ignored. Issue #9 may expand this subset when it can
prove optional, union, enum, nested, and recursive behavior against Pydantic
and the official MCP SDK from one schema source.

### Call authority

`AuthenticatedIdentity` is constructed by a trusted adapter and embedded in a
frozen `CallContext`. Identity is never accepted from tool arguments.
Call context also carries request and run IDs, W3C v00 trace state, a monotonic
deadline, adapter-neutral cancellation, and an optional idempotency key.

### Terminal results and errors

`InvocationResult` represents one terminal success or one stable public error.
The public codes are invalid input, unauthenticated, forbidden, approval
required, conflict, timeout, cancelled, unavailable, and internal failure.
Only timeout and unavailable are marked retryable, and only for safe or
idempotent operations.

Unknown exceptions map to `internal_failure`. Client data contains a fixed
message and request ID. Audit data contains only the stable code, bounded type
name, and request ID. Exception messages, arguments, payloads, credentials,
and stack traces are excluded by construction. `TerminalEmitter` serializes a
completion/cancellation race and accepts only the first result.

### Lifecycle

States are startup, ready, draining, and stopped. Start hooks run in
registration order; drain and stop hooks run in reverse order. Startup failure
rolls back every component reached. Drain and stop continue after individual
hook failures and report an aggregate count. A lock serializes concurrent
transitions, repeated shutdown is idempotent, and invalid transitions fail
deterministically.

The ordering assumes later components depend on earlier ones: dependencies
start first and stop last. Hooks remain sequential because dependency order is
part of correctness and component count is expected to be small. Issue #8 owns
the application composition that supplies concrete hooks.

### Adapter conformance

The public `tesserix_mcp_runtime.conformance` module tests listing, valid
invocation, invalid arguments, and unknown tools through an adapter-neutral
protocol. The issue #6 test suite runs one example through an in-process fake
and the official MCP SDK's in-memory client/server path. It opens no socket and
does not choose the production HTTP framework owned by issue #10.

## Failure behavior

| Failure | Deterministic result |
|---|---|
| Duplicate or malformed tool registration | `ContractViolation` before ready |
| Open, unbounded, oversized, or unsupported schema | stable violation code and schema path |
| Unknown handler exception | public `internal_failure`; scrubbed audit identity |
| Completion races cancellation | first terminal result wins exactly once |
| Startup hook fails | reverse rollback, `stopped`, one `LifecycleFailure` |
| Drain or stop hook fails | remaining hooks run; first component and count reported |
| Invalid or concurrent lifecycle transition | serialized result or `LifecycleTransitionError` |

No cross-system transaction is introduced. A retried write remains safe only
when its owning implementation enforces the declared idempotency contract;
issue #13 owns runtime policy enforcement.

## Alternatives considered

- Reuse official MCP SDK concrete types in core: rejected because it would
  couple every tool and ADK bridge to protocol package churn.
- Accept identity fields in arguments: rejected because model-controlled data
  cannot confer tenant or authorization authority.
- Return arbitrary exception messages: rejected because messages commonly
  contain payloads, dependency details, or secrets and are not stable APIs.
- Keep both `Tool` and `ToolDefinition`: rejected because adapters could choose
  incompatible invocation and metadata paths.
- Run lifecycle hooks concurrently: rejected because it destroys dependency
  order and makes rollback nondeterministic for a negligible startup saving.

## Compatibility, rollout, and rollback

This is a pre-release public API expansion and replacement authorized by
ADR-0003. The checked-in public API snapshot records every supported root
export. Future breaking changes require a major version; additive changes
follow the ADR-0003 review policy.

Rollout is a library release consumed by server applications; it changes no
gateway route, Kubernetes object, database, or credential. Rollback is one
dependency-lock reversion to the prior runtime build. A rollback also removes
the new contracts, so applications must roll back their use in the same
release. The implementation adds no infrastructure cost and no runtime
availability dependency.

## Verification

- deterministic unit and Hypothesis tests for context, metadata, schemas,
  errors, races, and lifecycle transitions;
- golden serialized metadata and public errors;
- the same conformance case through fake and official MCP SDK in-memory
  adapters;
- strict typing, lint, package, architecture, dependency, and compatibility
  gates required by the repository.
