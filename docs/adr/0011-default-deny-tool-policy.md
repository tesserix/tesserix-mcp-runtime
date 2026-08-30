# ADR-0011: Default-deny tool policy and exact approval binding

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#13](https://github.com/tesserix/tesserix-mcp-runtime/issues/13)

## Context

ADR-0001 assigns final per-tool scope, side-effect, and approval authorization
to this runtime. ADR-0010 supplies one immutable, independently verified
`CallContext` per gateway request. A valid runtime-audience token is necessary
but insufficient authority to execute every tool in a server.

The protected assets are tenant-scoped tool authority, approval capability,
mutation results, and policy audit evidence. Threat actors include a caller
from another tenant, a correctly authenticated caller replaying a prior call,
a compromised gateway forwarding broader input, a tool attempting to change
its own metadata, and a failed or compromised policy dependency. The runtime
trusts only the verified call context, reviewed immutable tool snapshots, and
typed results from configured policy stores. It never trusts tool arguments,
descriptions, `confirm=true`, client MCP `_meta`, or a tool's mutable runtime
attributes as authority.

The design remains inside the ADR-0001 and ADR-0006 envelope:

| Measure | Contract |
|---|---:|
| Sustained / short-burst calls per pod | 50 / 200 calls per second |
| Request / response ceiling | 64 KiB / 512 KiB |
| Maximum tools per server | 128 |
| Runtime-added direct-transport p99 | at most 15 ms |
| Monthly invocation availability | 99.9% |
| Typical read / mutation mix | 80% / 20% |

Catalog construction may hash bounded metadata and schemas once per tool.
Direct read authorization must remain local and constant-size. Approval lookup
is the only policy-store I/O and occurs only for tools whose reviewed metadata
requires it.

## Decision

### Explicit activation and visibility

`ToolPolicy` is the reusable default-deny `Authorizer`. A `ToolCatalog` may
contain tools that are not yet exported, but only an exact `ToolPolicyRule` in
the `active` state is visible or invocable. A missing rule and the default
`experimental` state are denied. `disabled` is an explicit safe retirement
state.

`Application` detects the policy's structural visibility method and filters
both tool names and handler-free manifests before a transport sees them.
Legacy injected authorizers continue to expose their existing read-only test
and compatibility catalogs; no ambient global policy is introduced.

Unknown and unexported tools return the same stable `invalid_input` result.
Policy audit may distinguish the known denied object inside the protected sink,
but the caller cannot distinguish its existence from the response.

### Exact reviewed contract and independent effects review

`tool_policy_fingerprint()` hashes canonical metadata plus input and output
schemas. It therefore binds name, description, discovery metadata, required
scopes, effect, approval, idempotency, and both schemas. Mapping order does not
change the digest.

An active rule must match the catalog snapshot before the application can
serve. Write and external-effect tools additionally require a `ToolReview`
whose author and reviewer differ and whose reviewed fingerprint exactly equals
the active rule. Changing a schema, description, scope, effect, or approval
requirement invalidates the prior review. A definition is associated with its
catalog snapshot by identity, so replacing its metadata after construction
cannot borrow another tool's active policy.

External effects always require per-call approval. Write and external-effect
metadata always require idempotency. These invariants fail during catalog or
policy construction, before a listener binds.

### Scope intersection

For one active tool, executable authority is:

```text
verified caller scopes ∩ server scope ceiling ∩ tool rule scope ceiling
```

Every scope declared in the reviewed `ToolMetadata.required_scopes` must be in
that intersection. An extra caller scope cannot broaden the server or tool
ceiling. A scope missing from any one set denies the call with the same
non-disclosing `invalid_input` result used for other per-tool authorization
denials.

### Exact, expiring approval records

`CallContext.approval_id` is a bounded reference, not authority. For a tool
requiring approval, `ToolPolicy` fetches an immutable `ApprovalRecord` through
the injected `ApprovalStore` and verifies all of:

- approval ID;
- tenant and caller subject;
- tool name and reviewed tool fingerprint;
- canonical arguments fingerprint;
- combined action fingerprint over every preceding field;
- expiry against the injected wall clock;
- one-time or reusable use policy.

One-time records are accepted only after `ApprovalStore.consume()` atomically
matches the approval ID and action fingerprint and marks the record consumed.
Concurrent or repeated consumption returns false and the runtime responds with
`approval_required`. Reusable records may repeat only for the same exact
action before expiry. The runtime never converts `confirm=true`, a model
message, description, or MCP metadata into approval.

An approval store is required at policy construction when any active tool
requires approval. Store read or consume failure returns `unavailable` and the
handler does not run. The runtime does not fail open or silently convert a
one-time record to reusable behavior.

### Idempotency ownership and crash recovery

Every write and external effect requires a bounded `Idempotency-Key` in the
verified request context. `GatewayJWTContextProvider` accepts that request
control only after peer and bearer-token authentication and passes it unchanged
through `CallContext` to the handler. The policy records only its SHA-256 hash.

The product backing service remains authoritative for idempotency records,
payload binding, in-progress state, and the stored original result. The runtime
does not add an in-memory or second durable idempotency store. Handlers pass the
same key and verified tenant to their backing operation. Concurrent duplicates
therefore return the authoritative first result or that service's documented
in-progress state without repeating the effect.

If the runtime crashes after the backing service commits but before the MCP
reply, retrying the same key reaches the backing service again and recovers its
stored result. This is at-least-once handler delivery plus an idempotent
authoritative consumer, not exactly-once transport delivery. A backing service
that does not implement this contract cannot host a write or external-effect
tool safely.

### Payload-free append-only decisions

Every policy allow or denial appends a frozen `ToolPolicyAuditEvent` through an
explicit `ToolPolicyAuditSink`. The event contains request and run IDs, tenant,
hashed subject, tool name and reviewed fingerprint, effect, verified scopes,
approval ID, hashed idempotency key, decision, and timestamp. It contains no
arguments, results, raw subject, raw idempotency key, credentials, exception
message, or stack trace.

Approval backend faults append a `policy_backend_unavailable` decision when the
audit sink is available. Audit append failure prevents an otherwise allowed
call with `unavailable`. If the call is already denied, append failure preserves
the stable denial code; the handler remains blocked and an audit outage cannot
disclose catalog membership. General application telemetry remains best effort
and payload-free as decided by ADR-0006. A production audit adapter must enqueue
append-only evidence within its bounded local contract and alert on append
failure; issue #32 owns durable export, retention, and gap alerting.

### ADK ownership remains unchanged

The optional ADK bridge continues to delegate descriptor, validation,
approval-pending, tenant-lane, redaction, and result behavior to the exact ADK
release. This policy does not reinterpret ADK approval results or execute ADK
tool bodies. `approval_id` is not promoted into ADK authority metadata.

## Failure behavior

| Condition | Result | Handler/effect behavior |
|---|---|---|
| Missing, experimental, disabled, or scope-denied tool | `invalid_input` | Handler not called |
| Active rule differs from reviewed contract | Construction fails | Listener never binds |
| Mutating tool lacks independent review | Construction fails | Listener never binds |
| External effect says approval is optional | Metadata construction fails | Tool cannot register |
| Write or external effect lacks idempotency key | `conflict` | Handler not called |
| Approval missing, unknown, expired, mismatched, or consumed | `approval_required` | Handler not called |
| Approval fetch or atomic consume fails | `unavailable` | Handler not called |
| Audit append fails for an otherwise allowed call | `unavailable` | Handler not called |
| Audit append fails while recording a denial | Original stable denial code | Handler not called |
| Duplicate backing mutation with same key and payload | Original backing result | Backing effect occurs once |
| Same key reused for different backing payload | Backing service conflict | No second effect |
| Runtime crashes after backing commit | Retry same key | Backing service returns prior result |

Authorization and approval denials use stable expected codes and are not
reported as unknown internal failures. Exception details and protected policy
values never enter the caller response.

## Alternatives considered

- Treat tool metadata as self-authorizing: rejected because a new or changed
  tool could grant itself scopes or weaken effect policy.
- Treat `confirm=true` as approval: rejected because model-controlled input is
  not a user or reviewer capability.
- Keep idempotency results in runtime memory: rejected because replicas and
  restarts would disagree and a crash after the business commit would remain
  ambiguous.
- Add a runtime database for idempotency: rejected because the product backing
  transaction is the only authoritative commit boundary; a second store adds a
  distributed transaction without solving the crash window.
- Reimplement ADK approvals in core: rejected because it would create two
  policy authorities and incompatible pending-result behavior.
- Expose forbidden for known denied tools and not-found for unknown tools:
  rejected because it discloses private catalog membership.

## Consequences, rollout, and rollback

Startup cost is O(number of tools) canonical hashing within the existing
128-tool and schema bounds. Direct per-call work is bounded set intersection,
small hashes for subject and idempotency identity, and one synchronous audit
append. Approval-required calls add the configured store fetch and optional
atomic consume inside the caller deadline. No queue, database, sidecar,
Kubernetes resource, credential, or network route is added by this library.

Rollout is additive for servers that compose `ToolPolicy`; existing read-only
compatibility fixtures retain their injected authorizers. Production servers
must provide active reviewed rules, an append-only audit adapter, and an
approval store where needed. Gateway configuration must forward the standard
`Idempotency-Key` and optional `X-Tesserix-Approval-Id` headers without making
either one identity authority.

Rollback is one dependency-lock reversion together with removal of the new
policy composition from the consuming server. It removes policy enforcement
and therefore is not a safe production response to a denial; traffic should
instead remain on the prior known-good server version and reviewed rules. No
data migration or compensation is introduced. Approval and product
idempotency records remain owned by their existing stores.

## Verification

- table-driven role, scope, effect, approval, and tenant boundary tests;
- unknown versus experimental listing and invocation equivalence;
- exact review digest and runtime metadata-replacement negative tests;
- missing, mismatched, expired, reusable, one-time, and replayed approvals;
- approval fetch, consume, clock, and audit fail-closed paths;
- concurrent duplicate calls through a fake authoritative idempotent backing
  API, proving one effect and the original result;
- gateway propagation bounds and MCP `_meta` non-authority tests;
- strict typing, lint, architecture, threat-model, package, and compatibility
  gates.
