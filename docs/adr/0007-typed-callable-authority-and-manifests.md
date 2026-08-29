# ADR-0007: Typed callable authority and handler-free manifests

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#9](https://github.com/tesserix/tesserix-mcp-runtime/issues/9)

## Context

An MCP tool contract must remain identical across runtime validation, protocol
schema, Registry metadata, and later ADK reuse. Hand-copying JSON Schema at
those boundaries creates silent drift. The official MCP Python SDK already
derives tool schemas and validation from Python annotations and Pydantic; the
runtime needs policy and publication surfaces around that authority, not a
second generator.

ADR-0001 assumes 12 tools per server and reviews at most 128, with 50 sustained
and 200 burst calls per second, 64 KiB requests, 512 KiB responses, less than
15 ms p99 runtime-added latency, startup within 2 seconds, and idle RSS within
128 MiB. This slice adds registration-time work only and no network hop,
datastore, queue, transaction, embedding call, or per-invocation semantic
search. Issue #29 owns production load and capacity evidence.

The runtime supports Python 3.12 through 3.14 and constrains the MCP SDK to
`>=2.1.1,<3`. As ADR-0002 records, MCP SDK 1.34 does not exist; package version,
Python version, and protocol revision are separate compatibility dimensions.

## Decision

### The official SDK is the schema authority

`callable_tool` explicitly adapts one callable. MCP SDK `Tool.from_function`
derives its input model, validation path, and structured output schema from the
same annotations used by Pydantic. The runtime JSON-normalizes the result,
closes the root input object, and applies its schema policy. It does not scan
imports, infer exposure, accept arbitrary decorator signatures, or implement a
parallel annotation-to-schema engine.

Input parsing and output conversion continue through the SDK metadata object so
MCP, in-process, and later Registry-backed paths do not diverge. SDK signature
or result-validation failures are translated at the adapter boundary rather
than leaking dependency-specific errors through the reusable contract.

### Registration is finite and fail closed

Both input and output schemas are validated before catalog construction. The
default cap is 65,536 UTF-8 bytes per schema, depth 16, 128 object or mapping
properties, 128 definitions, 4,096 nodes, 16 union variants, strings of 65,536
characters, and arrays of 1,024 items unless a stricter local policy applies.
Objects are closed, variable-size strings, arrays, and mappings require visible
bounds, and recursive schemas are rejected.

At the reviewed maximum, two schema documents per 128 tools admit at most
16 MiB of raw canonical schema JSON. The node ceiling admits at most 1,048,576
input-plus-output schema nodes across that deliberately adversarial catalog.
Those are safety ceilings rather than expected working-set sizes; the normal
12-tool catalog is expected to be orders of magnitude smaller. Startup and RSS
remain checked against ADR-0001, and issue #29 must measure worst-case catalog
fixtures before GA rather than treating these calculations as performance
claims.

Invalid signatures, JSON, bounds, references, or size fail before readiness
with a stable `ContractViolation` code and path. Case-insensitive normalized
name collisions fail startup and name both definitions.

### Semantic metadata is immutable and non-authoritative

`ToolMetadata` carries the side-effect class, approval and idempotency
requirements, required scopes, and optional `ToolDiscoveryMetadata`. Discovery
adds a summary, when-to-use text, capability tags, rate class, lifecycle, and
examples. These frozen values may be indexed for tenant-filtered semantic
discovery, but they are untrusted routing data, not model instructions or an
authorization decision.

Capability and required-scope lists are capped at 32 values. The default text
policy caps descriptions at 4,096 bytes/512 portable tokens, summaries at
512/128, when-to-use text at 2,048/256, and each example at 1,024/128. At most
eight examples and 4,096 bytes/512 tokens of aggregate example text are
accepted. The deterministic portable counter is a cross-model abuse budget,
not a vendor tokenizer estimate.

Model-controlled schemas may not request tenant, identity, subject, user, role,
scope, credential, secret, or token concepts, including normalized spellings
inside nested models. Authenticated identity remains transport-derived in
`CallContext`; `required_scopes` must be enforced by the injected default-deny
application authorizer immediately before handler execution. Semantic rank, a
Registry match, or a Gateway route never grants authority.

### Manifests contain contracts, never executable code

`ToolCatalog` snapshots one immutable `ToolManifest` per definition. It stores
canonical input and output schema JSON, normalized name, public metadata, and
SHA-256 input, output, and combined contract fingerprints. Accessors return
defensive decoded copies. `export_metadata()` emits JSON-safe values without a
handler, function, closure, credential, identity, or payload.

Fingerprinting uses sorted-key, compact, Unicode-preserving canonical JSON, so
mapping order and Python hash seed do not change the result. Registry signing,
publication, tenant filtering, activation, and Gateway pickup remain later
issues; this decision supplies their bounded compiler input only.

### Compatibility is directional

`classify_schema_change` returns identical, non-breaking, or breaking. For
inputs, the current schema must be a superset of the previous accepted values.
For outputs, the current schema must be a subset of values the previous client
contract allowed. The classifier understands the bounded supported subset,
including local definitions, unions, enum/const values, numeric and collection
bounds, closed objects, and additional-property schemas. Unknown constraints
must remain exactly equal. Malformed, recursive, exhausted, or unsupported
comparisons fail closed as breaking.

This classification is publication evidence, not a protocol negotiation or
automatic rollout mechanism. A breaking change needs a new externally managed
version and coexistence plan before route activation.

## Failure behavior

| Dependency or failure | Behavior |
|---|---|
| MCP SDK cannot resolve a callable signature | Reject registration as `invalid_callable_schema` |
| Structured output is missing or invalid | Reject registration or normalize the invocation failure at the adapter boundary |
| Schema is unbounded, recursive, malformed, or oversized | Reject registration with a stable code and exact path |
| Metadata exceeds a byte, token, or cardinality budget | Reject registration before catalog construction |
| A schema requests an identity-like field | Reject registration as `forbidden_identity_field` |
| Two names collide after case folding | Reject the catalog and identify both definitions |
| Fingerprint input is not finite, canonicalizable JSON | Reject manifest construction; never hash an ambiguous representation |
| Registry, semantic index, or Gateway is unavailable | Runtime authoring still works locally; publication or activation does not occur |
| Compatibility comparison cannot prove safety | Classify the change as breaking |

There is no distributed write in this slice and therefore no transaction,
outbox, retry, compensation, or idempotency key to add. Future publication must
bind the fingerprint to an immutable Registry version and use its own durable,
idempotent workflow. A process crash during local registration exposes no
listener and commits no external state.

## Alternatives considered

- Maintain handwritten JSON Schema beside Python types: rejected because MCP,
  Registry, ADK, and runtime validation would drift.
- Generate schemas in a new runtime-specific reflection layer: rejected because
  it would duplicate MCP SDK and Pydantic behavior and compatibility work.
- Use Pydantic output but a separate MCP input schema: rejected because one
  callable would have two validation authorities.
- Auto-expose decorated or imported functions: rejected because import
  side-effects would become an accidental security and publication boundary.
- Serialize handlers or closures in Registry manifests: rejected because code,
  credentials, and process state do not belong in discovery metadata.
- Embed and rank descriptions inside each server: rejected because semantic
  search is Registry-owned, tenant-filtered, and independently scalable.
- Accept arbitrary JSON Schema and defer failures to clients: rejected because
  recursive and unbounded inputs create startup, memory, and interoperability
  risk.

## Consequences, rollout, and rollback

The MCP SDK remains an adapter-only dependency and its major version is capped.
Schema derivation and manifest creation add startup CPU and bounded memory, but
no per-call discovery hop. Canonical snapshots make future publication and
drift checks deterministic at the cost of retaining schema JSON per catalog
entry.

This is an additive pre-release API. Rollout converts one explicitly registered
tool at a time, compares its golden MCP/Pydantic schema and fingerprints, then
uses the handler-free export as future Registry compiler input. It does not
publish a package, change a route, activate a Gateway, or migrate data by
itself.

Rollback restores that tool's prior explicit `ToolDefinition` or reverts this
package commit. Existing Registry and Gateway state is untouched because this
slice performs no external mutation. Once later publication exists, rollback
must reactivate the previous immutable Registry version by fingerprint rather
than rewriting a released contract in place.
