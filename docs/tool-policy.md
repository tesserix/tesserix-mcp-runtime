# Tool policy, approvals, and idempotency

`ToolPolicy` is the default-deny authorizer for non-ADK runtime tools. It
combines one verified call context with server scope ceilings, exact reviewed
tool rules, per-call approval records, and payload-free audit decisions.

## Compose an active policy

Build the catalog first, then review its immutable manifest fingerprint. This
example activates a read tool; mutating tools also need a `ToolReview` bound to
the same fingerprint.

```python
from tesserix_mcp_runtime import (
    Application,
    ToolPolicy,
    ToolPolicyRule,
    ToolPolicyState,
    tool_policy_fingerprint,
)

manifest = catalog.manifests[0]
rule = ToolPolicyRule(
    tool_name=manifest.metadata.name,
    reviewed_fingerprint=tool_policy_fingerprint(manifest),
    allowed_scopes=("orders:read",),
    state=ToolPolicyState.ACTIVE,
)

policy = ToolPolicy(
    catalog=catalog,
    server_scopes=("orders:read", "orders:write"),
    rules=(rule,),
    audit_sink=audit_sink,
)

application = Application(
    catalog=catalog,
    authorizer=policy,
    transport=transport,
    telemetry=telemetry,
    limits=limits,
    clock=clock,
)
```

Omitting `state` leaves a rule `experimental`, so it is neither listed nor
invocable. A catalog tool with no rule is also denied. Use `disabled` for an
explicitly retired rule.

For a write or external effect, record an independent review:

```python
from tesserix_mcp_runtime import ToolReview

fingerprint = tool_policy_fingerprint(manifest)
rule = ToolPolicyRule(
    tool_name=manifest.metadata.name,
    reviewed_fingerprint=fingerprint,
    allowed_scopes=("orders:write",),
    state=ToolPolicyState.ACTIVE,
    review=ToolReview(
        review_id="review-2026-08-orders",
        author_subject="publisher-subject",
        reviewer_subject="security-reviewer-subject",
        reviewed_fingerprint=fingerprint,
    ),
)
```

The author and reviewer must differ. Any metadata or schema change produces a
new fingerprint and requires a new review.

## Scope decision

The tool runs only when all `metadata.required_scopes` exist in the
intersection of verified caller scopes, `server_scopes`, and the rule's
`allowed_scopes`. Never construct caller scopes from arguments, descriptions,
MCP `_meta`, paths, or forwarded identity headers.

The runtime conceals catalog membership: unknown, unruled, experimental,
disabled, and scope-denied tools all return `invalid_input`. Protected audit
events retain the precise internal decision.

## Approval store contract

When metadata says `approval=required`, supply an object implementing
`ApprovalStore`:

```python
class ProductApprovalStore:
    async def fetch(self, *, approval_id: str) -> ApprovalRecord | None: ...

    async def consume(
        self,
        *,
        approval_id: str,
        action_fingerprint: str,
    ) -> bool: ...  # atomic compare-and-consume for one-time records
```

Approval issuers can construct the exact record with
`ApprovalRecord.for_action()`. It binds tenant, subject, manifest fingerprint,
tool name, and canonical arguments. `ONE_TIME` requires atomic consume;
`REUSABLE` skips consume but still enforces every binding and expiry.

`X-Tesserix-Approval-Id` is only a bounded lookup reference. A missing,
unknown, expired, mismatched, or already-consumed record returns
`approval_required`. Store failure returns `unavailable`. A `confirm` argument
never substitutes for a record.

## Idempotent mutation contract

Every write and external effect requires `Idempotency-Key`. The authenticated
gateway context provider copies the bounded value into
`CallContext.idempotency_key`; the handler passes the same key and verified
tenant to its backing API.

```python
async def __call__(self, input_model: UpdateInput, *, context: CallContext) -> UpdateOutput:
    if context.idempotency_key is None:
        raise RuntimeFailure(ErrorCode.CONFLICT)
    return await self._orders.update(
        tenant=context.tenant,
        value=input_model.value,
        idempotency_key=context.idempotency_key,
    )
```

The backing API must atomically bind `(tenant, operation, key)` to the payload
digest and original result. Concurrent duplicates return that result or its
documented in-progress state. A different payload with the same key conflicts.
This store belongs beside the business transaction; runtime memory is not a
durable idempotency authority.

## Audit contract

`ToolPolicyAuditSink.append()` is called with one frozen `ToolPolicyAuditEvent`
for every allowed or denied policy transition. Safe fields are:

- request and run IDs;
- tenant and hashed subject;
- tool name, exact policy fingerprint, and effect;
- verified scopes;
- approval ID and hashed idempotency key;
- decision and wall-clock timestamp.

Arguments, results, raw subject, raw idempotency key, credentials, exception
messages, and stack traces are excluded by construction. An audit append
failure prevents an otherwise allowed call with `unavailable`. If a call is
already denied, append failure preserves its stable denial code so a sink
outage cannot disclose whether the tool exists; the handler still never runs.
The production sink must alert on failed appends and evidence gaps.

## Gateway headers and MCP metadata

After direct-peer and JWT verification, `GatewayJWTContextProvider` accepts at
most one of each:

| Header | Limit | Meaning |
|---|---:|---|
| `Idempotency-Key` | 512 characters | Mutation replay identity, not caller identity |
| `X-Tesserix-Approval-Id` | 256 characters | Approval lookup reference, not approval itself |

Duplicate, empty, padded, control-character, or oversized values fail before a
tool call. Matching `tesserix/runtime/*` or `tesserix/adk/*` MCP metadata is
compatibility attribution only; a mismatch is rejected and metadata never
becomes authority.

## ADK-backed servers

Do not wrap ADK tools in `ToolPolicy`. The ADK bridge delegates validation,
approval-pending results, tenant lanes, redaction, and result semantics to the
attested ADK release. Core policy applies to runtime-owned non-ADK tool
definitions only.

## Failure checklist

- Policy or approval dependency times out: fail closed; do not invoke handler.
- Duplicate delivery: pass the same key; authoritative backing effect occurs
  once and returns the original result.
- Runtime crashes after backing commit: retry the same key to recover the
  backing result.
- Approval consume races: exactly one atomic consume succeeds.
- Tool metadata or schema changes: fingerprint differs; activation fails until
  independently reviewed.
- Audit sink fails for an otherwise allowed call: return `unavailable`; never
  silently omit an allowed decision.
- Audit sink fails while recording a denial: preserve the denial code and do
  not invoke the handler, keeping unknown and unexported tools
  indistinguishable.
