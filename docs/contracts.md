# Runtime contracts

The package facade, `tesserix_mcp_runtime`, is the supported import path for
runtime contracts. Protocol-specific adapters may import the official MCP SDK,
but tool implementations and the contract modules do not depend on transport
objects.

## Define and register a tool

A tool implements the structural `ToolDefinition[InputT, OutputT]` protocol.
Its handler receives a validated input model and a trusted `CallContext`; it
never receives raw transport state.

```python
from collections.abc import Mapping
from dataclasses import dataclass

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    CallContext,
    ErrorCode,
    IdempotencyRequirement,
    JsonValue,
    RuntimeFailure,
    ToolCatalog,
    ToolEffect,
    ToolMetadata,
)


@dataclass(frozen=True, slots=True)
class EchoInput:
    text: str


@dataclass(frozen=True, slots=True)
class EchoOutput:
    text: str


class EchoHandler:
    async def __call__(
        self,
        input_model: EchoInput,
        *,
        context: CallContext,
    ) -> EchoOutput:
        if "example:read" not in context.scopes:
            raise RuntimeFailure(ErrorCode.FORBIDDEN)
        return EchoOutput(text=input_model.text)


@dataclass(frozen=True, slots=True)
class EchoTool:
    metadata = ToolMetadata(
        name="example.echo",
        title="Echo text",
        description="Return bounded synthetic text.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("example:read",),
    )
    input_schema = {
        "type": "object",
        "properties": {"text": {"type": "string", "maxLength": 128}},
        "required": ["text"],
        "additionalProperties": False,
    }
    output_schema = input_schema
    handler = EchoHandler()

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> EchoInput:
        text = arguments.get("text")
        if set(arguments) != {"text"} or not isinstance(text, str) or len(text) > 128:
            raise RuntimeFailure(ErrorCode.INVALID_INPUT)
        return EchoInput(text=text)

    def serialize_output(self, output_model: EchoOutput) -> JsonValue:
        return {"text": output_model.text}


catalog = ToolCatalog([EchoTool()])
```

`ToolCatalog` preserves registration order and rejects non-structural
definitions, duplicate exposed names, invalid schemas, and schemas outside the
reviewed policy before traffic starts. `ToolMetadata` is immutable. Write and
external-effect tools must declare idempotency as required; external effects
must also require per-call approval. Approval metadata is always explicit.

Issue #9 owns the typed-callable registration API and official SDK/Pydantic
schema normalization. Until that lands, the contract accepts this closed
schema subset:

| Type | Required safety rule | Supported validation keywords |
|---|---|---|
| `object` | root and nested objects use `additionalProperties: false` | `properties`, `required`, `minProperties`, `maxProperties` |
| `string` | integer `maxLength` no greater than the policy limit | `minLength`, `maxLength`, `format` |
| `array` | integer `maxItems` and one bounded `items` schema | `minItems`, `maxItems`, `uniqueItems` |
| `integer`, `number` | explicit type | numeric minimum, maximum, exclusivity, and multiple keywords |
| `boolean`, `null` | explicit type | no type-specific keywords |

Common annotation and value keywords are `title`, `description`, `$comment`,
`default`, `examples`, `enum`, and `const`; root schemas may also contain
`$id` and `$schema`. Schema composition, references, recursive schemas, and
unknown keywords fail with `unsupported_schema_keyword` rather than bypassing
the policy.

`SchemaPolicy` defaults to 65,536 serialized bytes, depth 16, 128 properties
per object, string length 65,536, and 1,024 array items. A stricter policy may
be passed to `ToolCatalog`.

## Construct trusted call context

Only an authenticated transport adapter constructs `AuthenticatedIdentity`
and `CallContext`. Tenant, subject, issuer, scopes, request ID, run ID, trace
state, deadline, cancellation, idempotency key, and approval reference must
never be copied from model-controlled tool arguments. Use the
[tool policy guide](tool-policy.md) to enforce reviewed metadata at invocation.

Both objects are frozen. Deadlines are finite, non-negative monotonic
timestamps. `TraceContext` accepts W3C traceparent version 00 with non-zero IDs
and a bounded, unique-member tracestate. Cancellation is an adapter-neutral
protocol with a current-state property and an awaitable signal.

## Return stable failures

Adapters expose only `ErrorResponse.to_dict()` or an `InvocationResult` built
with `InvocationResult.success` or `InvocationResult.failure`. Clients branch
on `code`, never exception text or message text.

| Code | Retryability |
|---|---|
| `invalid_input`, `unauthenticated`, `forbidden` | `never` |
| `approval_required`, `conflict`, `cancelled` | `never` |
| `timeout`, `unavailable` | `safe_or_idempotent` |
| `internal_failure` | `never` |

`map_exception` maps known `RuntimeFailure`, timeout, and cancellation cases.
All other exceptions become `internal_failure`. The paired audit value contains
only code, a bounded exception type name, and request ID. It never contains an
exception message, stack trace, arguments, tool payload, tenant payload, or
credential. `TerminalEmitter` accepts the first completion or cancellation
result exactly once.

## Run lifecycle hooks

`LifecycleController.start()` runs components in registration order. On a
startup failure it stops the failing component and every component already
started in reverse order, then enters `stopped`. `drain(deadline=...)` and
`stop()` run started components in reverse order. A failing drain or stop hook
does not prevent remaining hooks from running; the controller raises one
`LifecycleFailure` with the first failed component and total failure count.

Transitions are serialized. Repeated drain and stop calls are safe; repeated
start or drain-before-ready raises `LifecycleTransitionError`. Call `stop()`
even when drain reports a failure.

## Reuse adapter conformance

Implement `ConformanceAdapter`, then run the same case against an in-process
adapter, the official MCP SDK adapter, or a future ADK bridge:

```python
from tesserix_mcp_runtime.conformance import (
    ConformanceCase,
    assert_adapter_conforms,
)

await assert_adapter_conforms(
    adapter,
    ConformanceCase(
        tool_name="example.echo",
        valid_arguments={"text": "hello"},
        expected_value={"text": "hello"},
        invalid_arguments={"text": 42},
    ),
)
```

The suite verifies exactly one listing, successful typed invocation, stable
invalid-input handling, and stable unknown-tool handling without a real
network.
