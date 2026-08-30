from __future__ import annotations

from collections.abc import Mapping

from tesserix_mcp_testkit import (
    CONFORMANCE_TOOL_NAME,
    REQUIRED_CAPABILITIES,
    ConformanceCase,
    ConformanceObservation,
    FakeIdentityFactory,
)

from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    ApprovalRequirement,
    CallContext,
    IdempotencyRequirement,
    JsonValue,
    ScrubbedError,
    SystemClock,
    ToolCatalog,
    ToolDefinition,
    ToolEffect,
    ToolMetadata,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport


class EchoTool:
    metadata = ToolMetadata(
        name=CONFORMANCE_TOOL_NAME,
        title="Conformance echo",
        description="Return one bounded synthetic value.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("conformance:invoke",),
    )
    input_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {"value": {"type": "string", "maxLength": 2}},
        "required": ["value"],
        "additionalProperties": False,
    }
    output_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {"echo": {"type": "string", "maxLength": 2}},
        "required": ["echo"],
        "additionalProperties": False,
    }

    async def handler(self, input_model: str, *, context: CallContext) -> dict[str, JsonValue]:
        del context
        return {"echo": input_model}

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> str:
        value = arguments.get("value")
        if not isinstance(value, str) or value != "ok":
            raise ValueError("value must be the conformance sentinel")
        return value

    def serialize_output(self, output_model: dict[str, JsonValue]) -> JsonValue:
        return output_model


class AllowAll:
    async def authorize(
        self,
        *,
        tool: ToolDefinition[object, object],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context


class IgnoreTelemetry:
    def emit(self, event: ScrubbedError) -> None:
        del event


class ExternalServerTarget:
    capabilities = REQUIRED_CAPABILITIES

    async def observe(self, case: ConformanceCase) -> ConformanceObservation:
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([EchoTool()]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=IgnoreTelemetry(),
            limits=ApplicationLimits(drain_timeout=1.0),
            clock=SystemClock(),
        )
        context = FakeIdentityFactory(default_scopes=("conformance:invoke",)).context()
        await application.start()
        try:
            if case.id == "discovery.tools":
                return ConformanceObservation(tool_names=await transport.list_tools())
            result = await transport.invoke(
                CONFORMANCE_TOOL_NAME,
                {"value": "ok"},
                context=context,
            )
            return ConformanceObservation(
                value=result.value, error_code=result.error.code if result.error else None
            )
        finally:
            await application.drain()
            await application.stop()
