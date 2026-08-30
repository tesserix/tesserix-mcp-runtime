from __future__ import annotations

import argparse
import asyncio
import signal
from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    Cancellation,
    IdempotencyRequirement,
    JsonValue,
    ScrubbedError,
    SystemClock,
    ToolCatalog,
    ToolDefinition,
    ToolEffect,
    ToolHandler,
    ToolMetadata,
)
from tesserix_mcp_runtime.adapters.mcp_authoring import callable_tool
from tesserix_mcp_runtime.adapters.streamable_http import (
    HTTPRequestMetadata,
    ProtocolTelemetryEvent,
    StreamableHTTPConfig,
    StreamableHTTPLimits,
    StreamableHTTPTransport,
)
from tesserix_mcp_runtime.application import Application, ApplicationLimits

BoundedText = Annotated[str, Field(max_length=64)]


class EchoResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: BoundedText


def echo(text: BoundedText) -> EchoResult:
    """Return the supplied text."""
    return EchoResult(text=text)


def always_fails() -> EchoResult:
    """Return a deterministic tool failure."""
    raise ValueError("expected compatibility failure")


def metadata(name: str, title: str) -> ToolMetadata:
    return ToolMetadata(
        name=name,
        title=title,
        description=f"Compatibility fixture for {title}.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=(),
    )


CancellationAction = Literal["status", "wait"]


class CancellationProbeDefinition:
    def __init__(self) -> None:
        self._metadata = metadata("cancellation_probe", "Cancellation probe")
        self._active = 0
        self._observed = 0

    @property
    def metadata(self) -> ToolMetadata:
        return self._metadata

    @property
    def input_schema(self) -> Mapping[str, JsonValue]:
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["status", "wait"]},
            },
            "required": ["action"],
            "additionalProperties": False,
        }

    @property
    def output_schema(self) -> Mapping[str, JsonValue]:
        return {
            "type": "object",
            "properties": {
                "active": {"type": "integer", "minimum": 0},
                "observed": {"type": "integer", "minimum": 0},
            },
            "required": ["active", "observed"],
            "additionalProperties": False,
        }

    @property
    def handler(self) -> ToolHandler[CancellationAction, dict[str, JsonValue]]:
        return self

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> CancellationAction:
        if set(arguments) != {"action"}:
            raise ValueError("cancellation probe requires one action")
        action = arguments["action"]
        if action == "status" or action == "wait":
            return action
        raise ValueError("cancellation probe action is invalid")

    async def __call__(
        self,
        input_model: CancellationAction,
        *,
        context: CallContext,
    ) -> dict[str, JsonValue]:
        if input_model == "status":
            return self._status()
        self._active += 1
        try:
            await context.cancellation.wait()
            self._observed += 1
            return self._status()
        finally:
            self._active -= 1

    def serialize_output(self, output_model: dict[str, JsonValue]) -> JsonValue:
        return output_model

    def _status(self) -> dict[str, JsonValue]:
        return {"active": self._active, "observed": self._observed}


class AllowAllAuthorizer:
    async def authorize(
        self,
        *,
        tool: ToolDefinition[Any, Any],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context


class NullTelemetry:
    def emit(self, event: ScrubbedError | ProtocolTelemetryEvent) -> None:
        del event


class CompatibilityContextProvider:
    def __init__(self) -> None:
        self._requests = 0

    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        del request
        self._requests += 1
        return CallContext(
            identity=AuthenticatedIdentity(
                tenant="compatibility",
                subject="matrix-client",
                issuer="https://compatibility.invalid",
                scopes=(),
            ),
            request_id=f"compatibility-{self._requests}",
            run_id="compatibility-matrix",
            cancellation=cancellation,
        )


async def serve(
    port: int,
    *,
    host: str = "127.0.0.1",
    allowed_hosts: tuple[str, ...] = (),
    allowed_origins: tuple[str, ...] = (),
) -> None:
    telemetry = NullTelemetry()
    transport = StreamableHTTPTransport(
        config=StreamableHTTPConfig(
            host=host,
            port=port,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
        ),
        limits=StreamableHTTPLimits(max_tools=4, tool_page_size=2, max_tool_pages=2),
        context_provider=CompatibilityContextProvider(),
        telemetry=telemetry,
    )
    application = Application(
        catalog=ToolCatalog(
            [
                callable_tool(echo, metadata=metadata("echo", "Echo")),
                CancellationProbeDefinition(),
                callable_tool(
                    always_fails,
                    metadata=metadata("always_fails", "Always fails"),
                ),
            ]
        ),
        authorizer=AllowAllAuthorizer(),
        transport=transport,
        telemetry=telemetry,
        limits=ApplicationLimits(drain_timeout=5.0),
        clock=SystemClock(),
    )
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for received_signal in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(received_signal, stopping.set)

    await application.start()
    try:
        await stopping.wait()
    finally:
        await application.drain()
        await application.stop()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--allowed-host", action="append", default=[])
    parser.add_argument("--allowed-origin", action="append", default=[])
    arguments = parser.parse_args()
    asyncio.run(
        serve(
            arguments.port,
            host=arguments.host,
            allowed_hosts=tuple(arguments.allowed_host),
            allowed_origins=tuple(arguments.allowed_origin),
        )
    )


if __name__ == "__main__":
    main()
