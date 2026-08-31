from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import signal
import sys
import time
from collections.abc import Mapping
from threading import Lock
from typing import Annotated, Any, Literal, TextIO

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
from tesserix_mcp_runtime.observability import (
    RuntimeLimit,
    RuntimeLogEvent,
    RuntimeObservability,
    RuntimeOperation,
    RuntimeOutcome,
    RuntimeSpan,
    RuntimeSpanName,
    RuntimeSpanSpec,
)

BoundedText = Annotated[str, Field(max_length=64)]
ReliabilityRequestText = Annotated[str, Field(max_length=60_000)]
ReliabilityResponseBytes = Annotated[int, Field(ge=1, le=500_000)]
ReliabilityResponseChunk = Annotated[str, Field(max_length=62_500)]
ReliabilityResponseChunks = Annotated[
    tuple[ReliabilityResponseChunk, ...],
    Field(min_length=1, max_length=8),
]
_RELIABILITY_SPAN_PREFIX = "TESSERIX_RELIABILITY_SPAN "


class _ReliabilityLogSpan:
    def __init__(self, *, exporter: ReliabilitySpanLogExporter, captured: bool) -> None:
        self._exporter = exporter
        self._captured = captured
        self._started = time.perf_counter()
        self._outcome = RuntimeOutcome.TOOL_FAILURE
        self._ended = False

    @property
    def trace_id(self) -> str | None:
        return None

    def activate(self) -> None:
        return None

    def set_outcome(self, outcome: RuntimeOutcome) -> None:
        self._outcome = outcome

    def end(self) -> None:
        if self._ended:
            return
        self._ended = True
        if self._captured:
            self._exporter.write_span(
                outcome=self._outcome,
                duration_seconds=max(time.perf_counter() - self._started, 1e-9),
            )


class ReliabilitySpanLogExporter:
    def __init__(self, *, stream: TextIO) -> None:
        self._stream = stream
        self._lock = Lock()

    def record_call(
        self,
        *,
        operation: RuntimeOperation,
        tool_name: str | None,
        outcome: RuntimeOutcome,
        duration_seconds: float,
    ) -> None:
        del operation, tool_name, outcome, duration_seconds

    def change_in_flight(
        self,
        *,
        tool_name: str,
        delta: int,
        server_capacity: int,
        tool_capacity: int,
    ) -> None:
        del tool_name, delta, server_capacity, tool_capacity

    def record_retry(self, *, tool_name: str) -> None:
        del tool_name

    def record_limit(self, *, tool_name: str | None, limit: RuntimeLimit) -> None:
        del tool_name, limit

    def record_dropped(self, *, count: int) -> None:
        del count

    def emit_log(self, event: RuntimeLogEvent) -> None:
        del event

    def start_span(self, spec: RuntimeSpanSpec) -> RuntimeSpan:
        return _ReliabilityLogSpan(
            exporter=self,
            captured=(
                spec.name is RuntimeSpanName.TOOL_EXECUTION
                and spec.tool_name == "reliability_probe"
            ),
        )

    def write_span(self, *, outcome: RuntimeOutcome, duration_seconds: float) -> None:
        encoded = json.dumps(
            {
                "schema_version": 1,
                "name": RuntimeSpanName.TOOL_EXECUTION.value,
                "outcome": outcome.value,
                "duration_seconds": duration_seconds,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        with self._lock:
            self._stream.write(f"{_RELIABILITY_SPAN_PREFIX}{encoded}\n")
            self._stream.flush()


class EchoResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: BoundedText


def echo(text: BoundedText) -> EchoResult:
    """Return the supplied text."""
    return EchoResult(text=text)


def always_fails() -> EchoResult:
    """Return a deterministic tool failure."""
    raise ValueError("expected compatibility failure")


class ReliabilityProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_bytes: int = Field(ge=0, le=60_000)
    response_bytes: int = Field(ge=1, le=500_000)
    chunks: ReliabilityResponseChunks


def reliability_probe(
    request: ReliabilityRequestText,
    response_bytes: ReliabilityResponseBytes,
) -> ReliabilityProbeResult:
    """Return one bounded synthetic response for reliability measurement."""
    request_size = len(request.encode("utf-8"))
    if request_size > 60_000:
        raise ValueError("reliability request exceeds the synthetic byte boundary")
    chunks = tuple(
        "s" * min(62_500, response_bytes - offset) for offset in range(0, response_bytes, 62_500)
    )
    return ReliabilityProbeResult(
        request_bytes=request_size,
        response_bytes=response_bytes,
        chunks=chunks,
    )


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
        if action == "status":
            return "status"
        if action == "wait":
            return "wait"
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
    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        del request
        return CallContext(
            identity=AuthenticatedIdentity(
                tenant="compatibility",
                subject="matrix-client",
                issuer="https://compatibility.invalid",
                scopes=(),
            ),
            request_id=f"compatibility-{secrets.token_hex(16)}",
            run_id="compatibility-matrix",
            cancellation=cancellation,
        )


async def serve(
    port: int,
    *,
    host: str = "127.0.0.1",
    allowed_hosts: tuple[str, ...] = (),
    allowed_origins: tuple[str, ...] = (),
    reliability_spans: bool = False,
) -> None:
    telemetry = NullTelemetry()
    observability = RuntimeObservability(
        server_name="tesserix-mcp-runtime",
        exporter=(ReliabilitySpanLogExporter(stream=sys.stdout) if reliability_spans else None),
    )
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
                callable_tool(
                    reliability_probe,
                    metadata=metadata("reliability_probe", "Reliability probe"),
                ),
            ]
        ),
        authorizer=AllowAllAuthorizer(),
        transport=transport,
        telemetry=telemetry,
        limits=ApplicationLimits(drain_timeout=5.0),
        clock=SystemClock(),
        observability=observability,
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
    parser.add_argument("--reliability-spans", action="store_true")
    arguments = parser.parse_args()
    asyncio.run(
        serve(
            arguments.port,
            host=arguments.host,
            allowed_hosts=tuple(arguments.allowed_host),
            allowed_origins=tuple(arguments.allowed_origin),
            reliability_spans=arguments.reliability_spans,
        )
    )


if __name__ == "__main__":
    main()
