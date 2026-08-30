from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, Never

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    ErrorCode,
    IdempotencyRequirement,
    InvocationResult,
    JsonValue,
    ScrubbedError,
    SecretRedactor,
    SecretValue,
    SystemClock,
    ToolCatalog,
    ToolDefinition,
    ToolEffect,
    ToolMetadata,
    TraceContext,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport
from tesserix_mcp_runtime.adapters.opentelemetry import OpenTelemetryRuntimeExporter
from tesserix_mcp_runtime.observability import (
    RuntimeExporter,
    RuntimeLimit,
    RuntimeLogEvent,
    RuntimeObservability,
    RuntimeOperation,
    RuntimeOutcome,
    RuntimeSpan,
    RuntimeSpanSpec,
)

CANARY = "SyntheticObservationCanary5Pk7"


@dataclass(frozen=True, slots=True)
class EchoInput:
    text: str


class EchoTool:
    metadata = ToolMetadata(
        name="orders.echo",
        title="Echo",
        description="Return bounded synthetic text.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("orders:read",),
    )
    input_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {"text": {"type": "string", "maxLength": 64}},
        "required": ["text"],
        "additionalProperties": False,
    }
    output_schema = input_schema

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> EchoInput:
        text = arguments.get("text")
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        return EchoInput(text=text)

    async def handler(self, input_model: EchoInput, *, context: CallContext) -> EchoInput:
        del context
        return input_model

    def serialize_output(self, output_model: EchoInput) -> JsonValue:
        return {"text": output_model.text}


class CancelledTool(EchoTool):
    async def handler(self, input_model: EchoInput, *, context: CallContext) -> EchoInput:
        del input_model, context
        raise asyncio.CancelledError


class AllowAll:
    async def authorize(
        self,
        *,
        tool: ToolDefinition[Any, Any],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context


class IgnoreTelemetry:
    def emit(self, event: ScrubbedError) -> None:
        del event


class ExplodingRuntimeExporter(RuntimeExporter):
    def _fail(self) -> Never:
        raise RuntimeError(CANARY)

    def record_call(
        self,
        *,
        operation: RuntimeOperation,
        tool_name: str | None,
        outcome: RuntimeOutcome,
        duration_seconds: float,
    ) -> None:
        del operation, tool_name, outcome, duration_seconds
        self._fail()

    def change_in_flight(
        self,
        *,
        tool_name: str,
        delta: int,
        server_capacity: int,
        tool_capacity: int,
    ) -> None:
        del tool_name, delta, server_capacity, tool_capacity
        self._fail()

    def record_retry(self, *, tool_name: str) -> None:
        del tool_name
        self._fail()

    def record_limit(self, *, tool_name: str | None, limit: RuntimeLimit) -> None:
        del tool_name, limit
        self._fail()

    def record_dropped(self, *, count: int) -> None:
        del count
        self._fail()

    def emit_log(self, event: RuntimeLogEvent) -> None:
        del event
        self._fail()

    def start_span(self, spec: RuntimeSpanSpec) -> RuntimeSpan:
        del spec
        self._fail()


def context() -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant="tenant-example",
            subject="subject-example",
            issuer="https://identity.example.invalid",
            scopes=("orders:read",),
        ),
        request_id="request-example",
        run_id="run-example",
        trace_context=TraceContext(
            traceparent="00-11111111111111111111111111111111-2222222222222222-01"
        ),
    )


def test_successful_call_emits_one_linked_request_authorization_and_execution_trace() -> None:
    async def exercise() -> None:
        spans = InMemorySpanExporter()
        tracer_provider = TracerProvider()
        tracer_provider.add_span_processor(SimpleSpanProcessor(spans))
        metric_reader = InMemoryMetricReader()
        meter_provider = MeterProvider(metric_readers=(metric_reader,))
        exporter = OpenTelemetryRuntimeExporter(
            server_name="orders-mcp",
            tracer=tracer_provider.get_tracer("test"),
            meter=meter_provider.get_meter("test"),
        )
        observability = RuntimeObservability(server_name="orders-mcp", exporter=exporter)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([EchoTool()]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=IgnoreTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=SystemClock(),
            observability=observability,
        )
        await application.start()

        result = await transport.invoke(
            "orders.echo",
            {"text": "hello"},
            context=context(),
        )

        assert result == InvocationResult.success({"text": "hello"})
        finished = spans.get_finished_spans()
        assert [span.name for span in finished] == [
            "mcp.tool.authorization",
            "mcp.tool.execution",
            "mcp.server.request",
        ]
        request_span = finished[2]
        assert request_span.parent is not None
        assert request_span.parent.span_id == int("2" * 16, 16)
        assert all(span.context is not None for span in finished)
        assert {span.context.trace_id for span in finished if span.context is not None} == {
            int("1" * 32, 16)
        }
        assert finished[0].parent == request_span.context
        assert finished[1].parent == request_span.context
        local_metrics = observability.render_prometheus()
        assert 'mcp_server_in_flight{server="orders-mcp"} 0' in local_metrics
        assert 'mcp_server_concurrency_limit{server="orders-mcp"} 64' in local_metrics
        assert 'mcp_tool_in_flight{server="orders-mcp",tool="orders.echo"} 0' in local_metrics
        assert (
            'mcp_tool_concurrency_limit{server="orders-mcp",tool="orders.echo"} 32' in local_metrics
        )

        await application.drain()
        await application.stop()
        tracer_provider.shutdown()
        meter_provider.shutdown()

    asyncio.run(exercise())


def test_cancellation_marks_execution_and_request_spans_without_swallowing_it() -> None:
    async def exercise() -> None:
        spans = InMemorySpanExporter()
        tracer_provider = TracerProvider()
        tracer_provider.add_span_processor(SimpleSpanProcessor(spans))
        metric_reader = InMemoryMetricReader()
        meter_provider = MeterProvider(metric_readers=(metric_reader,))
        exporter = OpenTelemetryRuntimeExporter(
            server_name="orders-mcp",
            tracer=tracer_provider.get_tracer("test"),
            meter=meter_provider.get_meter("test"),
        )
        observability = RuntimeObservability(server_name="orders-mcp", exporter=exporter)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([CancelledTool()]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=IgnoreTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=SystemClock(),
            observability=observability,
        )
        await application.start()

        result = await transport.invoke(
            "orders.echo",
            {"text": "hello"},
            context=context(),
        )

        assert result.error is not None
        assert result.error.code is ErrorCode.CANCELLED
        finished = spans.get_finished_spans()
        assert [span.name for span in finished] == [
            "mcp.tool.authorization",
            "mcp.tool.execution",
            "mcp.server.request",
        ]
        attributes = [span.attributes or {} for span in finished]
        assert attributes[0]["mcp.outcome"] == "success"
        assert attributes[1]["mcp.outcome"] == "cancellation"
        assert attributes[2]["mcp.outcome"] == "cancellation"

        await application.drain()
        await application.stop()
        tracer_provider.shutdown()
        meter_provider.shutdown()

    asyncio.run(exercise())


def test_exporter_failure_never_changes_a_tool_result() -> None:
    async def exercise() -> None:
        observability = RuntimeObservability(
            server_name="orders-mcp",
            exporter=ExplodingRuntimeExporter(),
        )
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([EchoTool()]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=IgnoreTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=SystemClock(),
            observability=observability,
        )
        await application.start()

        result = await transport.invoke(
            "orders.echo",
            {"text": "hello"},
            context=context(),
        )

        assert result == InvocationResult.success({"text": "hello"})
        assert observability.dropped_events > 0
        assert CANARY not in observability.render_prometheus()
        await application.drain()
        await application.stop()

    asyncio.run(exercise())


def test_request_log_contains_redacted_request_and_trace_ids_but_no_payload(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def exercise() -> None:
        logger = logging.getLogger("test.runtime.structured")
        caplog.set_level(logging.INFO, logger=logger.name)
        spans = InMemorySpanExporter()
        tracer_provider = TracerProvider()
        tracer_provider.add_span_processor(SimpleSpanProcessor(spans))
        metric_reader = InMemoryMetricReader()
        meter_provider = MeterProvider(metric_readers=(metric_reader,))
        exporter = OpenTelemetryRuntimeExporter(
            server_name="orders-mcp",
            tracer=tracer_provider.get_tracer("test"),
            meter=meter_provider.get_meter("test"),
            logger=logger,
        )
        observability = RuntimeObservability(server_name="orders-mcp", exporter=exporter)
        transport = InProcessTransport()
        application = Application(
            catalog=ToolCatalog([EchoTool()]),
            authorizer=AllowAll(),
            transport=transport,
            telemetry=IgnoreTelemetry(),
            limits=ApplicationLimits(drain_timeout=5.0),
            clock=SystemClock(),
            redactor=SecretRedactor(known_secrets=(SecretValue(CANARY),)),
            observability=observability,
        )
        await application.start()

        result = await transport.invoke(
            "orders.echo",
            {"text": CANARY},
            context=replace(context(), request_id=f"request-{CANARY}"),
        )

        assert result == InvocationResult.success({"text": "[REDACTED]"})
        messages = [record.getMessage() for record in caplog.records if record.name == logger.name]
        assert len(messages) == 1
        event = json.loads(messages[0])
        assert event == {
            "duration_seconds": event["duration_seconds"],
            "event": "request_completed",
            "operation": "tool_call",
            "outcome": "success",
            "request_id": "request-[REDACTED]",
            "server": "orders-mcp",
            "tool": "orders.echo",
            "trace_id": "1" * 32,
        }
        assert CANARY not in messages[0]
        assert "tenant-example" not in messages[0]
        assert "arguments" not in messages[0]
        assert "result" not in messages[0]
        assert CANARY not in observability.render_prometheus()
        assert all(CANARY not in str(span.attributes) for span in spans.get_finished_spans())

        await application.drain()
        await application.stop()
        tracer_provider.shutdown()
        meter_provider.shutdown()

    asyncio.run(exercise())
