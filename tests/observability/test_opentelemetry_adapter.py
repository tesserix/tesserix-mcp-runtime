from __future__ import annotations

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader, NumberDataPoint
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from tesserix_mcp_runtime import TraceContext
from tesserix_mcp_runtime.adapters.opentelemetry import OpenTelemetryRuntimeExporter
from tesserix_mcp_runtime.observability import (
    RuntimeLimit,
    RuntimeObservability,
    RuntimeOperation,
    RuntimeOutcome,
    RuntimeSpanName,
    RuntimeSpanSpec,
)


def test_request_span_uses_the_validated_gateway_parent_and_stable_attributes() -> None:
    spans = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(spans))
    metrics = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=(metrics,))
    exporter = OpenTelemetryRuntimeExporter(
        server_name="orders-mcp",
        tracer=tracer_provider.get_tracer("test"),
        meter=meter_provider.get_meter("test"),
    )
    observability = RuntimeObservability(server_name="orders-mcp", exporter=exporter)

    with observability.start_span(
        RuntimeSpanSpec(
            name=RuntimeSpanName.MCP_REQUEST,
            server_name="orders-mcp",
            trace_context=TraceContext(
                traceparent="00-11111111111111111111111111111111-2222222222222222-01"
            ),
            operation=RuntimeOperation.TOOL_CALL,
            tool_name="orders.get",
        )
    ) as span:
        assert span.trace_id == "1" * 32
        span.set_outcome(RuntimeOutcome.SUCCESS)

    finished = spans.get_finished_spans()
    assert len(finished) == 1
    assert finished[0].name == "mcp.server.request"
    assert finished[0].parent is not None
    assert finished[0].parent.span_id == int("2" * 16, 16)
    assert finished[0].context is not None
    assert finished[0].context.trace_id == int("1" * 32, 16)
    assert finished[0].status.status_code is StatusCode.OK
    assert dict(finished[0].attributes or {}) == {
        "mcp.operation": "tool_call",
        "mcp.outcome": "success",
        "mcp.server.name": "orders-mcp",
        "mcp.tool.name": "orders.get",
    }

    tracer_provider.shutdown()
    meter_provider.shutdown()


def test_red_and_saturation_metrics_export_without_high_cardinality_attributes() -> None:
    metrics = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=(metrics,))
    tracer_provider = TracerProvider()
    exporter = OpenTelemetryRuntimeExporter(
        server_name="orders-mcp",
        tracer=tracer_provider.get_tracer("test"),
        meter=meter_provider.get_meter("test"),
    )
    observability = RuntimeObservability(server_name="orders-mcp", exporter=exporter)

    observability.record_call(
        operation=RuntimeOperation.TOOL_CALL,
        tool_name="orders.get",
        outcome=RuntimeOutcome.SUCCESS,
        duration_seconds=0.012,
    )
    observability.change_in_flight(
        tool_name="orders.get",
        delta=1,
        server_capacity=200,
        tool_capacity=16,
    )
    observability.record_retry(tool_name="orders.get")
    observability.record_limit(tool_name="orders.get", limit=RuntimeLimit.TENANT)

    collected = metrics.get_metrics_data()
    assert collected is not None
    exported = {
        metric.name: metric
        for resource in collected.resource_metrics
        for scope in resource.scope_metrics
        for metric in scope.metrics
    }
    assert {
        "mcp.server.concurrency.limit",
        "mcp.server.in_flight",
        "mcp.server.limit.count",
        "mcp.server.request.count",
        "mcp.server.request.duration",
        "mcp.server.saturation",
        "mcp.tool.concurrency.limit",
        "mcp.tool.in_flight",
        "mcp.tool.retry.count",
    } <= exported.keys()
    request_count = tuple(exported["mcp.server.request.count"].data.data_points)
    assert len(request_count) == 1
    request_point = request_count[0]
    assert isinstance(request_point, NumberDataPoint)
    assert request_point.value == 1
    assert request_point.attributes == {
        "mcp.operation": "tool_call",
        "mcp.outcome": "success",
        "mcp.server.name": "orders-mcp",
        "mcp.tool.name": "orders.get",
    }
    all_attribute_names = {
        name
        for metric in exported.values()
        for point in metric.data.data_points
        for name in (point.attributes or {})
    }
    assert "request_id" not in all_attribute_names
    assert "tenant" not in all_attribute_names
    assert "url" not in all_attribute_names

    tracer_provider.shutdown()
    meter_provider.shutdown()
