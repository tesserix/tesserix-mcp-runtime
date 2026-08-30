from __future__ import annotations

import pytest

from tesserix_mcp_runtime import TraceContext
from tesserix_mcp_runtime.observability import (
    RuntimeLimit,
    RuntimeLogEvent,
    RuntimeLogName,
    RuntimeObservability,
    RuntimeOperation,
    RuntimeOutcome,
    RuntimeSpan,
    RuntimeSpanName,
    RuntimeSpanSpec,
)

CANARY = "SyntheticExporterCanary9Lm4"


class FailingMetricExporter:
    def record_call(
        self,
        *,
        operation: RuntimeOperation,
        tool_name: str | None,
        outcome: RuntimeOutcome,
        duration_seconds: float,
    ) -> None:
        del operation, tool_name, outcome, duration_seconds
        raise RuntimeError(CANARY)

    def change_in_flight(
        self,
        *,
        tool_name: str,
        delta: int,
        server_capacity: int,
        tool_capacity: int,
    ) -> None:
        del tool_name, delta, server_capacity, tool_capacity
        raise RuntimeError(CANARY)

    def record_retry(self, *, tool_name: str) -> None:
        del tool_name
        raise RuntimeError(CANARY)

    def record_limit(self, *, tool_name: str | None, limit: RuntimeLimit) -> None:
        del tool_name, limit
        raise RuntimeError(CANARY)

    def record_dropped(self, *, count: int) -> None:
        del count
        raise RuntimeError(CANARY)

    def emit_log(self, event: RuntimeLogEvent) -> None:
        del event
        raise RuntimeError(CANARY)

    def start_span(self, spec: RuntimeSpanSpec) -> RuntimeSpan:
        del spec
        raise RuntimeError(CANARY)


def test_red_metrics_use_stable_low_cardinality_dimensions() -> None:
    observability = RuntimeObservability(server_name="orders-mcp")

    observability.record_call(
        operation=RuntimeOperation.TOOL_CALL,
        tool_name="orders.get",
        outcome=RuntimeOutcome.SUCCESS,
        duration_seconds=0.012,
    )

    metrics = observability.render_prometheus()

    labels = 'operation="tool_call",outcome="success",server="orders-mcp",tool="orders.get"'
    assert f"mcp_server_request_count_total{{{labels}}} 1" in metrics
    assert f"mcp_server_request_duration_seconds_count{{{labels}}} 1" in metrics
    assert f"mcp_server_request_duration_seconds_sum{{{labels}}} 0.012" in metrics
    assert "request_id" not in metrics
    assert "tenant" not in metrics


def test_red_metrics_expose_every_operator_outcome_as_a_stable_label() -> None:
    observability = RuntimeObservability(server_name="orders-mcp")
    outcomes = (
        RuntimeOutcome.SUCCESS,
        RuntimeOutcome.POLICY_REFUSAL,
        RuntimeOutcome.TOOL_FAILURE,
        RuntimeOutcome.TIMEOUT,
        RuntimeOutcome.CANCELLATION,
        RuntimeOutcome.OVERLOAD,
        RuntimeOutcome.DEPENDENCY_OUTAGE,
    )

    for outcome in outcomes:
        observability.record_call(
            operation=RuntimeOperation.TOOL_CALL,
            tool_name="orders.get",
            outcome=outcome,
            duration_seconds=0.001,
        )

    metrics = observability.render_prometheus()
    for outcome in outcomes:
        labels = (
            f'operation="tool_call",outcome="{outcome.value}",server="orders-mcp",tool="orders.get"'
        )
        assert f"mcp_server_request_count_total{{{labels}}} 1" in metrics


@pytest.mark.parametrize("tool_name", ["bad\nlabel", "x" * 129])
def test_unbounded_tool_names_cannot_create_metric_series(tool_name: str) -> None:
    observability = RuntimeObservability(server_name="orders-mcp")

    with pytest.raises(ValueError, match="tool_name"):
        observability.record_call(
            operation=RuntimeOperation.TOOL_CALL,
            tool_name=tool_name,
            outcome=RuntimeOutcome.SUCCESS,
            duration_seconds=0.001,
        )

    assert tool_name not in observability.render_prometheus()


def test_saturation_metrics_track_active_work_without_tenant_labels() -> None:
    observability = RuntimeObservability(server_name="orders-mcp")

    observability.change_in_flight(
        tool_name="orders.get",
        delta=1,
        server_capacity=200,
        tool_capacity=16,
    )

    metrics = observability.render_prometheus()

    assert 'mcp_server_in_flight{server="orders-mcp"} 1' in metrics
    assert 'mcp_server_concurrency_limit{server="orders-mcp"} 200' in metrics
    assert 'mcp_server_saturation_ratio{server="orders-mcp"} 0.005' in metrics
    assert 'mcp_tool_in_flight{server="orders-mcp",tool="orders.get"} 1' in metrics
    assert 'mcp_tool_concurrency_limit{server="orders-mcp",tool="orders.get"} 16' in metrics
    assert 'mcp_server_queue_depth{server="orders-mcp"} 0' in metrics
    assert "tenant" not in metrics


def test_resilience_metrics_use_stable_retry_limit_and_cancellation_reasons() -> None:
    observability = RuntimeObservability(server_name="orders-mcp")

    observability.record_retry(tool_name="orders.get")
    observability.record_limit(tool_name="orders.get", limit=RuntimeLimit.TENANT)
    observability.record_call(
        operation=RuntimeOperation.TOOL_CALL,
        tool_name="orders.get",
        outcome=RuntimeOutcome.CANCELLATION,
        duration_seconds=0.2,
    )

    metrics = observability.render_prometheus()

    labels = 'server="orders-mcp",tool="orders.get"'
    assert f"mcp_tool_retry_count_total{{{labels}}} 1" in metrics
    assert f'mcp_server_limit_count_total{{limit="tenant",{labels}}} 1' in metrics
    assert f"mcp_server_cancellation_count_total{{{labels}}} 1" in metrics


def test_metric_export_failure_drops_telemetry_without_failing_runtime_work() -> None:
    observability = RuntimeObservability(
        server_name="orders-mcp",
        exporter=FailingMetricExporter(),
    )

    observability.record_call(
        operation=RuntimeOperation.TOOL_CALL,
        tool_name="orders.get",
        outcome=RuntimeOutcome.SUCCESS,
        duration_seconds=0.01,
    )

    assert observability.dropped_events == 1
    metrics = observability.render_prometheus()
    assert 'mcp_telemetry_dropped_count_total{server="orders-mcp"} 1' in metrics
    assert CANARY not in metrics


def test_structured_request_log_has_only_bounded_stable_fields() -> None:
    event = RuntimeLogEvent(
        name=RuntimeLogName.REQUEST_COMPLETED,
        server_name="orders-mcp",
        request_id="request-example",
        trace_id="1" * 32,
        operation=RuntimeOperation.TOOL_CALL,
        tool_name="orders.get",
        outcome=RuntimeOutcome.SUCCESS,
        duration_seconds=0.012,
    )

    assert event.to_dict() == {
        "duration_seconds": 0.012,
        "event": "request_completed",
        "operation": "tool_call",
        "outcome": "success",
        "request_id": "request-example",
        "server": "orders-mcp",
        "tool": "orders.get",
        "trace_id": "1" * 32,
    }


def test_span_export_failure_never_fails_the_instrumented_operation() -> None:
    observability = RuntimeObservability(
        server_name="orders-mcp",
        exporter=FailingMetricExporter(),
    )
    completed = False

    with observability.start_span(
        RuntimeSpanSpec(
            name=RuntimeSpanName.MCP_REQUEST,
            server_name="orders-mcp",
            trace_context=TraceContext(
                traceparent="00-11111111111111111111111111111111-1111111111111111-01"
            ),
            operation=RuntimeOperation.TOOL_CALL,
            tool_name="orders.get",
        )
    ) as span:
        span.set_outcome(RuntimeOutcome.SUCCESS)
        completed = True

    assert completed is True
    assert observability.dropped_events == 1
