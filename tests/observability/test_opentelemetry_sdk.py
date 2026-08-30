from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Sequence

import pytest
from opentelemetry.sdk.metrics.export import (
    AggregationTemporality,
    MetricExporter,
    MetricExportResult,
    MetricsData,
)
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from tesserix_mcp_runtime.adapters.opentelemetry_sdk import (
    OpenTelemetrySDKLimits,
    OpenTelemetrySDKRuntime,
)
from tesserix_mcp_runtime.observability import (
    RuntimeOperation,
    RuntimeOutcome,
    RuntimeSpanName,
    RuntimeSpanSpec,
)


class RecordingSpanExporter(SpanExporter):
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.exported: list[ReadableSpan] = []
        self.shutdown_called = False

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        if self.fail:
            raise RuntimeError("SyntheticSpanExporterCanary2Vt8")
        self.exported.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self.shutdown_called = True


class RecordingMetricExporter(MetricExporter):
    def __init__(self) -> None:
        super().__init__(preferred_temporality={object: AggregationTemporality.CUMULATIVE})
        self.exports = 0
        self.shutdown_called = False

    def export(
        self,
        metrics_data: MetricsData,
        timeout_millis: float = 10_000,
        **kwargs: object,
    ) -> MetricExportResult:
        del metrics_data, timeout_millis, kwargs
        self.exports += 1
        return MetricExportResult.SUCCESS

    def shutdown(self, timeout_millis: float = 30_000, **kwargs: object) -> None:
        del timeout_millis, kwargs
        self.shutdown_called = True

    def force_flush(self, timeout_millis: float = 10_000) -> bool:
        del timeout_millis
        return True


class BlockingSpanExporter(SpanExporter):
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        del spans
        self.entered.set()
        if not self.release.wait(timeout=5.0):
            return SpanExportResult.FAILURE
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self.release.set()


class PermanentlyBlockingSpanExporter(SpanExporter):
    def __init__(self) -> None:
        self.calls = 0
        self.entered = threading.Event()
        self.release = threading.Event()

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        del spans
        self.calls += 1
        self.entered.set()
        self.release.wait()
        return SpanExportResult.SUCCESS

    def shutdown(self) -> None:
        self.release.set()


def test_sdk_limits_reject_values_outside_hard_bounds() -> None:
    with pytest.raises(ValueError, match="span queue and batch sizes"):
        OpenTelemetrySDKLimits(span_queue_size=0)
    with pytest.raises(ValueError, match="durations must be finite and bounded"):
        OpenTelemetrySDKLimits(export_timeout_seconds=float("nan"))


def test_stopped_sdk_runtime_cannot_restart_and_stop_is_idempotent() -> None:
    async def exercise() -> None:
        runtime = OpenTelemetrySDKRuntime(server_name="orders-mcp")
        await runtime.start()
        await runtime.stop()
        await runtime.stop()
        with pytest.raises(RuntimeError, match="cannot restart"):
            await runtime.start()

    asyncio.run(exercise())


def test_sdk_runtime_batches_with_fixed_bounds_and_flushes_optional_exporters() -> None:
    async def exercise() -> None:
        spans = RecordingSpanExporter()
        metrics = RecordingMetricExporter()
        runtime = OpenTelemetrySDKRuntime(
            server_name="orders-mcp",
            span_exporter=spans,
            metric_exporter=metrics,
        )

        assert runtime.limits == OpenTelemetrySDKLimits(
            span_queue_size=2_048,
            span_batch_size=512,
            span_schedule_delay_seconds=5.0,
            export_timeout_seconds=5.0,
            metric_export_interval_seconds=60.0,
        )
        await runtime.start()
        with runtime.observability.start_span(
            RuntimeSpanSpec(
                name=RuntimeSpanName.MCP_REQUEST,
                server_name="orders-mcp",
                operation=RuntimeOperation.MCP_REQUEST,
            )
        ) as span:
            span.set_outcome(RuntimeOutcome.SUCCESS)
        runtime.observability.record_call(
            operation=RuntimeOperation.MCP_REQUEST,
            tool_name=None,
            outcome=RuntimeOutcome.SUCCESS,
            duration_seconds=0.001,
        )

        await runtime.drain(deadline=10.0)

        assert [span.name for span in spans.exported] == ["mcp.server.request"]
        assert metrics.exports >= 1
        await runtime.stop()
        assert spans.shutdown_called
        assert metrics.shutdown_called

    asyncio.run(exercise())


def test_sdk_export_failure_is_counted_locally_and_never_escapes_drain() -> None:
    async def exercise() -> None:
        runtime = OpenTelemetrySDKRuntime(
            server_name="orders-mcp",
            span_exporter=RecordingSpanExporter(fail=True),
        )
        await runtime.start()
        with runtime.observability.start_span(
            RuntimeSpanSpec(
                name=RuntimeSpanName.MCP_REQUEST,
                server_name="orders-mcp",
            )
        ):
            pass

        await runtime.drain(deadline=10.0)

        assert runtime.observability.dropped_events == 1
        assert (
            'mcp_telemetry_dropped_count_total{server="orders-mcp"} 1'
            in runtime.observability.render_prometheus()
        )
        await runtime.stop()

    asyncio.run(exercise())


def test_full_span_queue_counts_each_bounded_drop_locally() -> None:
    async def exercise() -> None:
        exporter = BlockingSpanExporter()
        runtime = OpenTelemetrySDKRuntime(
            server_name="orders-mcp",
            span_exporter=exporter,
            limits=OpenTelemetrySDKLimits(
                span_queue_size=4,
                span_batch_size=2,
                span_schedule_delay_seconds=30.0,
            ),
        )
        await runtime.start()

        for _ in range(2):
            with runtime.observability.start_span(
                RuntimeSpanSpec(
                    name=RuntimeSpanName.MCP_REQUEST,
                    server_name="orders-mcp",
                )
            ):
                pass
        assert await asyncio.to_thread(exporter.entered.wait, 1.0)
        for _ in range(5):
            with runtime.observability.start_span(
                RuntimeSpanSpec(
                    name=RuntimeSpanName.MCP_REQUEST,
                    server_name="orders-mcp",
                )
            ):
                pass

        assert runtime.observability.dropped_events == 1
        exporter.release.set()
        await runtime.drain(deadline=10.0)
        await runtime.stop()

    asyncio.run(exercise())


def test_blocked_export_is_timed_out_and_later_batches_are_dropped() -> None:
    async def exercise() -> None:
        exporter = PermanentlyBlockingSpanExporter()
        runtime = OpenTelemetrySDKRuntime(
            server_name="orders-mcp",
            span_exporter=exporter,
            limits=OpenTelemetrySDKLimits(
                span_queue_size=4,
                span_batch_size=1,
                span_schedule_delay_seconds=30.0,
                export_timeout_seconds=0.2,
            ),
        )
        await runtime.start()

        try:
            with runtime.observability.start_span(
                RuntimeSpanSpec(
                    name=RuntimeSpanName.MCP_REQUEST,
                    server_name="orders-mcp",
                )
            ):
                pass
            assert await asyncio.to_thread(exporter.entered.wait, 1.0)

            started = time.perf_counter()
            async with asyncio.timeout(0.5):
                await runtime.drain(deadline=1.0)
            first_drain_seconds = time.perf_counter() - started

            with runtime.observability.start_span(
                RuntimeSpanSpec(
                    name=RuntimeSpanName.MCP_REQUEST,
                    server_name="orders-mcp",
                )
            ):
                pass
            started = time.perf_counter()
            async with asyncio.timeout(0.5):
                await runtime.drain(deadline=1.0)
            second_drain_seconds = time.perf_counter() - started
        finally:
            exporter.release.set()
            await runtime.stop()

        assert first_drain_seconds < 0.5
        assert second_drain_seconds < 0.1
        assert exporter.calls == 1
        assert runtime.observability.dropped_events == 2

    asyncio.run(exercise())
