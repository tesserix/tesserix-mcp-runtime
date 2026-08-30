"""Bounded OpenTelemetry SDK providers for the runtime adapter."""

from __future__ import annotations

import asyncio
import logging
import math
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    MetricExporter,
    MetricExportResult,
    MetricsData,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

from tesserix_mcp_runtime.adapters.opentelemetry import OpenTelemetryRuntimeExporter
from tesserix_mcp_runtime.observability import RuntimeObservability

_MAX_SPAN_QUEUE_SIZE = 2_048
_MAX_SPAN_BATCH_SIZE = 512
_MAX_EXPORT_SECONDS = 30.0
_MAX_METRIC_INTERVAL_SECONDS = 300.0


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


@dataclass(frozen=True, slots=True, kw_only=True)
class OpenTelemetrySDKLimits:
    span_queue_size: int = _MAX_SPAN_QUEUE_SIZE
    span_batch_size: int = _MAX_SPAN_BATCH_SIZE
    span_schedule_delay_seconds: float = 5.0
    export_timeout_seconds: float = 5.0
    metric_export_interval_seconds: float = 60.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.span_queue_size, bool)
            or not _is_runtime_instance(self.span_queue_size, int)
            or not 1 <= self.span_queue_size <= _MAX_SPAN_QUEUE_SIZE
            or isinstance(self.span_batch_size, bool)
            or not _is_runtime_instance(self.span_batch_size, int)
            or not 1
            <= self.span_batch_size
            <= min(
                self.span_queue_size,
                _MAX_SPAN_BATCH_SIZE,
            )
        ):
            raise ValueError("span queue and batch sizes must satisfy runtime hard bounds")
        durations = (
            (self.span_schedule_delay_seconds, _MAX_EXPORT_SECONDS),
            (self.export_timeout_seconds, _MAX_EXPORT_SECONDS),
            (self.metric_export_interval_seconds, _MAX_METRIC_INTERVAL_SECONDS),
        )
        if any(
            isinstance(value, bool)
            or not (_is_runtime_instance(value, int) or _is_runtime_instance(value, float))
            or not math.isfinite(value)
            or not 0 < value <= maximum
            for value, maximum in durations
        ):
            raise ValueError("OpenTelemetry durations must be finite and bounded")


class _DropRecorder:
    def __init__(self) -> None:
        self.observability: RuntimeObservability | None = None

    def record(self, count: int) -> None:
        if self.observability is not None:
            self.observability.record_dropped(count=count)


class _MetricExporterOperations(Protocol):
    def export(
        self,
        metrics_data: MetricsData,
        timeout_millis: float = 10_000,
        **kwargs: object,
    ) -> MetricExportResult: ...

    def shutdown(self, timeout_millis: float = 30_000, **kwargs: object) -> None: ...

    def force_flush(self, timeout_millis: float = 10_000) -> bool: ...


class _PendingSpans:
    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._count = 0
        self._lock = threading.Lock()

    def add(self) -> bool:
        with self._lock:
            if self._count >= self._capacity:
                return False
            self._count += 1
            return True

    def remove(self, count: int) -> None:
        with self._lock:
            self._count = max(0, self._count - count)

    def clear(self) -> int:
        with self._lock:
            count = self._count
            self._count = 0
            return count


class _ResilientSpanExporter(SpanExporter):
    def __init__(
        self,
        inner: SpanExporter,
        drops: _DropRecorder,
        pending: _PendingSpans,
        export_timeout_seconds: float,
    ) -> None:
        self._inner = inner
        self._drops = drops
        self._pending = pending
        self._export_timeout_seconds = export_timeout_seconds
        self._in_flight_lock = threading.Lock()
        self._in_flight: threading.Thread | None = None

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        self._pending.remove(len(spans))
        count = max(1, len(spans))
        result = [SpanExportResult.FAILURE]
        completed = threading.Event()
        with self._in_flight_lock:
            if self._in_flight is not None:
                self._drops.record(count)
                return SpanExportResult.FAILURE
            export_thread = threading.Thread(
                target=self._export,
                args=(tuple(spans), result, completed),
                daemon=True,
            )
            self._in_flight = export_thread
            try:
                export_thread.start()
            except RuntimeError:
                self._in_flight = None
                self._drops.record(count)
                return SpanExportResult.FAILURE
        if not completed.wait(self._export_timeout_seconds):
            self._drops.record(count)
            return SpanExportResult.FAILURE
        if result[0] is not SpanExportResult.SUCCESS:
            self._drops.record(count)
        return result[0]

    def _export(
        self,
        spans: Sequence[ReadableSpan],
        result: list[SpanExportResult],
        completed: threading.Event,
    ) -> None:
        try:
            result[0] = self._inner.export(spans)
        except Exception:
            result[0] = SpanExportResult.FAILURE
        finally:
            with self._in_flight_lock:
                self._in_flight = None
            completed.set()

    def shutdown(self) -> None:
        try:
            self._inner.shutdown()
        except Exception:
            self._drops.record(1)


class _DropCountingBatchSpanProcessor(BatchSpanProcessor):
    def __init__(
        self,
        exporter: SpanExporter,
        *,
        pending: _PendingSpans,
        drops: _DropRecorder,
        limits: OpenTelemetrySDKLimits,
    ) -> None:
        self._pending = pending
        self._drops = drops
        self._accepting = True
        super().__init__(
            exporter,
            max_queue_size=limits.span_queue_size,
            max_export_batch_size=limits.span_batch_size,
            schedule_delay_millis=limits.span_schedule_delay_seconds * 1_000,
            export_timeout_millis=limits.export_timeout_seconds * 1_000,
        )

    def on_end(self, span: ReadableSpan) -> None:
        context = span.context
        if (
            context is not None
            and context.trace_flags.sampled
            and (not self._accepting or not self._pending.add())
        ):
            self._drops.record(1)
        super().on_end(span)

    def shutdown(self) -> None:
        self._accepting = False
        shutdown: Callable[[], None] = super().shutdown
        shutdown()
        remaining = self._pending.clear()
        if remaining:
            self._drops.record(remaining)


class _ResilientMetricExporter(MetricExporter):
    def __init__(self, inner: MetricExporter, drops: _DropRecorder) -> None:
        super().__init__()
        self._inner: _MetricExporterOperations = inner
        self._drops = drops

    def export(
        self,
        metrics_data: MetricsData,
        timeout_millis: float = 10_000,
        **kwargs: object,
    ) -> MetricExportResult:
        try:
            result = self._inner.export(
                metrics_data,
                timeout_millis=timeout_millis,
                **kwargs,
            )
        except Exception:
            self._drops.record(1)
            return MetricExportResult.FAILURE
        if result is not MetricExportResult.SUCCESS:
            self._drops.record(1)
        return result

    def shutdown(self, timeout_millis: float = 30_000, **kwargs: object) -> None:
        try:
            self._inner.shutdown(timeout_millis=timeout_millis, **kwargs)
        except Exception:
            self._drops.record(1)

    def force_flush(self, timeout_millis: float = 10_000) -> bool:
        try:
            flushed = self._inner.force_flush(timeout_millis=timeout_millis)
        except Exception:
            self._drops.record(1)
            return False
        if not flushed:
            self._drops.record(1)
        return flushed


class OpenTelemetrySDKRuntime:
    name = "opentelemetry_sdk"

    def __init__(
        self,
        *,
        server_name: str,
        span_exporter: SpanExporter | None = None,
        metric_exporter: MetricExporter | None = None,
        logger: logging.Logger | None = None,
        limits: OpenTelemetrySDKLimits | None = None,
    ) -> None:
        resolved_limits = OpenTelemetrySDKLimits() if limits is None else limits
        if not _is_runtime_instance(resolved_limits, OpenTelemetrySDKLimits):
            raise ValueError("limits must be OpenTelemetrySDKLimits")
        RuntimeObservability(server_name=server_name)
        if span_exporter is not None and not _is_runtime_instance(span_exporter, SpanExporter):
            raise ValueError("span_exporter must be an OpenTelemetry SpanExporter")
        if metric_exporter is not None and not _is_runtime_instance(
            metric_exporter, MetricExporter
        ):
            raise ValueError("metric_exporter must be an OpenTelemetry MetricExporter")
        if logger is not None and not _is_runtime_instance(logger, logging.Logger):
            raise ValueError("logger must be a logging.Logger")

        drops = _DropRecorder()
        resource = Resource.create({"service.name": server_name})
        tracer_provider = TracerProvider(resource=resource)
        if span_exporter is not None:
            pending = _PendingSpans(resolved_limits.span_queue_size)
            tracer_provider.add_span_processor(
                _DropCountingBatchSpanProcessor(
                    _ResilientSpanExporter(
                        span_exporter,
                        drops,
                        pending,
                        resolved_limits.export_timeout_seconds,
                    ),
                    pending=pending,
                    drops=drops,
                    limits=resolved_limits,
                )
            )
        readers = (
            (
                PeriodicExportingMetricReader(
                    _ResilientMetricExporter(metric_exporter, drops),
                    export_interval_millis=(resolved_limits.metric_export_interval_seconds * 1_000),
                    export_timeout_millis=(resolved_limits.export_timeout_seconds * 1_000),
                ),
            )
            if metric_exporter is not None
            else ()
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=readers)
        exporter = OpenTelemetryRuntimeExporter(
            server_name=server_name,
            tracer=tracer_provider.get_tracer("tesserix_mcp_runtime"),
            meter=meter_provider.get_meter("tesserix_mcp_runtime"),
            logger=logger,
        )
        observability = RuntimeObservability(server_name=server_name, exporter=exporter)
        drops.observability = observability

        self._limits = resolved_limits
        self._tracer_provider = tracer_provider
        self._meter_provider = meter_provider
        self._observability = observability
        self._stopped = False

    @property
    def limits(self) -> OpenTelemetrySDKLimits:
        return self._limits

    @property
    def observability(self) -> RuntimeObservability:
        return self._observability

    async def start(self) -> None:
        if self._stopped:
            raise RuntimeError("stopped OpenTelemetry runtime cannot restart")

    async def drain(self, *, deadline: float) -> None:
        del deadline
        timeout_millis = int(self._limits.export_timeout_seconds * 1_000)
        await asyncio.to_thread(self._force_flush, timeout_millis)

    def _force_flush(self, timeout_millis: int) -> None:
        try:
            traces_flushed = self._tracer_provider.force_flush(timeout_millis)
        except Exception:
            self._observability.record_dropped()
        else:
            if not traces_flushed:
                self._observability.record_dropped()
        try:
            metrics_flushed = self._meter_provider.force_flush(timeout_millis)
        except Exception:
            self._observability.record_dropped()
        else:
            if not metrics_flushed:
                self._observability.record_dropped()

    async def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(self._shutdown_traces())
            tasks.create_task(self._shutdown_metrics())

    async def _shutdown_traces(self) -> None:
        try:
            await asyncio.to_thread(self._tracer_provider.shutdown)
        except Exception:
            self._observability.record_dropped()

    async def _shutdown_metrics(self) -> None:
        try:
            await asyncio.to_thread(
                self._meter_provider.shutdown,
                self._limits.export_timeout_seconds * 1_000,
            )
        except Exception:
            self._observability.record_dropped()


__all__ = ["OpenTelemetrySDKLimits", "OpenTelemetrySDKRuntime"]
