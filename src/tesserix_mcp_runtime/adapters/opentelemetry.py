"""OpenTelemetry export for bounded runtime observations."""

from __future__ import annotations

import json
import logging
from contextvars import Token
from threading import Lock

from opentelemetry import context as otel_context
from opentelemetry.context import Context
from opentelemetry.metrics import Meter
from opentelemetry.propagators.textmap import Getter
from opentelemetry.trace import (
    Span,
    SpanKind,
    Status,
    StatusCode,
    Tracer,
    set_span_in_context,
)
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from tesserix_mcp_runtime.observability import (
    RuntimeLimit,
    RuntimeLogEvent,
    RuntimeOperation,
    RuntimeOutcome,
    RuntimeSpan,
    RuntimeSpanName,
    RuntimeSpanSpec,
)


class _MappingGetter(Getter[dict[str, str]]):
    def get(self, carrier: dict[str, str], key: str) -> list[str] | None:
        value = carrier.get(key)
        return [value] if value is not None else None

    def keys(self, carrier: dict[str, str]) -> list[str]:
        return list(carrier)


_GETTER = _MappingGetter()


class _OpenTelemetrySpan(RuntimeSpan):
    def __init__(self, span: Span) -> None:
        self._span = span
        self._token: Token[Context] | None = None
        self._ended = False

    @property
    def trace_id(self) -> str | None:
        context = self._span.get_span_context()
        if not context.is_valid:
            return None
        return format(context.trace_id, "032x")

    def activate(self) -> None:
        if self._ended or self._token is not None:
            raise RuntimeError("span activation order is invalid")
        self._token = otel_context.attach(set_span_in_context(self._span))

    def set_outcome(self, outcome: object) -> None:
        if self._ended or not isinstance(outcome, RuntimeOutcome):
            raise RuntimeError("span outcome order is invalid")
        self._span.set_attribute("mcp.outcome", outcome.value)
        status = StatusCode.OK if outcome is RuntimeOutcome.SUCCESS else StatusCode.ERROR
        self._span.set_status(Status(status))

    def end(self) -> None:
        if self._ended:
            return
        token = self._token
        self._token = None
        if token is not None:
            otel_context.detach(token)
        self._span.end()
        self._ended = True


class OpenTelemetryRuntimeExporter:
    def __init__(
        self,
        *,
        server_name: str,
        tracer: Tracer,
        meter: Meter,
        logger: logging.Logger | None = None,
    ) -> None:
        self._server_name = server_name
        self._tracer = tracer
        self._logger = logger
        self._request_count = meter.create_counter("mcp.server.request.count", unit="{request}")
        self._request_duration = meter.create_histogram("mcp.server.request.duration", unit="s")
        self._server_in_flight = meter.create_up_down_counter(
            "mcp.server.in_flight", unit="{request}"
        )
        self._tool_in_flight = meter.create_up_down_counter("mcp.tool.in_flight", unit="{request}")
        self._server_limit = meter.create_gauge("mcp.server.concurrency.limit", unit="{request}")
        self._tool_limit = meter.create_gauge("mcp.tool.concurrency.limit", unit="{request}")
        self._saturation = meter.create_gauge("mcp.server.saturation", unit="1")
        self._queue_depth = meter.create_gauge("mcp.server.queue.depth", unit="{request}")
        self._retry_count = meter.create_counter("mcp.tool.retry.count", unit="{retry}")
        self._limit_count = meter.create_counter("mcp.server.limit.count", unit="{event}")
        self._cancellation_count = meter.create_counter(
            "mcp.server.cancellation.count", unit="{event}"
        )
        self._dropped_count = meter.create_counter("mcp.telemetry.dropped.count", unit="{event}")
        self._active = 0
        self._tool_active: dict[str, int] = {}
        self._lock = Lock()
        self._queue_depth.set(0, {"mcp.server.name": server_name})

    def _attributes(
        self,
        *,
        tool_name: str | None = None,
        operation: RuntimeOperation | None = None,
        outcome: RuntimeOutcome | None = None,
    ) -> dict[str, str]:
        attributes = {"mcp.server.name": self._server_name}
        if tool_name is not None:
            attributes["mcp.tool.name"] = tool_name
        if operation is not None:
            attributes["mcp.operation"] = operation.value
        if outcome is not None:
            attributes["mcp.outcome"] = outcome.value
        return attributes

    def record_call(
        self,
        *,
        operation: RuntimeOperation,
        tool_name: str | None,
        outcome: RuntimeOutcome,
        duration_seconds: float,
    ) -> None:
        attributes = self._attributes(
            tool_name=tool_name,
            operation=operation,
            outcome=outcome,
        )
        self._request_count.add(1, attributes)
        self._request_duration.record(duration_seconds, attributes)
        if outcome is RuntimeOutcome.CANCELLATION:
            self._cancellation_count.add(1, self._attributes(tool_name=tool_name))

    def change_in_flight(
        self,
        *,
        tool_name: str,
        delta: int,
        server_capacity: int,
        tool_capacity: int,
    ) -> None:
        server_attributes = self._attributes()
        tool_attributes = self._attributes(tool_name=tool_name)
        with self._lock:
            self._active += delta
            self._tool_active[tool_name] = self._tool_active.get(tool_name, 0) + delta
            active = self._active
        self._server_in_flight.add(delta, server_attributes)
        self._tool_in_flight.add(delta, tool_attributes)
        self._server_limit.set(server_capacity, server_attributes)
        self._tool_limit.set(tool_capacity, tool_attributes)
        self._saturation.set(active / server_capacity, server_attributes)

    def record_retry(self, *, tool_name: str) -> None:
        self._retry_count.add(1, self._attributes(tool_name=tool_name))

    def record_limit(self, *, tool_name: str | None, limit: RuntimeLimit) -> None:
        attributes = self._attributes(tool_name=tool_name)
        attributes["mcp.limit"] = limit.value
        self._limit_count.add(1, attributes)

    def record_dropped(self, *, count: int) -> None:
        self._dropped_count.add(count, self._attributes())

    def emit_log(self, event: RuntimeLogEvent) -> None:
        if self._logger is not None:
            self._logger.info(json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":")))

    def start_span(self, spec: RuntimeSpanSpec) -> RuntimeSpan:
        if spec.server_name != self._server_name:
            raise ValueError("span server does not match exporter")
        parent: Context | None = None
        if spec.trace_context is not None:
            parent = Context()
            if spec.trace_context.traceparent is not None:
                carrier = dict(spec.trace_context.as_mapping())
                parent = TraceContextTextMapPropagator().extract(
                    carrier=carrier,
                    context=parent,
                    getter=_GETTER,
                )
        attributes = self._attributes(
            tool_name=spec.tool_name,
            operation=spec.operation,
        )
        if spec.destination_fingerprint is not None:
            attributes["mcp.destination.fingerprint"] = spec.destination_fingerprint
        kind = (
            SpanKind.SERVER
            if spec.name is RuntimeSpanName.MCP_REQUEST
            else SpanKind.CLIENT
            if spec.name is RuntimeSpanName.DOWNSTREAM
            else SpanKind.INTERNAL
        )
        span = self._tracer.start_span(
            spec.name.value,
            context=parent,
            kind=kind,
            attributes=attributes,
        )
        return _OpenTelemetrySpan(span)
