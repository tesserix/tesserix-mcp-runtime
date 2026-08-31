"""Bounded low-cardinality runtime observations and local metrics."""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from threading import Lock
from typing import Any, Literal, Protocol, runtime_checkable

from tesserix_mcp_runtime.contracts import JsonValue, TraceContext

_DIMENSION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,127})?\Z")
_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
_MAX_DURATION_SECONDS = 3_600.0
_MAX_DROPPED_BATCH = 1_000_000
_MAX_REQUEST_SERIES = 2_048
_MAX_TOOLS = 128


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


class RuntimeOperation(StrEnum):
    MCP_REQUEST = "mcp_request"
    TOOL_CALL = "tool_call"
    AUTHORIZATION = "authorization"
    TOOL_EXECUTION = "tool_execution"
    DOWNSTREAM = "downstream"


class RuntimeOutcome(StrEnum):
    SUCCESS = "success"
    POLICY_REFUSAL = "policy_refusal"
    TOOL_FAILURE = "tool_failure"
    TIMEOUT = "timeout"
    CANCELLATION = "cancellation"
    OVERLOAD = "overload"
    DEPENDENCY_OUTAGE = "dependency_outage"
    INVALID_INPUT = "invalid_input"
    LIMIT_EXCEEDED = "limit_exceeded"


class RuntimeLimit(StrEnum):
    GLOBAL = "global"
    SERVER = "server"
    TOOL = "tool"
    TENANT = "tenant"
    INPUT = "input"
    RESULT = "result"
    DRAIN = "drain"
    CIRCUIT = "circuit"


class RuntimeLogName(StrEnum):
    REQUEST_COMPLETED = "request_completed"
    TRACE_CONTEXT_REJECTED = "trace_context_rejected"
    LIFECYCLE = "lifecycle"
    READINESS_FAILED = "readiness_failed"


class RuntimeReason(StrEnum):
    MALFORMED_TRACE_CONTEXT = "malformed_trace_context"
    STARTUP_FAILURE = "startup_failure"
    DRAIN_TIMEOUT = "drain_timeout"
    READINESS_DEPENDENCY = "readiness_dependency"


class RuntimeSpanName(StrEnum):
    MCP_REQUEST = "mcp.server.request"
    AUTHORIZATION = "mcp.tool.authorization"
    TOOL_EXECUTION = "mcp.tool.execution"
    DOWNSTREAM = "mcp.client.request"


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeSpanSpec:
    name: RuntimeSpanName
    server_name: str
    trace_context: TraceContext | None = None
    operation: RuntimeOperation | None = None
    tool_name: str | None = None
    destination_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.name, RuntimeSpanName):
            raise ValueError("name must use the stable runtime span vocabulary")
        _dimension("server_name", self.server_name)
        if self.trace_context is not None and not _is_runtime_instance(
            self.trace_context, TraceContext
        ):
            raise ValueError("trace_context must be a validated W3C context")
        if self.operation is not None and not _is_runtime_instance(
            self.operation, RuntimeOperation
        ):
            raise ValueError("operation must use the stable runtime vocabulary")
        if self.tool_name is not None:
            _dimension("tool_name", self.tool_name)
        if (
            self.destination_fingerprint is not None
            and re.fullmatch(r"[0-9a-f]{64}", self.destination_fingerprint) is None
        ):
            raise ValueError("destination_fingerprint must be a SHA-256 digest")


@runtime_checkable
class RuntimeSpan(Protocol):
    @property
    def trace_id(self) -> str | None: ...

    def activate(self) -> None: ...

    def set_outcome(self, outcome: RuntimeOutcome) -> None: ...

    def end(self) -> None: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class RuntimeLogEvent:
    name: RuntimeLogName
    server_name: str
    request_id: str | None = None
    trace_id: str | None = None
    operation: RuntimeOperation | None = None
    tool_name: str | None = None
    outcome: RuntimeOutcome | None = None
    reason: RuntimeReason | None = None
    duration_seconds: float | None = None

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.name, RuntimeLogName):
            raise ValueError("name must use the stable runtime log vocabulary")
        _dimension("server_name", self.server_name)
        if self.request_id is not None and (
            not _is_runtime_instance(self.request_id, str)
            or not 1 <= len(self.request_id) <= 256
            or any(ord(character) < 32 or ord(character) == 127 for character in self.request_id)
        ):
            raise ValueError("request_id must be bounded visible text")
        if self.trace_id is not None and re.fullmatch(r"[0-9a-f]{32}", self.trace_id) is None:
            raise ValueError("trace_id must be a lowercase W3C trace identifier")
        if self.operation is not None and not _is_runtime_instance(
            self.operation, RuntimeOperation
        ):
            raise ValueError("operation must use the stable runtime vocabulary")
        if self.tool_name is not None:
            _dimension("tool_name", self.tool_name)
        if self.outcome is not None and not _is_runtime_instance(self.outcome, RuntimeOutcome):
            raise ValueError("outcome must use the stable runtime vocabulary")
        if self.reason is not None and not _is_runtime_instance(self.reason, RuntimeReason):
            raise ValueError("reason must use the stable runtime vocabulary")
        if self.duration_seconds is not None and (
            isinstance(self.duration_seconds, bool)
            or not (
                _is_runtime_instance(self.duration_seconds, int)
                or _is_runtime_instance(self.duration_seconds, float)
            )
            or not math.isfinite(self.duration_seconds)
            or not 0 <= self.duration_seconds <= _MAX_DURATION_SECONDS
        ):
            raise ValueError("duration_seconds must be finite and bounded")
        if self.name is RuntimeLogName.REQUEST_COMPLETED and (
            self.request_id is None
            or self.operation is None
            or self.outcome is None
            or self.duration_seconds is None
        ):
            raise ValueError(
                "request completion logs require request, trace, operation, outcome, time"
            )

    def to_dict(self) -> dict[str, JsonValue]:
        values: tuple[tuple[str, JsonValue | None], ...] = (
            ("duration_seconds", self.duration_seconds),
            ("event", self.name.value),
            ("operation", self.operation.value if self.operation is not None else None),
            ("outcome", self.outcome.value if self.outcome is not None else None),
            ("reason", self.reason.value if self.reason is not None else None),
            ("request_id", self.request_id),
            ("server", self.server_name),
            ("tool", self.tool_name),
            ("trace_id", self.trace_id),
        )
        return {name: value for name, value in values if value is not None}


@runtime_checkable
class RuntimeExporter(Protocol):
    def record_call(
        self,
        *,
        operation: RuntimeOperation,
        tool_name: str | None,
        outcome: RuntimeOutcome,
        duration_seconds: float,
    ) -> None: ...

    def change_in_flight(
        self,
        *,
        tool_name: str,
        delta: int,
        server_capacity: int,
        tool_capacity: int,
    ) -> None: ...

    def record_retry(self, *, tool_name: str) -> None: ...

    def record_limit(self, *, tool_name: str | None, limit: RuntimeLimit) -> None: ...

    def record_dropped(self, *, count: int) -> None: ...

    def emit_log(self, event: RuntimeLogEvent) -> None: ...

    def start_span(self, spec: RuntimeSpanSpec) -> RuntimeSpan: ...


class _SafeSpan:
    def __init__(self, owner: RuntimeObservability, inner: RuntimeSpan | None) -> None:
        self._owner = owner
        self._inner = inner

    @property
    def trace_id(self) -> str | None:
        if self._inner is None:
            return None
        try:
            value = self._inner.trace_id
            if value is not None and re.fullmatch(r"[0-9a-f]{32}", value) is None:
                raise ValueError("invalid trace identifier")
            return value
        except Exception:
            self._owner.record_dropped()
            self._inner = None
            return None

    def __enter__(self) -> _SafeSpan:
        if self._inner is not None:
            try:
                self._inner.activate()
            except Exception:
                self._owner.record_dropped()
                self._inner = None
        return self

    def set_outcome(self, outcome: RuntimeOutcome) -> None:
        if not _is_runtime_instance(outcome, RuntimeOutcome):
            raise ValueError("outcome must use the stable runtime vocabulary")
        if self._inner is not None:
            try:
                self._inner.set_outcome(outcome)
            except Exception:
                self._owner.record_dropped()
                self._inner = None

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object | None,
    ) -> Literal[False]:
        del exception_type, exception, traceback
        if self._inner is not None:
            try:
                self._inner.end()
            except Exception:
                self._owner.record_dropped()
            finally:
                self._inner = None
        return False


@dataclass(slots=True)
class _Histogram:
    count: int = 0
    total: float = 0.0
    buckets: list[int] = field(default_factory=lambda: [0] * len(_DURATION_BUCKETS))

    def observe(self, value: float) -> None:
        self.count += 1
        self.total += value
        for index, boundary in enumerate(_DURATION_BUCKETS):
            if value <= boundary:
                self.buckets[index] += 1


def _dimension(name: str, value: object) -> str:
    if not isinstance(value, str) or _DIMENSION.fullmatch(value) is None:
        raise ValueError(f"{name} must be a bounded low-cardinality identifier")
    return value


def _number(value: float) -> str:
    return format(value, ".12g")


def _labels(*, server: str, operation: str, tool: str, outcome: str) -> str:
    return f'operation="{operation}",outcome="{outcome}",server="{server}",tool="{tool}"'


class RuntimeObservability:
    def __init__(
        self,
        *,
        server_name: str,
        exporter: RuntimeExporter | None = None,
    ) -> None:
        if exporter is not None and not _is_runtime_instance(exporter, RuntimeExporter):
            raise ValueError("exporter must satisfy the runtime observation contract")
        self._server_name = _dimension("server_name", server_name)
        self._exporter = exporter
        self._requests: dict[tuple[RuntimeOperation, str, RuntimeOutcome], _Histogram] = {}
        self._server_in_flight = 0
        self._server_capacity: int | None = None
        self._tool_in_flight: dict[str, int] = {}
        self._tool_capacity: dict[str, int] = {}
        self._queue_depth = 0
        self._retries: dict[str, int] = {}
        self._limits: dict[tuple[RuntimeLimit, str], int] = {}
        self._cancellations: dict[str, int] = {}
        self._dropped_events = 0
        self._pending_drops = 0
        self._lock = Lock()

    @property
    def server_name(self) -> str:
        return self._server_name

    @property
    def dropped_events(self) -> int:
        with self._lock:
            return self._dropped_events

    def record_call(
        self,
        *,
        operation: RuntimeOperation,
        tool_name: str | None,
        outcome: RuntimeOutcome,
        duration_seconds: float,
    ) -> None:
        if not _is_runtime_instance(operation, RuntimeOperation) or not _is_runtime_instance(
            outcome, RuntimeOutcome
        ):
            raise ValueError("operation and outcome must use stable runtime vocabularies")
        tool = "none" if tool_name is None else _dimension("tool_name", tool_name)
        if (
            isinstance(duration_seconds, bool)
            or not (
                _is_runtime_instance(duration_seconds, int)
                or _is_runtime_instance(duration_seconds, float)
            )
            or not math.isfinite(duration_seconds)
            or not 0 <= duration_seconds <= _MAX_DURATION_SECONDS
        ):
            raise ValueError("duration_seconds must be finite and bounded")
        key = (operation, tool, outcome)
        with self._lock:
            histogram = self._requests.get(key)
            if histogram is None:
                if len(self._requests) >= _MAX_REQUEST_SERIES:
                    self._dropped_events += 1
                    return
                histogram = _Histogram()
                self._requests[key] = histogram
            histogram.observe(float(duration_seconds))
            if outcome is RuntimeOutcome.CANCELLATION:
                self._cancellations[tool] = self._cancellations.get(tool, 0) + 1
        self._export(
            lambda exporter: exporter.record_call(
                operation=operation,
                tool_name=tool_name,
                outcome=outcome,
                duration_seconds=float(duration_seconds),
            )
        )

    def record_retry(self, *, tool_name: str) -> None:
        tool = _dimension("tool_name", tool_name)
        with self._lock:
            if tool not in self._retries and len(self._retries) >= _MAX_TOOLS:
                self._dropped_events += 1
                return
            self._retries[tool] = self._retries.get(tool, 0) + 1
        self._export(lambda exporter: exporter.record_retry(tool_name=tool_name))

    def record_limit(self, *, tool_name: str | None, limit: RuntimeLimit) -> None:
        if not _is_runtime_instance(limit, RuntimeLimit):
            raise ValueError("limit must use the stable runtime vocabulary")
        tool = "none" if tool_name is None else _dimension("tool_name", tool_name)
        key = (limit, tool)
        with self._lock:
            if key not in self._limits and len(self._limits) >= len(RuntimeLimit) * (
                _MAX_TOOLS + 1
            ):
                self._dropped_events += 1
                return
            self._limits[key] = self._limits.get(key, 0) + 1
        self._export(lambda exporter: exporter.record_limit(tool_name=tool_name, limit=limit))

    def change_in_flight(
        self,
        *,
        tool_name: str,
        delta: int,
        server_capacity: int,
        tool_capacity: int,
    ) -> None:
        tool = _dimension("tool_name", tool_name)
        if delta not in {-1, 1} or isinstance(delta, bool):
            raise ValueError("delta must be exactly -1 or 1")
        if (
            isinstance(server_capacity, bool)
            or not _is_runtime_instance(server_capacity, int)
            or not 1 <= server_capacity <= 256
            or isinstance(tool_capacity, bool)
            or not _is_runtime_instance(tool_capacity, int)
            or not 1 <= tool_capacity <= 128
        ):
            raise ValueError("concurrency capacities must satisfy runtime hard maxima")
        with self._lock:
            if self._server_capacity is None:
                self._server_capacity = server_capacity
            elif self._server_capacity != server_capacity:
                self._dropped_events += 1
                return
            if tool not in self._tool_capacity:
                if len(self._tool_capacity) >= _MAX_TOOLS:
                    self._dropped_events += 1
                    return
                self._tool_capacity[tool] = tool_capacity
                self._tool_in_flight[tool] = 0
            elif self._tool_capacity[tool] != tool_capacity:
                self._dropped_events += 1
                return
            next_server = self._server_in_flight + delta
            next_tool = self._tool_in_flight[tool] + delta
            if not 0 <= next_server <= server_capacity or not 0 <= next_tool <= tool_capacity:
                self._dropped_events += 1
                return
            self._server_in_flight = next_server
            self._tool_in_flight[tool] = next_tool
        self._export(
            lambda exporter: exporter.change_in_flight(
                tool_name=tool_name,
                delta=delta,
                server_capacity=server_capacity,
                tool_capacity=tool_capacity,
            )
        )

    def emit_log(self, event: RuntimeLogEvent) -> None:
        if not _is_runtime_instance(event, RuntimeLogEvent):
            raise ValueError("event must satisfy the structured runtime log contract")
        self._export(lambda exporter: exporter.emit_log(event))

    def record_dropped(self, *, count: int = 1) -> None:
        if (
            isinstance(count, bool)
            or not _is_runtime_instance(count, int)
            or not 1 <= count <= _MAX_DROPPED_BATCH
        ):
            raise ValueError("dropped telemetry count must be a bounded positive integer")
        with self._lock:
            self._dropped_events += count
            self._pending_drops += count

    def start_span(self, spec: RuntimeSpanSpec) -> _SafeSpan:
        if not _is_runtime_instance(spec, RuntimeSpanSpec) or spec.server_name != self._server_name:
            raise ValueError("span must satisfy this runtime server contract")
        exporter = self._exporter
        if exporter is None:
            return _SafeSpan(self, None)
        try:
            span = exporter.start_span(spec)
            if not _is_runtime_instance(span, RuntimeSpan):
                raise ValueError("exporter returned an invalid runtime span")
            return _SafeSpan(self, span)
        except Exception:
            self.record_dropped()
            return _SafeSpan(self, None)

    def _export(self, operation: Callable[[RuntimeExporter], None]) -> None:
        exporter = self._exporter
        if exporter is None:
            return
        with self._lock:
            pending = self._pending_drops
        if pending:
            try:
                exporter.record_dropped(count=pending)
            except Exception:
                pass
            else:
                with self._lock:
                    self._pending_drops = max(0, self._pending_drops - pending)
        try:
            operation(exporter)
        except Exception:
            self.record_dropped()

    def render_prometheus(self) -> str:
        with self._lock:
            requests = tuple(
                (key, histogram.count, histogram.total, tuple(histogram.buckets))
                for key, histogram in sorted(
                    self._requests.items(),
                    key=lambda item: (item[0][0].value, item[0][1], item[0][2].value),
                )
            )
            server_in_flight = self._server_in_flight
            server_capacity = self._server_capacity or 0
            tool_saturation = tuple(
                (tool, self._tool_in_flight[tool], capacity)
                for tool, capacity in sorted(self._tool_capacity.items())
            )
            queue_depth = self._queue_depth
            retries = tuple(sorted(self._retries.items()))
            limits = tuple(
                (limit, tool, count)
                for (limit, tool), count in sorted(
                    self._limits.items(), key=lambda item: (item[0][0].value, item[0][1])
                )
            )
            cancellations = tuple(sorted(self._cancellations.items()))
            dropped_events = self._dropped_events

        lines = [
            "# TYPE mcp_server_request_count_total counter",
            "# TYPE mcp_server_request_duration_seconds histogram",
        ]
        for (operation, tool, outcome), count, total, buckets in requests:
            labels = _labels(
                server=self._server_name,
                operation=operation.value,
                tool=tool,
                outcome=outcome.value,
            )
            lines.append(f"mcp_server_request_count_total{{{labels}}} {count}")
            for boundary, bucket_count in zip(_DURATION_BUCKETS, buckets, strict=True):
                lines.append(
                    "mcp_server_request_duration_seconds_bucket"
                    f'{{{labels},le="{_number(boundary)}"}} {bucket_count}'
                )
            lines.extend(
                (
                    f'mcp_server_request_duration_seconds_bucket{{{labels},le="+Inf"}} {count}',
                    f"mcp_server_request_duration_seconds_count{{{labels}}} {count}",
                    f"mcp_server_request_duration_seconds_sum{{{labels}}} {_number(total)}",
                )
            )
        lines.extend(
            (
                "# TYPE mcp_server_in_flight gauge",
                f'mcp_server_in_flight{{server="{self._server_name}"}} {server_in_flight}',
                "# TYPE mcp_server_concurrency_limit gauge",
                f'mcp_server_concurrency_limit{{server="{self._server_name}"}} {server_capacity}',
                "# TYPE mcp_server_saturation_ratio gauge",
                "mcp_server_saturation_ratio"
                f'{{server="{self._server_name}"}} '
                f"{_number(server_in_flight / server_capacity if server_capacity else 0.0)}",
                "# TYPE mcp_server_queue_depth gauge",
                f'mcp_server_queue_depth{{server="{self._server_name}"}} {queue_depth}',
                "# TYPE mcp_tool_in_flight gauge",
                "# TYPE mcp_tool_concurrency_limit gauge",
            )
        )
        for tool, in_flight, capacity in tool_saturation:
            labels = f'server="{self._server_name}",tool="{tool}"'
            lines.append(f"mcp_tool_in_flight{{{labels}}} {in_flight}")
            lines.append(f"mcp_tool_concurrency_limit{{{labels}}} {capacity}")
        lines.extend(
            (
                "# TYPE mcp_tool_retry_count_total counter",
                "# TYPE mcp_server_limit_count_total counter",
                "# TYPE mcp_server_cancellation_count_total counter",
            )
        )
        for tool, count in retries:
            lines.append(
                f'mcp_tool_retry_count_total{{server="{self._server_name}",tool="{tool}"}} {count}'
            )
        for limit, tool, count in limits:
            lines.append(
                "mcp_server_limit_count_total"
                f'{{limit="{limit.value}",server="{self._server_name}",tool="{tool}"}} {count}'
            )
        for tool, count in cancellations:
            lines.append(
                "mcp_server_cancellation_count_total"
                f'{{server="{self._server_name}",tool="{tool}"}} {count}'
            )
        lines.extend(
            (
                "# TYPE mcp_telemetry_dropped_count_total counter",
                "mcp_telemetry_dropped_count_total"
                f'{{server="{self._server_name}"}} {dropped_events}',
            )
        )
        return "\n".join(lines) + "\n"
