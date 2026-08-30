from __future__ import annotations

import argparse
import asyncio
import json
import math
import platform
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    IdempotencyRequirement,
    InvocationResult,
    JsonValue,
    RuntimeLimit,
    RuntimeLogEvent,
    RuntimeObservability,
    RuntimeOperation,
    RuntimeOutcome,
    RuntimeSpan,
    RuntimeSpanSpec,
    ScrubbedError,
    SystemClock,
    ToolCatalog,
    ToolDefinition,
    ToolEffect,
    ToolMetadata,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport

_TARGET_P99_MILLISECONDS = 15.0
_EVENTS_PER_SAMPLE = 7


@dataclass(frozen=True, slots=True)
class _Input:
    value: str


class _NoOpSpan:
    @property
    def trace_id(self) -> str | None:
        return None

    def activate(self) -> None:
        pass

    def set_outcome(self, outcome: RuntimeOutcome) -> None:
        del outcome

    def end(self) -> None:
        pass


class _CountingExporter:
    def __init__(self) -> None:
        self.events = 0

    def record_call(
        self,
        *,
        operation: RuntimeOperation,
        tool_name: str | None,
        outcome: RuntimeOutcome,
        duration_seconds: float,
    ) -> None:
        del operation, tool_name, outcome, duration_seconds
        self.events += 1

    def change_in_flight(
        self,
        *,
        tool_name: str,
        delta: int,
        server_capacity: int,
        tool_capacity: int,
    ) -> None:
        del tool_name, delta, server_capacity, tool_capacity
        self.events += 1

    def record_retry(self, *, tool_name: str) -> None:
        del tool_name
        self.events += 1

    def record_limit(self, *, tool_name: str | None, limit: RuntimeLimit) -> None:
        del tool_name, limit
        self.events += 1

    def record_dropped(self, *, count: int) -> None:
        self.events += count

    def emit_log(self, event: RuntimeLogEvent) -> None:
        del event
        self.events += 1

    def start_span(self, spec: RuntimeSpanSpec) -> RuntimeSpan:
        del spec
        self.events += 1
        return _NoOpSpan()


class _AllowAllAuthorizer:
    async def authorize(
        self,
        *,
        tool: ToolDefinition[Any, Any],
        arguments: Mapping[str, JsonValue],
        context: CallContext,
    ) -> None:
        del tool, arguments, context


class _NoOpTelemetry:
    def emit(self, event: ScrubbedError) -> None:
        del event


class _NoOpTool:
    metadata = ToolMetadata(
        name="benchmark.noop",
        title="Benchmark no-op",
        description="Return one bounded synthetic value.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("benchmark:invoke",),
    )
    input_schema: Mapping[str, JsonValue] = {
        "type": "object",
        "properties": {"value": {"type": "string", "maxLength": 16}},
        "required": ["value"],
        "additionalProperties": False,
    }
    output_schema = input_schema

    async def handler(self, input_model: _Input, *, context: CallContext) -> _Input:
        del context
        return input_model

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> _Input:
        value = arguments.get("value")
        if not isinstance(value, str):
            raise ValueError
        return _Input(value)

    def serialize_output(self, output_model: _Input) -> JsonValue:
        return {"value": output_model.value}


def _bounded_count(value: str) -> int:
    count = int(value)
    if not 1 <= count <= 100_000:
        raise argparse.ArgumentTypeError("count must be between 1 and 100000")
    return count


def _bounded_warmup(value: str) -> int:
    count = int(value)
    if not 0 <= count <= 10_000:
        raise argparse.ArgumentTypeError("warmup must be between 0 and 10000")
    return count


def _percentile(samples: list[int], quantile: float) -> float:
    ordered = sorted(samples)
    index = max(0, math.ceil(len(ordered) * quantile) - 1)
    return ordered[index] / 1_000_000


async def _measure(samples: int, warmup: int) -> dict[str, object]:
    exporter = _CountingExporter()
    observability = RuntimeObservability(server_name="benchmark-mcp", exporter=exporter)
    transport = InProcessTransport()
    application = Application(
        catalog=ToolCatalog([_NoOpTool()]),
        authorizer=_AllowAllAuthorizer(),
        transport=transport,
        telemetry=_NoOpTelemetry(),
        limits=ApplicationLimits(drain_timeout=1.0),
        clock=SystemClock(),
        observability=observability,
    )
    context = CallContext(
        identity=AuthenticatedIdentity(
            tenant="benchmark-tenant",
            subject="benchmark-subject",
            issuer="https://identity.example.invalid",
            scopes=("benchmark:invoke",),
        ),
        request_id="benchmark-request",
        run_id="benchmark-run",
    )
    expected = InvocationResult.success({"value": "ok"})
    durations: list[int] = []
    await application.start()
    try:
        for _ in range(warmup):
            if (
                await transport.invoke("benchmark.noop", {"value": "ok"}, context=context)
                != expected
            ):
                raise RuntimeError("benchmark warmup failed")
        baseline_events = exporter.events
        for _ in range(samples):
            started = time.perf_counter_ns()
            result = await transport.invoke("benchmark.noop", {"value": "ok"}, context=context)
            durations.append(time.perf_counter_ns() - started)
            if result != expected:
                raise RuntimeError("benchmark invocation failed")
        observed_events = exporter.events - baseline_events
    finally:
        await application.drain()
        await application.stop()
    if observed_events != samples * _EVENTS_PER_SAMPLE:
        raise RuntimeError("benchmark did not exercise the complete observation path")
    p99 = _percentile(durations, 0.99)
    return {
        "schema_version": 1,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "case": "successful_tool_call_observability",
        "samples": samples,
        "warmup": warmup,
        "events_per_sample": _EVENTS_PER_SAMPLE,
        "target_p99_milliseconds": _TARGET_P99_MILLISECONDS,
        "latency_milliseconds": {
            "p50": _percentile(durations, 0.50),
            "p99": p99,
            "maximum": max(durations) / 1_000_000,
        },
        "passed": p99 < _TARGET_P99_MILLISECONDS,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=_bounded_count, default=1_000)
    parser.add_argument("--warmup", type=_bounded_warmup, default=100)
    arguments = parser.parse_args()
    try:
        report = asyncio.run(_measure(arguments.samples, arguments.warmup))
    except RuntimeError:
        json.dump({"code": "observability_measurement_failed"}, sys.stderr)
        sys.stderr.write("\n")
        return 2
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
