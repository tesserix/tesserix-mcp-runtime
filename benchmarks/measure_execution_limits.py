from __future__ import annotations

import argparse
import gc
import json
import math
import platform
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass

from tesserix_mcp_runtime import ExecutionLimits, JsonValue
from tesserix_mcp_runtime.execution import validate_json_value


@dataclass(frozen=True, slots=True)
class _Case:
    name: str
    configured_ceiling: int
    observed_units: int
    value: JsonValue
    maximum_bytes: int


def _encoded_size(value: JsonValue) -> int:
    return len(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _exact_byte_value(size: int) -> JsonValue:
    empty_size = _encoded_size({"value": ""})
    return {"value": "x" * (size - empty_size)}


def _exact_depth_value(depth: int) -> JsonValue:
    value: JsonValue = 0
    for _ in range(depth - 1):
        value = {"value": value}
    return value


def _cases(limits: ExecutionLimits) -> tuple[_Case, ...]:
    input_value = _exact_byte_value(limits.max_input_bytes)
    result_value = _exact_byte_value(limits.max_result_bytes)
    depth_value = _exact_depth_value(limits.max_json_depth)
    properties_value: dict[str, JsonValue] = {
        f"field_{index}": 0 for index in range(limits.max_object_properties)
    }
    array_value: list[JsonValue] = list(range(limits.max_array_items))
    node_value: list[JsonValue] = []
    for _ in range(limits.max_array_items - 1):
        inner: list[JsonValue] = [0, 0, 0]
        node_value.append(inner)
    node_value.append([0, 0])
    return (
        _Case(
            "input_bytes",
            limits.max_input_bytes,
            _encoded_size(input_value),
            input_value,
            limits.max_input_bytes,
        ),
        _Case(
            "result_bytes",
            limits.max_result_bytes,
            _encoded_size(result_value),
            result_value,
            limits.max_result_bytes,
        ),
        _Case(
            "json_depth",
            limits.max_json_depth,
            limits.max_json_depth,
            depth_value,
            limits.max_input_bytes,
        ),
        _Case(
            "object_properties",
            limits.max_object_properties,
            len(properties_value),
            properties_value,
            limits.max_input_bytes,
        ),
        _Case(
            "array_items",
            limits.max_array_items,
            len(array_value),
            array_value,
            limits.max_input_bytes,
        ),
        _Case(
            "json_nodes",
            limits.max_json_nodes,
            1 + limits.max_array_items + (limits.max_array_items - 1) * 3 + 2,
            node_value,
            limits.max_input_bytes,
        ),
    )


def _percentile(samples: list[int], quantile: float) -> float:
    ordered = sorted(samples)
    index = max(0, math.ceil(len(ordered) * quantile) - 1)
    return ordered[index] / 1_000_000


def _measure(case: _Case, limits: ExecutionLimits, samples: int) -> dict[str, object]:
    validate_json_value(case.value, limits=limits, maximum_bytes=case.maximum_bytes)
    durations: list[int] = []
    for _ in range(samples):
        started = time.perf_counter_ns()
        validate_json_value(case.value, limits=limits, maximum_bytes=case.maximum_bytes)
        durations.append(time.perf_counter_ns() - started)

    gc.collect()
    tracemalloc.start()
    baseline, _ = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    validate_json_value(case.value, limits=limits, maximum_bytes=case.maximum_bytes)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "name": case.name,
        "configured_ceiling": case.configured_ceiling,
        "observed_units": case.observed_units,
        "encoded_bytes": _encoded_size(case.value),
        "latency_milliseconds": {
            "p50": _percentile(durations, 0.50),
            "p99": _percentile(durations, 0.99),
            "maximum": max(durations) / 1_000_000,
        },
        "peak_temporary_bytes": max(0, peak - baseline),
    }


def _sample_count(value: str) -> int:
    samples = int(value)
    if not 1 <= samples <= 10_000:
        raise argparse.ArgumentTypeError("samples must be between 1 and 10000")
    return samples


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=_sample_count, default=50)
    arguments = parser.parse_args()
    limits = ExecutionLimits()
    report = {
        "schema_version": 1,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "samples_per_case": arguments.samples,
        "limits": asdict(limits),
        "cases": [_measure(case, limits, arguments.samples) for case in _cases(limits)],
    }
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
