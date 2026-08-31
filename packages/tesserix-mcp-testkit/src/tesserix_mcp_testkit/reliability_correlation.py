from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, cast

from pydantic import ValidationError

from tesserix_mcp_testkit.reliability import (
    ReliabilityCorrelationEvidence,
    ReliabilityLane,
    ReliabilityLoadEvidence,
    ReliabilityLoadKind,
)

_MAX_SOURCE_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_LINES = 100_000
_MAX_PROMETHEUS_VALUE = 1_000_000_000_000
_SPAN_PREFIX = "TESSERIX_RELIABILITY_SPAN "
_METRIC_LINE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{(?P<labels>.*)\})?[ \t]+"
    r"(?P<value>[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)"
    r"(?:[ \t]+[0-9]+)?$"
)
_LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"\s*')
_CPU_PERCENT = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?%$")
_MEMORY_USAGE = re.compile(
    r"^(?P<value>(?:0|[1-9][0-9]*)(?:\.[0-9]+)?)"
    r"(?P<unit>B|KiB|MiB|GiB)[ \t]+/[ \t]+"
    r"(?P<limit_value>(?:0|[1-9][0-9]*)(?:\.[0-9]+)?)"
    r"(?P<limit_unit>B|KiB|MiB|GiB)$"
)

_GATEWAY_METRICS = frozenset(
    {
        "agentgateway_mcp_requests_total",
        "agentgateway_request_duration_seconds_bucket",
        "agentgateway_request_duration_seconds_count",
    }
)
_RUNTIME_METRICS = frozenset(
    {
        "mcp_server_request_count_total",
        "mcp_server_request_duration_seconds_bucket",
        "mcp_server_request_duration_seconds_count",
    }
)


@dataclass(frozen=True, slots=True)
class _PrometheusSample:
    name: str
    labels: tuple[tuple[str, str], ...]
    value: float

    def has_labels(self, required: dict[str, str]) -> bool:
        available = dict(self.labels)
        return all(available.get(name) == value for name, value in required.items())


def _bounded_text(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= _MAX_SOURCE_BYTES:
        raise ValueError("reliability correlation source must be bounded UTF-8 text")
    if value.count("\n") + 1 > _MAX_SOURCE_LINES:
        raise ValueError("reliability correlation source has too many lines")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("reliability correlation JSON contains duplicate keys")
        result[name] = value
    return result


def _json_object(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise ValueError("reliability correlation JSON is invalid") from None
    if not isinstance(parsed, dict):
        raise ValueError("reliability correlation JSON must be an object")
    result: dict[str, Any] = {}
    untyped = cast(dict[object, object], parsed)
    for name, item in untyped.items():
        if not isinstance(name, str):
            raise ValueError("reliability correlation JSON keys must be text")
        result[name] = item
    return result


def _load_kind(value: object) -> ReliabilityLoadKind:
    if not isinstance(value, ReliabilityLoadKind):
        raise TypeError("kind must use the reliability load vocabulary")
    return value


def _client_load(report_text: str, kind: ReliabilityLoadKind) -> ReliabilityLoadEvidence:
    report = _json_object(_bounded_text(report_text))
    if set(report) != {"schema_version", "lane", "route", "targets", "loads", "passed"}:
        raise ValueError("client reliability report has an invalid shape")
    schema_version = report.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != 1
        or report.get("lane") != ReliabilityLane.AGENTGATEWAY.value
        or report.get("route") != "/gateway/runtime/mcp"
        or report.get("passed") is not True
    ):
        raise ValueError("client reliability report is not passing AgentGateway evidence")
    targets_value = report.get("targets")
    expected_targets = {
        "sustained_requests_per_second": 50,
        "burst_requests_per_second": 200,
        "request_bytes": 60_000,
        "response_bytes": 500_000,
    }
    if not isinstance(targets_value, dict):
        raise ValueError("client reliability report does not carry qualification targets")
    untyped_targets = cast(dict[object, object], targets_value)
    if not all(isinstance(name, str) for name in untyped_targets):
        raise ValueError("client reliability report does not carry qualification targets")
    targets = {str(name): value for name, value in untyped_targets.items()}
    if set(targets) != set(expected_targets) or any(
        isinstance(targets[name], bool)
        or not isinstance(targets[name], int)
        or targets[name] != expected
        for name, expected in expected_targets.items()
    ):
        raise ValueError("client reliability report does not carry qualification targets")
    loads_value = report.get("loads")
    if not isinstance(loads_value, list):
        raise ValueError("client reliability report has invalid load evidence")
    loads = cast(list[object], loads_value)
    if not 1 <= len(loads) <= len(ReliabilityLoadKind):
        raise ValueError("client reliability report has invalid load evidence")
    matches: list[dict[str, Any]] = []
    for item in loads:
        if not isinstance(item, dict):
            raise ValueError("client reliability report has invalid load evidence")
        untyped_item = cast(dict[object, object], item)
        if not all(isinstance(name, str) for name in untyped_item):
            raise ValueError("client reliability report has invalid load evidence")
        load_item = {str(name): value for name, value in untyped_item.items()}
        if load_item.get("kind") == kind.value:
            matches.append(load_item)
    if len(matches) != 1:
        raise ValueError("client reliability report must contain one requested load window")
    try:
        load = ReliabilityLoadEvidence.model_validate_json(
            json.dumps(matches[0], separators=(",", ":"), sort_keys=True)
        )
    except (TypeError, ValidationError, ValueError):
        raise ValueError("client reliability load evidence is invalid") from None
    if (
        load.lane is not ReliabilityLane.AGENTGATEWAY
        or load.kind is not kind
        or load.successful != load.completed
    ):
        raise ValueError("client reliability load is not a successful AgentGateway window")
    return load


def _labels(value: str | None) -> tuple[tuple[str, str], ...]:
    if value is None or value == "":
        return ()
    labels: dict[str, str] = {}
    position = 0
    while position < len(value):
        match = _LABEL.match(value, position)
        if match is None:
            raise ValueError("Prometheus labels are invalid")
        name, encoded = match.groups()
        if name in labels:
            raise ValueError("Prometheus labels must be unique")
        try:
            decoded = json.loads(f'"{encoded}"')
        except json.JSONDecodeError:
            raise ValueError("Prometheus label encoding is invalid") from None
        if not isinstance(decoded, str) or len(decoded) > 2_048:
            raise ValueError("Prometheus label value is invalid")
        labels[name] = decoded
        position = match.end()
        if position == len(value):
            break
        if value[position] != ",":
            raise ValueError("Prometheus labels are invalid")
        position += 1
    return tuple(sorted(labels.items()))


def _prometheus_samples(
    source: str,
    *,
    metric_names: frozenset[str],
) -> tuple[_PrometheusSample, ...]:
    text = _bounded_text(source)
    samples: list[_PrometheusSample] = []
    keys: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name = line.split("{", 1)[0].split(None, 1)[0]
        if name not in metric_names:
            continue
        match = _METRIC_LINE.fullmatch(line)
        if match is None:
            raise ValueError("Prometheus reliability metric is invalid")
        labels = _labels(match.group("labels"))
        value = float(match.group("value"))
        if not math.isfinite(value) or not 0 <= value <= _MAX_PROMETHEUS_VALUE:
            raise ValueError("Prometheus reliability metric must be finite and bounded")
        key = (name, labels)
        if key in keys:
            raise ValueError("Prometheus reliability metric series must be unique")
        keys.add(key)
        samples.append(_PrometheusSample(name=name, labels=labels, value=value))
    return tuple(samples)


def _metric_total(
    samples: tuple[_PrometheusSample, ...],
    *,
    name: str,
    labels: dict[str, str],
) -> float:
    return sum(
        sample.value for sample in samples if sample.name == name and sample.has_labels(labels)
    )


def _counter_delta(
    before: tuple[_PrometheusSample, ...],
    after: tuple[_PrometheusSample, ...],
    *,
    name: str,
    labels: dict[str, str],
) -> int:
    baseline = _metric_total(before, name=name, labels=labels)
    final = _metric_total(after, name=name, labels=labels)
    delta = final - baseline
    if not baseline.is_integer() or not final.is_integer() or not 1 <= delta <= 100_000:
        raise ValueError("Prometheus reliability counter delta is invalid")
    return int(delta)


def _histogram_buckets(
    samples: tuple[_PrometheusSample, ...],
    *,
    name: str,
    labels: dict[str, str],
) -> dict[float, float]:
    buckets: defaultdict[float, float] = defaultdict(float)
    for sample in samples:
        if sample.name != name or not sample.has_labels(labels):
            continue
        boundary = dict(sample.labels).get("le")
        if boundary is None:
            raise ValueError("Prometheus histogram bucket is missing its boundary")
        try:
            parsed_boundary = math.inf if boundary == "+Inf" else float(boundary)
        except ValueError:
            raise ValueError("Prometheus histogram boundary is invalid") from None
        if parsed_boundary <= 0 or math.isnan(parsed_boundary):
            raise ValueError("Prometheus histogram boundary is invalid")
        buckets[parsed_boundary] += sample.value
    return dict(buckets)


def _histogram_delta_p99(
    before: tuple[_PrometheusSample, ...],
    after: tuple[_PrometheusSample, ...],
    *,
    bucket_name: str,
    count_name: str,
    labels: dict[str, str],
) -> tuple[int, float]:
    count = _counter_delta(before, after, name=count_name, labels=labels)
    baseline = _histogram_buckets(before, name=bucket_name, labels=labels)
    final = _histogram_buckets(after, name=bucket_name, labels=labels)
    boundaries = sorted(set(baseline) | set(final))
    if not boundaries or boundaries[-1] != math.inf:
        raise ValueError("Prometheus reliability histogram must contain +Inf")
    deltas: list[tuple[float, int]] = []
    previous = 0
    for boundary in boundaries:
        delta = final.get(boundary, 0.0) - baseline.get(boundary, 0.0)
        if not delta.is_integer() or not previous <= delta <= count:
            raise ValueError("Prometheus reliability histogram delta is invalid")
        previous = int(delta)
        deltas.append((boundary, previous))
    if previous != count:
        raise ValueError("Prometheus reliability histogram does not cover its count")
    rank = math.ceil(count * 0.99)
    for boundary, cumulative in deltas:
        if cumulative >= rank:
            if not math.isfinite(boundary):
                raise ValueError("Prometheus reliability p99 exceeds the finite buckets")
            return count, boundary * 1_000
    raise ValueError("Prometheus reliability histogram cannot produce p99")


def _runtime_span_p99(source: str) -> tuple[int, float]:
    durations: list[float] = []
    for line in _bounded_text(source).splitlines():
        if not line.startswith(_SPAN_PREFIX):
            continue
        sample = _json_object(line.removeprefix(_SPAN_PREFIX))
        if set(sample) != {"schema_version", "name", "outcome", "duration_seconds"}:
            raise ValueError("runtime reliability span has an invalid shape")
        duration = sample.get("duration_seconds")
        schema_version = sample.get("schema_version")
        if (
            isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or schema_version != 1
            or sample.get("name") != "mcp.tool.execution"
            or sample.get("outcome") != "success"
            or isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or not 0 < duration <= 300
        ):
            raise ValueError("runtime reliability span is invalid")
        durations.append(float(duration))
    if not 1 <= len(durations) <= 100_000:
        raise ValueError("runtime reliability spans must contain bounded samples")
    durations.sort()
    rank = math.ceil(len(durations) * 0.99)
    return len(durations), round(durations[rank - 1] * 1_000, 6)


def _pod_resources(source: str) -> tuple[int, float, float]:
    rss_samples: list[float] = []
    cpu_samples: list[float] = []
    factors = {"B": 1 / (1024 * 1024), "KiB": 1 / 1024, "MiB": 1.0, "GiB": 1024.0}
    for line in _bounded_text(source).splitlines():
        if not line:
            continue
        sample = _json_object(line)
        cpu = sample.get("CPUPerc")
        memory = sample.get("MemUsage")
        if not isinstance(cpu, str) or _CPU_PERCENT.fullmatch(cpu) is None:
            raise ValueError("pod CPU resource sample is invalid")
        memory_match = _MEMORY_USAGE.fullmatch(memory) if isinstance(memory, str) else None
        if memory_match is None:
            raise ValueError("pod RSS resource sample is invalid")
        cpu_millicores = float(cpu.removesuffix("%")) * 10
        rss_mebibytes = float(memory_match.group("value")) * factors[memory_match.group("unit")]
        limit_mebibytes = (
            float(memory_match.group("limit_value")) * factors[memory_match.group("limit_unit")]
        )
        if (
            not math.isfinite(cpu_millicores)
            or not 0 <= cpu_millicores <= 1_000_000
            or not math.isfinite(rss_mebibytes)
            or not 0 < rss_mebibytes <= 4_096
            or not math.isfinite(limit_mebibytes)
            or rss_mebibytes > limit_mebibytes
        ):
            raise ValueError("pod resource sample is outside reliability bounds")
        cpu_samples.append(cpu_millicores)
        rss_samples.append(rss_mebibytes)
    if not 2 <= len(cpu_samples) <= 100_000:
        raise ValueError("pod resources must contain at least two bounded samples")
    return len(cpu_samples), round(max(cpu_samples), 3), round(max(rss_samples), 3)


def _digest_sources(sources: dict[str, str], evidence: dict[str, object]) -> str:
    source_digests = {
        name: hashlib.sha256(value.encode("utf-8")).hexdigest()
        for name, value in sorted(sources.items())
    }
    encoded = json.dumps(
        {"schema_version": 1, "sources": source_digests, "evidence": evidence},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def correlate_agentgateway_reliability_window(
    *,
    kind: ReliabilityLoadKind,
    client_report: str,
    gateway_metrics_before: str,
    gateway_metrics_after: str,
    runtime_metrics_before: str,
    runtime_metrics_after: str,
    runtime_spans: str,
    pod_resource_samples: str,
) -> ReliabilityCorrelationEvidence:
    kind = _load_kind(kind)
    load = _client_load(client_report, kind)
    gateway_before = _prometheus_samples(
        gateway_metrics_before,
        metric_names=_GATEWAY_METRICS,
    )
    gateway_after = _prometheus_samples(
        gateway_metrics_after,
        metric_names=_GATEWAY_METRICS,
    )
    runtime_before = _prometheus_samples(
        runtime_metrics_before,
        metric_names=_RUNTIME_METRICS,
    )
    runtime_after = _prometheus_samples(
        runtime_metrics_after,
        metric_names=_RUNTIME_METRICS,
    )
    gateway_tool_calls = _counter_delta(
        gateway_before,
        gateway_after,
        name="agentgateway_mcp_requests_total",
        labels={"method": "tools/call", "resource": "reliability_probe"},
    )
    gateway_metric_samples, gateway_p99 = _histogram_delta_p99(
        gateway_before,
        gateway_after,
        bucket_name="agentgateway_request_duration_seconds_bucket",
        count_name="agentgateway_request_duration_seconds_count",
        labels={"protocol": "mcp", "method": "POST"},
    )
    runtime_metric_samples = _counter_delta(
        runtime_before,
        runtime_after,
        name="mcp_server_request_count_total",
        labels={"operation": "tool_call", "tool": "reliability_probe"},
    )
    runtime_histogram_samples, runtime_metric_p99 = _histogram_delta_p99(
        runtime_before,
        runtime_after,
        bucket_name="mcp_server_request_duration_seconds_bucket",
        count_name="mcp_server_request_duration_seconds_count",
        labels={"operation": "tool_call", "tool": "reliability_probe"},
    )
    if runtime_histogram_samples != runtime_metric_samples:
        raise ValueError("runtime reliability metrics disagree on sample count")
    runtime_span_samples, runtime_span_p99 = _runtime_span_p99(runtime_spans)
    pod_samples, cpu_peak, rss_peak = _pod_resources(pod_resource_samples)
    aggregates: dict[str, object] = {
        "kind": kind.value,
        "requests": load.completed,
        "client_sample_digest": load.sample_digest,
        "client_p99_milliseconds": load.latency.p99_milliseconds,
        "gateway_tool_calls": gateway_tool_calls,
        "gateway_metric_samples": gateway_metric_samples,
        "gateway_p99_milliseconds": gateway_p99,
        "runtime_span_samples": runtime_span_samples,
        "runtime_span_p99_milliseconds": runtime_span_p99,
        "runtime_metric_samples": runtime_metric_samples,
        "runtime_metric_p99_milliseconds": runtime_metric_p99,
        "pod_resource_samples": pod_samples,
        "pod_cpu_millicores_peak": cpu_peak,
        "pod_rss_mebibytes_peak": rss_peak,
    }
    sources = {
        "client_report": client_report,
        "gateway_metrics_before": gateway_metrics_before,
        "gateway_metrics_after": gateway_metrics_after,
        "runtime_metrics_before": runtime_metrics_before,
        "runtime_metrics_after": runtime_metrics_after,
        "runtime_spans": runtime_spans,
        "pod_resource_samples": pod_resource_samples,
    }
    return ReliabilityCorrelationEvidence(
        lane=ReliabilityLane.AGENTGATEWAY,
        kind=kind,
        window_digest=_digest_sources(sources, aggregates),
        requests=load.completed,
        client_samples=load.completed,
        gateway_tool_calls=gateway_tool_calls,
        gateway_metric_samples=gateway_metric_samples,
        runtime_span_samples=runtime_span_samples,
        runtime_metric_samples=runtime_metric_samples,
        pod_resource_samples=pod_samples,
        client_p99_milliseconds=load.latency.p99_milliseconds,
        gateway_p99_milliseconds=gateway_p99,
        runtime_span_p99_milliseconds=runtime_span_p99,
        runtime_metric_p99_milliseconds=runtime_metric_p99,
        pod_cpu_millicores_peak=cpu_peak,
        pod_rss_mebibytes_peak=rss_peak,
    )


__all__ = ["correlate_agentgateway_reliability_window"]
