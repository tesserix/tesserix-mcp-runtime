from __future__ import annotations

import json
import re
from typing import cast

import pytest
from tesserix_mcp_testkit import (
    ReliabilityCorrelationEvidence,
    ReliabilityLane,
    ReliabilityLoadKind,
    correlate_agentgateway_reliability_window,
)


def _client_report() -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "lane": "agentgateway",
            "route": "/gateway/runtime/mcp",
            "targets": {
                "sustained_requests_per_second": 50,
                "burst_requests_per_second": 200,
                "request_bytes": 60_000,
                "response_bytes": 500_000,
            },
            "loads": [
                {
                    "name": "agentgateway-sustained",
                    "lane": "agentgateway",
                    "kind": "sustained",
                    "request_bytes": 1_024,
                    "response_bytes": 4_096,
                    "completed": 2,
                    "successful": 2,
                    "outcomes": [{"outcome": "success", "count": 2}],
                    "duration_seconds": 0.02,
                    "throughput_requests_per_second": 100.0,
                    "latency": {
                        "p50_milliseconds": 4.0,
                        "p95_milliseconds": 8.0,
                        "p99_milliseconds": 9.0,
                        "maximum_milliseconds": 10.0,
                    },
                    "peak_client_concurrency": 2,
                    "maximum_queue_depth": 0,
                    "sample_digest": "sha256:" + "a" * 64,
                }
            ],
            "passed": True,
        },
        sort_keys=True,
    )


def _gateway_metrics(*, calls: int, requests: int, fast: int) -> str:
    labels = 'protocol="mcp",method="POST",status="200",reason="Upstream"'
    return "\n".join(
        (
            (
                "agentgateway_mcp_requests_total"
                f'{{method="tools/call",resource="reliability_probe"}} {calls}'
            ),
            f'agentgateway_request_duration_seconds_bucket{{{labels},le="0.005"}} {fast}',
            f'agentgateway_request_duration_seconds_bucket{{{labels},le="0.01"}} {requests}',
            f'agentgateway_request_duration_seconds_bucket{{{labels},le="+Inf"}} {requests}',
            f"agentgateway_request_duration_seconds_count{{{labels}}} {requests}",
            "",
        )
    )


def _runtime_metrics(*, calls: int, fast: int) -> str:
    labels = 'operation="tool_call",outcome="success",server="runtime",tool="reliability_probe"'
    return "\n".join(
        (
            f"mcp_server_request_count_total{{{labels}}} {calls}",
            f'mcp_server_request_duration_seconds_bucket{{{labels},le="0.005"}} {fast}',
            f'mcp_server_request_duration_seconds_bucket{{{labels},le="0.01"}} {calls}',
            f'mcp_server_request_duration_seconds_bucket{{{labels},le="+Inf"}} {calls}',
            f"mcp_server_request_duration_seconds_count{{{labels}}} {calls}",
            "",
        )
    )


def _runtime_spans() -> str:
    return "\n".join(
        (
            'TESSERIX_RELIABILITY_SPAN {"schema_version":1,"name":"mcp.tool.execution",'
            '"outcome":"success","duration_seconds":0.002}',
            'TESSERIX_RELIABILITY_SPAN {"schema_version":1,"name":"mcp.tool.execution",'
            '"outcome":"success","duration_seconds":0.004}',
            "",
        )
    )


def _resource_samples(*, container: str = "container", name: str = "runtime") -> str:
    return "\n".join(
        (
            json.dumps(
                {
                    "Container": container,
                    "Name": name,
                    "CPUPerc": "1.00%",
                    "MemUsage": "10.00MiB / 1GiB",
                }
            ),
            json.dumps(
                {
                    "Container": container,
                    "Name": name,
                    "CPUPerc": "2.00%",
                    "MemUsage": "12.00MiB / 1GiB",
                }
            ),
            "",
        )
    )


def _correlate(
    *,
    kind: ReliabilityLoadKind = ReliabilityLoadKind.SUSTAINED,
    client_report: str | None = None,
    gateway_metrics_before: str | None = None,
    gateway_metrics_after: str | None = None,
    runtime_metrics_before: str | None = None,
    runtime_metrics_after: str | None = None,
    runtime_spans: str | None = None,
    pod_resource_samples: str | None = None,
) -> ReliabilityCorrelationEvidence:
    return correlate_agentgateway_reliability_window(
        kind=kind,
        client_report=_client_report() if client_report is None else client_report,
        gateway_metrics_before=(
            _gateway_metrics(calls=10, requests=20, fast=10)
            if gateway_metrics_before is None
            else gateway_metrics_before
        ),
        gateway_metrics_after=(
            _gateway_metrics(calls=12, requests=24, fast=12)
            if gateway_metrics_after is None
            else gateway_metrics_after
        ),
        runtime_metrics_before=(
            _runtime_metrics(calls=10, fast=5)
            if runtime_metrics_before is None
            else runtime_metrics_before
        ),
        runtime_metrics_after=(
            _runtime_metrics(calls=12, fast=7)
            if runtime_metrics_after is None
            else runtime_metrics_after
        ),
        runtime_spans=_runtime_spans() if runtime_spans is None else runtime_spans,
        pod_resource_samples=(
            _resource_samples() if pod_resource_samples is None else pod_resource_samples
        ),
    )


def _client_document() -> dict[str, object]:
    return cast(dict[str, object], json.loads(_client_report()))


def _single_client_load(document: dict[str, object]) -> dict[str, object]:
    loads = document["loads"]
    assert isinstance(loads, list)
    untyped_loads = cast(list[object], loads)
    assert len(untyped_loads) == 1
    return cast(dict[str, object], untyped_loads[0])


def _resource_samples_with_first(**updates: object) -> str:
    samples = [
        cast(dict[str, object], json.loads(line)) for line in _resource_samples().splitlines()
    ]
    samples[0].update(updates)
    return "\n".join(json.dumps(sample, sort_keys=True) for sample in samples)


def _metric_value(source: str, line_index: int, value: str) -> str:
    lines = source.splitlines()
    prefix, _ = lines[line_index].rsplit(" ", 1)
    lines[line_index] = f"{prefix} {value}"
    return "\n".join(lines)


def test_correlator_emits_only_joined_aggregate_window_evidence() -> None:
    tenant_canary = "tenant-secret-canary"
    request_canary = "request-secret-canary"
    evidence = correlate_agentgateway_reliability_window(
        kind=ReliabilityLoadKind.SUSTAINED,
        client_report=_client_report(),
        gateway_metrics_before=_gateway_metrics(calls=10, requests=20, fast=10),
        gateway_metrics_after=_gateway_metrics(calls=12, requests=24, fast=12),
        runtime_metrics_before=_runtime_metrics(calls=10, fast=5),
        runtime_metrics_after=_runtime_metrics(calls=12, fast=7),
        runtime_spans=_runtime_spans(),
        pod_resource_samples=_resource_samples(
            container=request_canary,
            name=tenant_canary,
        ),
    )

    assert evidence.lane is ReliabilityLane.AGENTGATEWAY
    assert evidence.kind is ReliabilityLoadKind.SUSTAINED
    assert evidence.requests == evidence.client_samples == 2
    assert evidence.gateway_tool_calls == 2
    assert evidence.gateway_metric_samples == 4
    assert evidence.runtime_span_samples == evidence.runtime_metric_samples == 2
    assert evidence.pod_resource_samples == 2
    assert evidence.client_p99_milliseconds == 9.0
    assert evidence.gateway_p99_milliseconds == 10.0
    assert evidence.runtime_span_p99_milliseconds == 4.0
    assert evidence.runtime_metric_p99_milliseconds == 5.0
    assert evidence.pod_cpu_millicores_peak == 20.0
    assert evidence.pod_rss_mebibytes_peak == 12.0
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", evidence.window_digest)
    serialized = evidence.model_dump_json()
    assert tenant_canary not in serialized
    assert request_canary not in serialized


def test_correlator_rejects_a_boolean_client_schema_version() -> None:
    report = json.loads(_client_report())
    report["schema_version"] = True

    with pytest.raises(ValueError, match="client reliability report"):
        _correlate(client_report=json.dumps(report))


def test_correlator_rejects_a_boolean_runtime_span_schema_version() -> None:
    spans = _runtime_spans().replace('"schema_version":1', '"schema_version":true')

    with pytest.raises(ValueError, match="runtime reliability span"):
        _correlate(runtime_spans=spans)


def test_correlator_rounds_measured_span_latency_to_microsecond_precision() -> None:
    spans = _runtime_spans().replace("0.002", "0.001").replace("0.004", "0.00123456789")

    evidence = _correlate(runtime_spans=spans)

    assert evidence.runtime_span_p99_milliseconds == 1.234568


@pytest.mark.parametrize(
    ("source", "message"),
    (
        ("", "bounded UTF-8 text"),
        ("\n" * 100_000, "too many lines"),
        ('{"schema_version":1,"schema_version":1}', "JSON is invalid"),
        ("{", "JSON is invalid"),
        ("[]", "must be an object"),
    ),
)
def test_correlator_rejects_malformed_or_unbounded_source_documents(
    source: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _correlate(client_report=source)


def test_correlator_requires_the_stable_load_kind_vocabulary() -> None:
    with pytest.raises(TypeError, match="kind must use the reliability load vocabulary"):
        _correlate(kind=cast(ReliabilityLoadKind, "sustained"))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("lane", "direct_http"),
        ("route", "/mcp"),
        ("passed", False),
    ),
)
def test_correlator_rejects_client_reports_from_a_different_window(
    field: str,
    value: object,
) -> None:
    report = _client_document()
    report[field] = value

    with pytest.raises(ValueError, match="client reliability report"):
        _correlate(client_report=json.dumps(report))


def test_correlator_rejects_an_incomplete_client_report_shape() -> None:
    report = _client_document()
    del report["targets"]

    with pytest.raises(ValueError, match="invalid shape"):
        _correlate(client_report=json.dumps(report))


@pytest.mark.parametrize("loads", ({}, [1]), ids=("not-a-list", "non-object-item"))
def test_correlator_rejects_invalid_client_load_collections(loads: object) -> None:
    report = _client_document()
    report["loads"] = loads

    with pytest.raises(ValueError, match="invalid load evidence"):
        _correlate(client_report=json.dumps(report))


def test_correlator_requires_exactly_one_requested_client_load() -> None:
    report = _client_document()
    load = _single_client_load(report)
    report["loads"] = [load, dict(load)]

    with pytest.raises(ValueError, match="one requested load window"):
        _correlate(client_report=json.dumps(report))


def test_correlator_rejects_a_client_load_with_an_invalid_schema() -> None:
    report = _client_document()
    _single_client_load(report)["duration_seconds"] = "fast"

    with pytest.raises(ValueError, match="load evidence is invalid"):
        _correlate(client_report=json.dumps(report))


def test_correlator_rejects_a_valid_load_from_another_lane() -> None:
    report = _client_document()
    _single_client_load(report)["lane"] = "direct_http"

    with pytest.raises(ValueError, match="not a successful AgentGateway window"):
        _correlate(client_report=json.dumps(report))


def test_correlator_ignores_comments_unrelated_series_and_non_span_logs() -> None:
    gateway_before = "\n".join(
        (
            "",
            "# HELP ignored synthetic help",
            "unrelated_metric 1",
            "agentgateway_mcp_requests_total 999",
            _gateway_metrics(calls=10, requests=20, fast=10),
        )
    )
    evidence = _correlate(
        gateway_metrics_before=gateway_before,
        runtime_spans="ordinary sanitized log\n" + _runtime_spans(),
        pod_resource_samples="\n" + _resource_samples(),
    )

    assert evidence.requests == 2


@pytest.mark.parametrize(
    ("source", "message"),
    (
        (
            _gateway_metrics(calls=10, requests=20, fast=10).replace(
                'resource="reliability_probe"',
                "resource=unquoted",
                1,
            ),
            "labels are invalid",
        ),
        (
            _gateway_metrics(calls=10, requests=20, fast=10).replace(
                'resource="reliability_probe"',
                'method="tools/call",resource="reliability_probe"',
                1,
            ),
            "labels must be unique",
        ),
        (
            _gateway_metrics(calls=10, requests=20, fast=10).replace(
                "reliability_probe",
                "bad\\x",
                1,
            ),
            "label encoding is invalid",
        ),
        (
            _gateway_metrics(calls=10, requests=20, fast=10).replace(
                "reliability_probe",
                "x" * 2_049,
                1,
            ),
            "label value is invalid",
        ),
        (
            _gateway_metrics(calls=10, requests=20, fast=10).replace(
                ',resource="reliability_probe"',
                ';resource="reliability_probe"',
                1,
            ),
            "labels are invalid",
        ),
    ),
    ids=("unquoted", "duplicate", "encoding", "bounded", "separator"),
)
def test_correlator_rejects_malformed_prometheus_labels(
    source: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _correlate(gateway_metrics_before=source)


def test_correlator_rejects_malformed_unbounded_and_duplicate_metric_series() -> None:
    baseline = _gateway_metrics(calls=10, requests=20, fast=10)
    counter = baseline.splitlines()[0]
    cases = (
        (baseline.replace(" 10", " invalid", 1), "metric is invalid"),
        (baseline.replace(" 10", " 1e309", 1), "finite and bounded"),
        (baseline + "\n" + counter, "series must be unique"),
    )

    for source, message in cases:
        with pytest.raises(ValueError, match=message):
            _correlate(gateway_metrics_before=source)


@pytest.mark.parametrize(
    "after",
    (
        _gateway_metrics(calls=9, requests=24, fast=12),
        _gateway_metrics(calls=12, requests=24, fast=12).replace(" 12", " 12.5", 1),
    ),
    ids=("decreasing", "fractional"),
)
def test_correlator_rejects_invalid_counter_deltas(after: str) -> None:
    with pytest.raises(ValueError, match="counter delta is invalid"):
        _correlate(gateway_metrics_after=after)


@pytest.mark.parametrize(
    ("before", "after", "message"),
    (
        (
            _gateway_metrics(calls=10, requests=20, fast=10).replace(',le="0.005"', "", 1),
            _gateway_metrics(calls=12, requests=24, fast=12),
            "missing its boundary",
        ),
        (
            _gateway_metrics(calls=10, requests=20, fast=10).replace('le="0.005"', 'le="bad"', 1),
            _gateway_metrics(calls=12, requests=24, fast=12),
            "boundary is invalid",
        ),
        (
            _gateway_metrics(calls=10, requests=20, fast=10).replace('le="0.005"', 'le="0"', 1),
            _gateway_metrics(calls=12, requests=24, fast=12),
            "boundary is invalid",
        ),
        (
            "\n".join(
                line
                for line in _gateway_metrics(calls=10, requests=20, fast=10).splitlines()
                if 'le="+Inf"' not in line
            ),
            "\n".join(
                line
                for line in _gateway_metrics(calls=12, requests=24, fast=12).splitlines()
                if 'le="+Inf"' not in line
            ),
            "must contain \\+Inf",
        ),
        (
            _gateway_metrics(calls=10, requests=20, fast=10),
            _gateway_metrics(calls=12, requests=24, fast=15),
            "histogram delta is invalid",
        ),
        (
            _gateway_metrics(calls=10, requests=20, fast=10),
            _metric_value(_gateway_metrics(calls=12, requests=24, fast=12), 4, "25"),
            "does not cover its count",
        ),
        (
            _gateway_metrics(calls=10, requests=20, fast=10),
            _metric_value(
                _metric_value(_gateway_metrics(calls=12, requests=24, fast=12), 1, "10"),
                2,
                "20",
            ),
            "p99 exceeds the finite buckets",
        ),
    ),
    ids=(
        "missing-boundary",
        "text-boundary",
        "nonpositive-boundary",
        "missing-infinity",
        "nonmonotonic",
        "count-mismatch",
        "infinite-p99",
    ),
)
def test_correlator_rejects_invalid_prometheus_histograms(
    before: str,
    after: str,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _correlate(gateway_metrics_before=before, gateway_metrics_after=after)


def test_correlator_rejects_runtime_counter_and_histogram_disagreement() -> None:
    after = _metric_value(_runtime_metrics(calls=12, fast=7), 0, "13")

    with pytest.raises(ValueError, match="metrics disagree on sample count"):
        _correlate(runtime_metrics_after=after)


@pytest.mark.parametrize(
    "spans",
    (
        "ordinary sanitized log",
        _runtime_spans().replace("duration_seconds", 'extra":1,"duration_seconds', 1),
        _runtime_spans().replace("mcp.tool.execution", "other.span", 1),
        _runtime_spans().replace('"outcome":"success"', '"outcome":"failure"', 1),
        _runtime_spans().replace("0.002", "false", 1),
        _runtime_spans().replace("0.002", "0", 1),
        _runtime_spans().replace("0.002", "301", 1),
    ),
    ids=("missing", "shape", "name", "outcome", "boolean", "zero", "bounded"),
)
def test_correlator_rejects_missing_or_invalid_runtime_spans(spans: str) -> None:
    with pytest.raises(ValueError, match="runtime reliability span"):
        _correlate(runtime_spans=spans)


@pytest.mark.parametrize(
    "source",
    (
        _resource_samples().splitlines()[0],
        _resource_samples_with_first(CPUPerc=1),
        _resource_samples_with_first(CPUPerc="01%"),
        _resource_samples_with_first(MemUsage=1),
        _resource_samples_with_first(MemUsage="invalid"),
        _resource_samples_with_first(MemUsage="12MiB / invalid"),
        _resource_samples_with_first(CPUPerc="100001.00%"),
        _resource_samples_with_first(MemUsage="5GiB / 6GiB"),
        _resource_samples_with_first(MemUsage="0MiB / 1GiB"),
    ),
    ids=(
        "one-sample",
        "cpu-type",
        "cpu-format",
        "rss-type",
        "rss-format",
        "rss-limit-format",
        "cpu-bound",
        "rss-bound",
        "rss-zero",
    ),
)
def test_correlator_rejects_invalid_or_insufficient_pod_samples(source: str) -> None:
    with pytest.raises(ValueError, match=r"pod (CPU|RSS|resource|resources)"):
        _correlate(pod_resource_samples=source)
