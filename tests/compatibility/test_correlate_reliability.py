from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from compatibility.correlate_reliability import main, read_reliability_source


def _write_sources(root: Path) -> dict[str, Path]:
    load = {
        "name": "agentgateway-sustained",
        "lane": "agentgateway",
        "kind": "sustained",
        "request_bytes": 1_024,
        "response_bytes": 4_096,
        "completed": 1,
        "successful": 1,
        "outcomes": [{"outcome": "success", "count": 1}],
        "duration_seconds": 0.01,
        "throughput_requests_per_second": 100.0,
        "latency": {
            "p50_milliseconds": 4.0,
            "p95_milliseconds": 4.0,
            "p99_milliseconds": 4.0,
            "maximum_milliseconds": 4.0,
        },
        "peak_client_concurrency": 1,
        "maximum_queue_depth": 0,
        "sample_digest": "sha256:" + "a" * 64,
    }
    client: dict[str, object] = {
        "schema_version": 1,
        "lane": "agentgateway",
        "route": "/gateway/runtime/mcp",
        "targets": {
            "sustained_requests_per_second": 50,
            "burst_requests_per_second": 200,
            "request_bytes": 60_000,
            "response_bytes": 500_000,
        },
        "loads": [load],
        "passed": True,
    }
    gateway_labels = 'protocol="mcp",method="POST",status="200",reason="Upstream"'
    runtime_labels = (
        'operation="tool_call",outcome="success",server="runtime",tool="reliability_probe"'
    )
    contents = {
        "client": json.dumps(client),
        "gateway-before": "\n".join(
            (
                "agentgateway_mcp_requests_total"
                '{method="tools/call",resource="reliability_probe"} 1',
                f'agentgateway_request_duration_seconds_bucket{{{gateway_labels},le="0.01"}} 2',
                f'agentgateway_request_duration_seconds_bucket{{{gateway_labels},le="+Inf"}} 2',
                f"agentgateway_request_duration_seconds_count{{{gateway_labels}}} 2",
            )
        ),
        "gateway-after": "\n".join(
            (
                "agentgateway_mcp_requests_total"
                '{method="tools/call",resource="reliability_probe"} 2',
                f'agentgateway_request_duration_seconds_bucket{{{gateway_labels},le="0.01"}} 4',
                f'agentgateway_request_duration_seconds_bucket{{{gateway_labels},le="+Inf"}} 4',
                f"agentgateway_request_duration_seconds_count{{{gateway_labels}}} 4",
            )
        ),
        "runtime-before": "\n".join(
            (
                f"mcp_server_request_count_total{{{runtime_labels}}} 1",
                f'mcp_server_request_duration_seconds_bucket{{{runtime_labels},le="0.005"}} 1',
                f'mcp_server_request_duration_seconds_bucket{{{runtime_labels},le="+Inf"}} 1',
                f"mcp_server_request_duration_seconds_count{{{runtime_labels}}} 1",
            )
        ),
        "runtime-after": "\n".join(
            (
                f"mcp_server_request_count_total{{{runtime_labels}}} 2",
                f'mcp_server_request_duration_seconds_bucket{{{runtime_labels},le="0.005"}} 2',
                f'mcp_server_request_duration_seconds_bucket{{{runtime_labels},le="+Inf"}} 2',
                f"mcp_server_request_duration_seconds_count{{{runtime_labels}}} 2",
            )
        ),
        "runtime-spans": (
            'TESSERIX_RELIABILITY_SPAN {"schema_version":1,"name":"mcp.tool.execution",'
            '"outcome":"success","duration_seconds":0.003}'
        ),
        "pod-resources": "\n".join(
            (
                '{"CPUPerc":"1.00%","MemUsage":"10.00MiB / 1GiB"}',
                '{"CPUPerc":"2.00%","MemUsage":"12.00MiB / 1GiB"}',
            )
        ),
    }
    paths: dict[str, Path] = {}
    for name, content in contents.items():
        path = root / f"{name}.txt"
        path.write_text(content + "\n", encoding="utf-8")
        paths[name] = path
    return paths


def _arguments(sources: dict[str, Path], output: Path) -> list[str]:
    return [
        "correlate_reliability.py",
        "--kind",
        "sustained",
        "--client-report",
        str(sources["client"]),
        "--gateway-before",
        str(sources["gateway-before"]),
        "--gateway-after",
        str(sources["gateway-after"]),
        "--runtime-before",
        str(sources["runtime-before"]),
        "--runtime-after",
        str(sources["runtime-after"]),
        "--runtime-spans",
        str(sources["runtime-spans"]),
        "--pod-resources",
        str(sources["pod-resources"]),
        "--output",
        str(output),
    ]


def test_correlation_cli_writes_one_sanitized_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = _write_sources(tmp_path)
    output = tmp_path / "correlation.json"
    monkeypatch.setattr(sys, "argv", _arguments(sources, output))

    assert main() == 0
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["kind"] == "sustained"
    assert evidence["requests"] == 1
    assert evidence["gateway_tool_calls"] == 1
    assert evidence["runtime_span_samples"] == 1
    assert set(evidence) == {
        "lane",
        "kind",
        "window_digest",
        "requests",
        "client_samples",
        "gateway_tool_calls",
        "gateway_metric_samples",
        "runtime_span_samples",
        "runtime_metric_samples",
        "pod_resource_samples",
        "client_p99_milliseconds",
        "gateway_p99_milliseconds",
        "runtime_span_p99_milliseconds",
        "runtime_metric_p99_milliseconds",
        "pod_cpu_millicores_peak",
        "pod_rss_mebibytes_peak",
    }


def test_correlation_source_rejects_a_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.txt"
    attacker = tmp_path / "attacker.txt"
    source.write_text("safe", encoding="utf-8")
    attacker.write_text("evil", encoding="utf-8")
    original_open = os.open

    def swap_then_open(path: str | os.PathLike[str], flags: int) -> int:
        if Path(path) == source:
            source.unlink()
            source.symlink_to(attacker)
        return original_open(path, flags)

    monkeypatch.setattr(os, "open", swap_then_open)

    with pytest.raises(ValueError, match="source"):
        read_reliability_source(source)


def test_correlation_cli_never_follows_an_output_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = _write_sources(tmp_path)
    victim = tmp_path / "victim.json"
    victim.write_text("unchanged\n", encoding="utf-8")
    output = tmp_path / "correlation.json"
    output.symlink_to(victim)
    monkeypatch.setattr(sys, "argv", _arguments(sources, output))

    assert main() == 2
    assert victim.read_text(encoding="utf-8") == "unchanged\n"
