from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
GUIDE = ROOT / "docs" / "observability.md"


def test_dashboard_and_alert_guide_covers_every_emitted_operator_signal() -> None:
    guide = GUIDE.read_text(encoding="utf-8")

    for metric in (
        "mcp_server_request_count_total",
        "mcp_server_request_duration_seconds_bucket",
        "mcp_server_in_flight",
        "mcp_server_concurrency_limit",
        "mcp_server_saturation_ratio",
        "mcp_server_queue_depth",
        "mcp_tool_retry_count_total",
        "mcp_server_limit_count_total",
        "mcp_server_cancellation_count_total",
        "mcp_telemetry_dropped_count_total",
    ):
        assert metric in guide

    for outcome in (
        "success",
        "policy_refusal",
        "tool_failure",
        "timeout",
        "cancellation",
        "overload",
        "dependency_outage",
    ):
        assert f"`{outcome}`" in guide

    for path in ("/startupz", "/livez", "/readyz", "/metrics"):
        assert f"`{path}`" in guide
    assert "14.4" in guide
    assert "6\u00d7" in guide
    assert "Owner" in guide
    assert "Runbook" in guide
