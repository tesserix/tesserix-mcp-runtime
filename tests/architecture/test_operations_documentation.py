from __future__ import annotations

from pathlib import Path


def test_operations_runbook_covers_slos_alerts_failures_and_recovery() -> None:
    guide = (Path(__file__).parents[2] / "docs" / "operations.md").read_text(encoding="utf-8")

    for required in (
        "99.9%",
        "Registry outage",
        "Gateway outage",
        "Identity outage",
        "Backing API outage",
        "bad deployment",
        "RTO",
        "RPO",
        "14.4",
        "6x",
        "mcp_telemetry_dropped_count_total",
        "git revert --no-edit",
        "request ID",
        "trace ID",
        "PostgreSQL",
        "Temporal",
    ):
        assert required in guide
