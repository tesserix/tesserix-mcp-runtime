from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_reconciliation_decision_is_evidence_based_and_keeps_repair_polling() -> None:
    decision = (ROOT / "docs" / "reconciliation-decision.md").read_text(encoding="utf-8")
    evidence = json.loads((ROOT / "benchmarks" / "reconciliation-observations.json").read_text())

    assert evidence["schema_version"] == 1
    assert evidence["baseline"]["activation_p99_seconds"] <= 120
    assert evidence["baseline"]["route_count"] >= 500
    for required in (
        "polling remains",
        "at-least-once",
        "out of order",
        "dead letter",
        "full reconciliation",
        "git revert --no-edit",
        "Registry outage",
    ):
        assert required in decision
