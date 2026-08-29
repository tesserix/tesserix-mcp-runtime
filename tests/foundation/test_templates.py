from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
REQUIRED_EVIDENCE = ("tests", "security", "rollout", "rollback", "compatibility")


def test_pull_request_and_issue_templates_require_delivery_evidence() -> None:
    pull_request = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
    for evidence in REQUIRED_EVIDENCE:
        assert re.search(rf"- \[ \].*{evidence}", pull_request, re.IGNORECASE), evidence

    for filename in ("bug.yml", "feature.yml"):
        document = (ROOT / ".github" / "ISSUE_TEMPLATE" / filename).read_text(encoding="utf-8")
        for evidence in REQUIRED_EVIDENCE:
            marker = f"    id: {evidence}\n"
            start = document.find(marker)
            assert start >= 0, f"{filename}: missing {evidence} field"
            end = document.find("\n  - type:", start)
            field = document[start:] if end < 0 else document[start:end]
            assert "\n    validations:\n      required: true\n" in f"\n{field}\n"
