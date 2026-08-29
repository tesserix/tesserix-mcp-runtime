from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
IMMUTABLE_ACTION = re.compile(r"^\s*uses:\s+[^\s@]+@([0-9a-f]{40})(?:\s+#.*)?$")


def test_workflows_are_pinned_and_least_privilege() -> None:
    workflows = {
        path.name: path.read_text(encoding="utf-8") for path in WORKFLOW_ROOT.glob("*.yml")
    }

    assert {
        "codeql.yml",
        "compatibility.yml",
        "dependency-review.yml",
        "quality.yml",
        "security.yml",
    } <= workflows.keys()

    for name, document in workflows.items():
        assert "pull_request_target:" not in document, name
        assert "\npermissions:\n  contents: read\n" in document, name
        assert "timeout-minutes:" in document, name

        action_lines = [line for line in document.splitlines() if "uses:" in line]
        assert action_lines, name
        for line in action_lines:
            assert IMMUTABLE_ACTION.match(line), f"{name}: action is not pinned: {line.strip()}"

        if "actions/checkout@" in document:
            assert "persist-credentials: false" in document, name
