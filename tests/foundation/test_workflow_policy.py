from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
IMMUTABLE_ACTION = re.compile(r"^\s*uses:\s+[^\s@]+@([0-9a-f]{40})(?:\s+#.*)?$")
LOCAL_REUSABLE_WORKFLOW = re.compile(
    r"^\s*uses:\s+\./\.github/workflows/[a-z0-9][a-z0-9._-]*\.yml\s*$"
)


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
            assert IMMUTABLE_ACTION.match(line) or LOCAL_REUSABLE_WORKFLOW.match(line), (
                f"{name}: action is not pinned: {line.strip()}"
            )

        if "actions/checkout@" in document:
            assert "persist-credentials: false" in document, name


def test_adk_compatibility_verifies_provenance_before_the_optional_install() -> None:
    workflow = (WORKFLOW_ROOT / "compatibility.yml").read_text(encoding="utf-8")

    assert "repository_dispatch:\n    types: [adk-release]" in workflow
    assert "attestations: read" in workflow
    attestation = workflow.index("gh attestation verify")
    compatibility = workflow.index(
        "uv run --isolated --frozen --extra adk --extra testkit pytest",
    )
    assert attestation < compatibility
    assert "eec6afc695518971f44723e520cf43f0997110d013ce4733f8d6d30ec96b8bdb" in workflow
    assert "find_spec('tesserix_adk') is None" in workflow
