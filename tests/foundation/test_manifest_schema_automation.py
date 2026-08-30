from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
CHECKER = ROOT / "architecture" / "update_manifest_schema.py"
WORKFLOW = ROOT / ".github" / "workflows" / "manifest-schema-update.yml"
COMPATIBILITY_WORKFLOW = ROOT / ".github" / "workflows" / "manifest-compatibility.yml"


def test_checked_in_schema_provenance_verifies_offline() -> None:
    completed = subprocess.run(
        [sys.executable, str(CHECKER), "--verify"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == (
        "official MCP schema 2025-12-11 verified "
        "(registry v1.8.1 @ f52dc8525a441a3abf5fedc9912152d95af5aab1)\n"
    )
    assert completed.stderr == ""


def test_schema_update_workflow_opens_a_reviewed_pinned_pull_request() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "schedule:" in workflow
    assert "python architecture/update_manifest_schema.py --update" in workflow
    assert "python architecture/update_manifest_schema.py --verify" in workflow
    assert "peter-evans/create-pull-request@5f6978faf089d4d20b00c7766989d076bb2fc7f1" in workflow
    assert "contents: write" in workflow
    assert "pull-requests: write" in workflow
    assert "chore: update official MCP server schema" in workflow


def test_manifest_compatibility_workflow_uses_only_no_write_validators() -> None:
    workflow = COMPATIBILITY_WORKFLOW.read_text(encoding="utf-8")

    assert "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e" in workflow
    assert (
        "github.com/modelcontextprotocol/registry/cmd/publisher@f52dc8525a441a3abf5fedc9912152d95af5aab1"
        in workflow
    )
    assert (
        "github.com/tesserix/agentic-registry/cmd/agentic@6921474591b6c59e89025370c310c7f85859246f"
        in workflow
    )
    assert '"packages/tesserix-mcp-publisher/**"' in workflow
    assert " validate " in workflow
    assert " publish " not in workflow
    assert " apply " not in workflow
    assert " push " not in workflow
    assert "contents: read" in workflow
