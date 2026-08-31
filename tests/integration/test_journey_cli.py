from __future__ import annotations

import json
import re
from pathlib import Path

from integration.journey.run import run


def _arguments(tmp_path: Path, *, run_id: str) -> list[str]:
    return [
        "--runtime-image",
        "tesserix-mcp-runtime:journey",
        "--registry-image",
        "tesserix-agentic-registry:6921474",
        "--runtime-artifact-digest",
        "sha256:" + "a" * 64,
        "--package-digest",
        "sha256:" + "b" * 64,
        "--source-revision",
        "c" * 40,
        "--output-dir",
        str(tmp_path),
        "--compose-standalone",
        str(tmp_path / "missing-compose"),
        "--run-id",
        run_id,
    ]


def test_cli_bounds_maximum_run_id_before_compose_execution(
    tmp_path: Path,
) -> None:
    run_id = "r" * 128

    assert run(_arguments(tmp_path, run_id=run_id)) == 1

    failure = json.loads((tmp_path / "journey-failure.json").read_bytes())
    assert failure == {
        "code": "command_unavailable",
        "created_at": failure["created_at"],
        "run_id": run_id,
        "status": "failed",
    }
    assert not (tmp_path / "failure-logs").exists()


def test_cli_configuration_failure_still_writes_canonical_artifact(
    tmp_path: Path,
) -> None:
    assert run(_arguments(tmp_path, run_id="invalid run id")) == 1

    failure_path = tmp_path / "journey-failure.json"
    failure = json.loads(failure_path.read_bytes())
    assert failure == {
        "code": "configuration_invalid",
        "created_at": failure["created_at"],
        "run_id": failure["run_id"],
        "status": "failed",
    }
    assert re.fullmatch(r"invalid-[0-9a-f]{16}", failure["run_id"])
    assert b"invalid run id" not in failure_path.read_bytes()
    assert failure_path.read_bytes().endswith(b"\n")
