from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
VERIFIER = ROOT / "deploy" / "container" / "verify.py"


def test_verifier_starts_only_a_hardened_loopback_container() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(VERIFIER),
            "--print-run-command",
            "example.invalid/runtime@sha256:digest",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert tuple(json.loads(completed.stdout)) == (
        "docker",
        "run",
        "--detach",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=67108864",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--user",
        "10001:10001",
        "--publish",
        "127.0.0.1::8000",
        "--label",
        "tesserix.mcp-runtime.verification=true",
        "example.invalid/runtime@sha256:digest",
    )
