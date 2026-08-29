from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_runtime_license_scan_follows_requested_dependency_extras() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "security" / "check_licenses.py")],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert {"cffi", "cryptography", "pycparser"} <= set(report["packages"])


def test_forbidden_license_reports_the_dependency_path(tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "allowed_licenses": ["Apache-2.0", "MIT"],
                "license_overrides": {},
            }
        ),
        encoding="utf-8",
    )
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "root": "runtime",
                "packages": [
                    {
                        "dependencies": ["safe-library"],
                        "license": "Apache-2.0",
                        "name": "runtime",
                        "version": "1.0.0",
                    },
                    {
                        "dependencies": ["copyleft-library"],
                        "license": "MIT",
                        "name": "safe-library",
                        "version": "2.0.0",
                    },
                    {
                        "dependencies": [],
                        "license": "GPL-3.0-only",
                        "name": "copyleft-library",
                        "version": "3.0.0",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "security" / "check_licenses.py"),
            "--inventory",
            str(inventory),
            "--policy",
            str(policy),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 1
    assert "GPL-3.0-only" in completed.stderr
    assert "runtime -> safe-library -> copyleft-library" in completed.stderr
