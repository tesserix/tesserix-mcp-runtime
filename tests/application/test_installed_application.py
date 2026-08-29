from __future__ import annotations

import json
import selectors
import signal
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
SMOKE = ROOT / "tests" / "fixtures" / "application_smoke.py"
MEASURE = ROOT / "benchmarks" / "measure_application.py"


@pytest.fixture(scope="module")
def installed_python(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("installed-application")
    distributions = root / "dist"
    environment = root / "venv"
    built = subprocess.run(
        ["uv", "build", "--wheel", "--offline", "--out-dir", str(distributions)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    created = subprocess.run(
        ["uv", "venv", "--python", sys.executable, str(environment)],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    assert created.returncode == 0, created.stderr
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    wheel = next(distributions.glob("*.whl"))
    installed = subprocess.run(
        [
            "uv",
            "pip",
            "install",
            "--offline",
            "--no-deps",
            "--python",
            str(python),
            str(wheel),
        ],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    assert installed.returncode == 0, installed.stderr
    return python


def test_installed_application_handles_sigterm_and_exits_zero(
    installed_python: Path,
) -> None:
    process = subprocess.Popen(
        [str(installed_python), "-I", str(SMOKE), "success"],
        cwd=installed_python.parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(timeout=10), "smoke application did not report readiness"
        ready = process.stdout.readline()
        if not ready:
            _, stderr = process.communicate(timeout=10)
            pytest.fail(f"smoke application exited before readiness: {stderr}")
        assert json.loads(ready) == {"state": "ready"}

        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
    finally:
        selector.close()
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=10)

    assert process.returncode == 0, stderr
    assert json.loads(stdout) == {"diagnostic": None, "exit_code": 0}
    assert stderr == ""


def test_installed_application_failure_is_nonzero_and_scrubbed(
    installed_python: Path,
) -> None:
    completed = subprocess.run(
        [str(installed_python), "-I", str(SMOKE), "fail-start"],
        cwd=installed_python.parent,
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 1
    assert json.loads(completed.stdout) == {
        "diagnostic": {
            "code": "startup_failed",
            "exception_type": "LifecycleFailure",
            "phase": "startup",
        },
        "exit_code": 1,
    }
    assert "startup-secret-must-not-escape" not in completed.stdout
    assert "startup-secret-must-not-escape" not in completed.stderr


def test_installed_application_meets_startup_and_idle_memory_envelope(
    installed_python: Path,
) -> None:
    completed = subprocess.run(
        [sys.executable, str(MEASURE), str(installed_python), str(SMOKE)],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["passed"] is True
    assert {check["metric"] for check in report["checks"]} == {
        "idle_rss_mebibytes",
        "startup_seconds",
    }
