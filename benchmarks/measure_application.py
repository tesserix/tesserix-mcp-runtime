from __future__ import annotations

import json
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from check_envelope import evaluate

TARGETS = Path(__file__).with_name("envelope-targets.json")
MEASURED_METRICS = {"idle_rss_mebibytes", "startup_seconds"}


class MeasurementError(RuntimeError):
    pass


def wait_until_ready(process: subprocess.Popen[str]) -> None:
    stdout = process.stdout
    if stdout is None:
        raise MeasurementError
    selector = selectors.DefaultSelector()
    try:
        selector.register(stdout, selectors.EVENT_READ)
        if not selector.select(timeout=10):
            raise MeasurementError
        line = stdout.readline()
        if not line or json.loads(line) != {"state": "ready"}:
            raise MeasurementError
    finally:
        selector.close()


def idle_rss_mebibytes(process: subprocess.Popen[str]) -> float:
    sampled = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(process.pid)],
        capture_output=True,
        check=False,
        text=True,
        timeout=5,
    )
    if sampled.returncode != 0:
        raise MeasurementError
    try:
        rss_kibibytes = int(sampled.stdout.strip())
    except ValueError as error:
        raise MeasurementError from error
    return rss_kibibytes / 1024


def selected_targets() -> list[dict[str, Any]]:
    document = json.loads(TARGETS.read_text(encoding="utf-8"))
    targets = [target for target in document["targets"] if target["metric"] in MEASURED_METRICS]
    if {target["metric"] for target in targets} != MEASURED_METRICS:
        raise MeasurementError
    return targets


def measure(python: Path, smoke: Path) -> dict[str, Any]:
    started = time.perf_counter()
    process = subprocess.Popen(
        [str(python), "-I", str(smoke), "success"],
        cwd=python.parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_until_ready(process)
        startup_seconds = time.perf_counter() - started
        idle_memory = idle_rss_mebibytes(process)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=10)
        if (
            process.returncode != 0
            or stderr
            or json.loads(stdout) != {"diagnostic": None, "exit_code": 0}
        ):
            raise MeasurementError
    finally:
        if process.poll() is None:
            process.terminate()
            process.communicate(timeout=10)
    observed: dict[str, object] = {
        "idle_rss_mebibytes": idle_memory,
        "startup_seconds": startup_seconds,
    }
    return evaluate(observed, selected_targets())


def main() -> int:
    if len(sys.argv) != 3:
        return 2
    try:
        report = measure(Path(sys.argv[1]), Path(sys.argv[2]))
    except (MeasurementError, OSError, subprocess.SubprocessError, json.JSONDecodeError):
        print(
            json.dumps({"code": "application_measurement_failed"}),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
