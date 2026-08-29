#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

TARGETS_PATH = Path(__file__).with_name("envelope-targets.json")


def evaluate(observed: dict[str, object], targets: list[dict[str, Any]]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    for target in targets:
        metric = target["metric"]
        if metric not in observed:
            raise ValueError(f"missing observation: {metric}")
        actual = observed[metric]
        if (
            isinstance(actual, bool)
            or not isinstance(actual, (int, float))
            or not math.isfinite(actual)
        ):
            raise ValueError(f"observation {metric} must be a finite number")
        expected = target["value"]
        passed = actual >= expected if target["operator"] == "minimum" else actual <= expected
        checks.append(
            {
                "actual": actual,
                "metric": metric,
                "operator": target["operator"],
                "passed": passed,
                "target": expected,
                "unit": target["unit"],
            }
        )
    return {"checks": checks, "passed": all(check["passed"] for check in checks)}


def main() -> int:
    results_path = Path(sys.argv[1])
    targets_document = json.loads(TARGETS_PATH.read_text(encoding="utf-8"))
    try:
        results_document = json.loads(results_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(
            json.dumps(
                {
                    "code": "invalid_measurements",
                    "message": "measurement document is not valid JSON",
                }
            ),
            file=sys.stderr,
        )
        return 2
    try:
        if not isinstance(results_document, dict) or not isinstance(
            results_document.get("observed"), dict
        ):
            raise ValueError("measurement document requires an observed object")
        report = evaluate(results_document["observed"], targets_document["targets"])
    except ValueError as error:
        print(
            json.dumps({"code": "invalid_measurements", "message": str(error)}),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
