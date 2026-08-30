from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import cast

_MAX_REPORT_BYTES = 16_777_216
_MAX_RESULTS = 1_024
_MAX_FINDINGS = 16_384
_MAX_TEXT = 1_024
_SEVERITIES = frozenset({"HIGH", "CRITICAL"})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _read_report(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Trivy report must be a regular file")
    size = path.stat().st_size
    if not 1 <= size <= _MAX_REPORT_BYTES:
        raise ValueError("Trivy report size is invalid")
    try:
        value = json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("Trivy report is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Trivy report must be an object")
    document = cast(dict[str, object], value)
    results_value = document.get("Results")
    if not isinstance(results_value, list):
        raise ValueError("Trivy report results are invalid")
    results = cast(list[object], results_value)
    if not 1 <= len(results) <= _MAX_RESULTS:
        raise ValueError("Trivy report results are invalid")
    return document


def _required_text(finding: dict[str, object], name: str) -> str:
    value = finding.get(name)
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_TEXT:
        raise ValueError("Trivy report finding is invalid")
    return value


def evaluate_trivy_report(path: Path) -> dict[str, object]:
    document = _read_report(path)
    results = cast(list[object], document["Results"])
    critical = 0
    high = 0
    fixable = 0
    unfixed = 0
    observed = 0
    for result_value in results:
        if not isinstance(result_value, dict):
            raise ValueError("Trivy report result is invalid")
        result = cast(dict[str, object], result_value)
        findings_value = result.get("Vulnerabilities")
        if findings_value is None:
            continue
        if not isinstance(findings_value, list):
            raise ValueError("Trivy report vulnerabilities are invalid")
        for finding_value in cast(list[object], findings_value):
            observed += 1
            if observed > _MAX_FINDINGS or not isinstance(finding_value, dict):
                raise ValueError("Trivy report finding count is invalid")
            finding = cast(dict[str, object], finding_value)
            _required_text(finding, "VulnerabilityID")
            _required_text(finding, "PkgName")
            _required_text(finding, "InstalledVersion")
            severity = _required_text(finding, "Severity")
            if severity not in _SEVERITIES:
                raise ValueError("Trivy report finding severity is invalid")
            if severity == "CRITICAL":
                critical += 1
            else:
                high += 1
            fixed_version = finding.get("FixedVersion")
            if fixed_version is not None and not isinstance(fixed_version, str):
                raise ValueError("Trivy report fixed version is invalid")
            if fixed_version:
                fixable += 1
            else:
                unfixed += 1
    if fixable:
        raise ValueError(f"Trivy report contains {fixable} fixable HIGH/CRITICAL findings")
    return {
        "schema_version": 1,
        "critical_findings": critical,
        "high_findings": high,
        "fixable_findings": fixable,
        "unfixed_findings": unfixed,
        "trivy_report_sha256": _sha256(path),
        "passed": True,
    }


def _write_report(path: Path, document: dict[str, object]) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()) or not path.parent.is_dir():
        raise ValueError("Trivy policy report target is invalid")
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    document = evaluate_trivy_report(arguments.report)
    _write_report(arguments.output, document)
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["evaluate_trivy_report", "main"]
