from __future__ import annotations

import json
from pathlib import Path

import pytest
from release.vulnerabilities import evaluate_trivy_report


def _write_report(path: Path, vulnerabilities: list[dict[str, object]]) -> None:
    path.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactName": "runtime-image.tar",
                "Results": [
                    {
                        "Target": "runtime-image.tar (debian 13.6)",
                        "Class": "os-pkgs",
                        "Type": "debian",
                        "Vulnerabilities": vulnerabilities,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_trivy_policy_retains_and_counts_unfixed_high_and_critical_findings(
    tmp_path: Path,
) -> None:
    report = tmp_path / "trivy.json"
    _write_report(
        report,
        [
            {
                "VulnerabilityID": "CVE-2026-10001",
                "PkgName": "curl",
                "InstalledVersion": "1.0",
                "FixedVersion": "",
                "Severity": "HIGH",
            },
            {
                "VulnerabilityID": "CVE-2026-10002",
                "PkgName": "perl-base",
                "InstalledVersion": "2.0",
                "FixedVersion": None,
                "Severity": "CRITICAL",
            },
        ],
    )

    result = evaluate_trivy_report(report)

    assert result == {
        "critical_findings": 1,
        "fixable_findings": 0,
        "high_findings": 1,
        "passed": True,
        "schema_version": 1,
        "trivy_report_sha256": result["trivy_report_sha256"],
        "unfixed_findings": 2,
    }
    assert len(str(result["trivy_report_sha256"])) == 64


def test_trivy_policy_rejects_any_high_or_critical_finding_with_a_fix(
    tmp_path: Path,
) -> None:
    report = tmp_path / "trivy.json"
    _write_report(
        report,
        [
            {
                "VulnerabilityID": "CVE-2026-10003",
                "PkgName": "example",
                "InstalledVersion": "1.0",
                "FixedVersion": "1.1",
                "Severity": "HIGH",
            }
        ],
    )

    with pytest.raises(ValueError, match="fixable HIGH/CRITICAL"):
        evaluate_trivy_report(report)


def test_trivy_policy_rejects_malformed_or_unbounded_evidence(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"Results": null}', encoding="utf-8")

    with pytest.raises(ValueError, match="Trivy report"):
        evaluate_trivy_report(malformed)

    malformed.write_bytes(b"x" * 16_777_217)
    with pytest.raises(ValueError, match="Trivy report"):
        evaluate_trivy_report(malformed)
