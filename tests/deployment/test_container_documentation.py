from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
ADR = ROOT / "docs" / "adr" / "0022-container-and-gitops-deployment.md"
GUIDE = ROOT / "docs" / "container-gitops.md"
REFERENCE_GUIDE = ROOT / "deploy" / "kubernetes" / "reference" / "README.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_container_gitops_decision_is_complete_and_indexed() -> None:
    decision = _read(ADR)
    index = _read(ROOT / "docs" / "adr" / "README.md")

    for section in (
        "## Status",
        "## Context and quantitative envelope",
        "## Threat model and trust boundaries",
        "## Decision",
        "## Dependency failure classification",
        "## Canary, promotion, and rollback",
        "## Cost and capacity",
        "## Alternatives considered",
        "## Consequences",
    ):
        assert section in decision

    for contract in (
        "99.9%",
        "50 calls/second",
        "200 calls/second",
        "Python 3.14",
        "one Git revert",
        "previous Registry route",
        "RTO",
        "RPO",
    ):
        assert contract in decision

    assert "[0022](0022-container-and-gitops-deployment.md)" in index


def test_operator_guide_records_build_security_and_rollout_evidence() -> None:
    guide = _read(GUIDE)
    root_readme = _read(ROOT / "README.md")

    for evidence in (
        "base-python-runtime-3.14:20260829@sha256:",
        "base-python-adk-3.14:20260829@sha256:",
        "66,975,933",
        "146,156,861",
        "66,342,726",
        "145,231,613",
        "10001:10001",
        "read-only root",
        "no runtime shell",
        "OpenTelemetry 1.42.1",
        "OpenTelemetry 1.44.0",
        "fresh Syft",
        "inherited layer SBOM",
        "git revert",
        "expand-contract",
        "local Kind",
    ):
        assert evidence in guide

    assert "[Container and GitOps deployment](docs/container-gitops.md)" in root_readme


def test_reference_package_fails_closed_until_gitops_adoption() -> None:
    guide = _read(REFERENCE_GUIDE)

    for warning in (
        "not deployable as checked in",
        "registry.invalid",
        "replace-in-tesserix-k8s",
        "replace-before-adoption.invalid",
        "Host and Origin",
        "workload identity",
        "backing API",
        "AgentGateway",
        "tesserix-k8s",
    ):
        assert warning in guide
