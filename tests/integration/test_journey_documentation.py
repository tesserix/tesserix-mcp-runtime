from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
ADR = ROOT / "docs" / "adr" / "0023-release-integration-journey.md"
SECURITY_ADR = ROOT / "docs" / "adr" / "0025-adversarial-security-evidence.md"
SECURITY_GUIDE = ROOT / "docs" / "security-verification.md"


def test_journey_adr_records_verified_compatibility_and_equivalence_limits() -> None:
    document = ADR.read_text(encoding="utf-8")
    normalized = " ".join(document.split())

    assert "Python 3.14.7" in normalized
    assert "MCP SDK 2.1.1" in normalized
    assert "MCP SDK 1.34 is not" in normalized
    assert "`internal: false`" in normalized
    assert "loopback-only" in normalized
    assert "re-resolves the published port" in normalized
    assert "Standalone mode does not prove Kubernetes controller adoption" in normalized
    assert "tesserix/tesserix-k8s#758" in normalized


def test_security_verification_contract_is_documented_at_every_operator_boundary() -> None:
    guide = SECURITY_GUIDE.read_text(encoding="utf-8")
    decision = SECURITY_ADR.read_text(encoding="utf-8")
    normalized = " ".join((guide + decision).split())

    assert "51 required cases" in normalized
    assert "12 named sinks" in normalized
    assert "require_independent_review=True" in normalized
    assert "MCP SDK 1.34 does not exist" in normalized
    assert "verifier dependency" in normalized

    references = (
        ROOT / "README.md",
        ROOT / "docs" / "adr" / "README.md",
        ROOT / "docs" / "conformance.md",
        ROOT / "docs" / "releasing.md",
        ROOT / "packages" / "tesserix-mcp-testkit" / "README.md",
    )
    for reference in references:
        assert "security-verification" in reference.read_text(encoding="utf-8")
