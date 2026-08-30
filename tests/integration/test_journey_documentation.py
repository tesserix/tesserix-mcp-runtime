from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
ADR = ROOT / "docs" / "adr" / "0023-release-integration-journey.md"


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
