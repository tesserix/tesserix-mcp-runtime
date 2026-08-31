from __future__ import annotations

from compatibility.server import reliability_probe


def test_reliability_probe_accepts_large_synthetic_boundaries_without_echoing_input() -> None:
    request = "r" * 60_000

    result = reliability_probe(request, 500_000)

    assert result.request_bytes == 60_000
    assert result.response_bytes == 500_000
    assert len(result.chunks) == 8
    assert sum(len(chunk) for chunk in result.chunks) == 500_000
    assert all(request not in chunk for chunk in result.chunks)
