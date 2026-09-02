from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def _read(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_public_package_jobs_do_not_receive_private_repository_credentials() -> None:
    for name in ("containers.yml", "quality.yml", "security.yml"):
        assert "GO_PRIVATE_TOKEN" not in _read(name)


def test_private_cross_repository_reads_do_not_use_the_repository_token() -> None:
    compatibility = _read("compatibility.yml")
    journey = _read("release-journey.yml")
    release = _read("release.yml")

    assert compatibility.count("token: ${{ secrets.GO_PRIVATE_TOKEN }}") == 1
    assert "GH_TOKEN: ${{ secrets.GO_PRIVATE_TOKEN }}" in compatibility
    assert "GH_TOKEN: ${{ github.token }}" not in compatibility
    assert journey.count("token: ${{ secrets.GO_PRIVATE_TOKEN }}") == 1
    assert release.count("GO_PRIVATE_TOKEN: ${{ secrets.GO_PRIVATE_TOKEN }}") == 2
    assert "secrets: inherit" not in release
