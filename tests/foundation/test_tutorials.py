from __future__ import annotations

from pathlib import Path


def test_tutorial_covers_local_and_production_safe_paths() -> None:
    guide = (Path(__file__).parents[2] / "docs" / "tutorial.md").read_text(encoding="utf-8")

    for required in (
        "Five-minute local path",
        "Production path",
        "Python 3.14",
        "MCP SDK 1.34",
        "server.json",
        "dry-run",
        "activation",
        "semantic",
        "idempotency",
        "GitOps",
        "no-match",
        "retire",
        "examples/conformance-server",
        "compatibility/adk/test_bridge.py",
    ):
        assert required in guide
