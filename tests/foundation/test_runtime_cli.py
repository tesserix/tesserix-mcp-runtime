from __future__ import annotations

from collections.abc import Callable
from types import ModuleType

import pytest

from tesserix_mcp_runtime import __main__ as runtime_cli


class PublisherModule(ModuleType):
    run: Callable[[list[str]], int]


def test_root_cli_lazily_delegates_publisher_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delegated: list[list[str]] = []
    publisher = PublisherModule("tesserix_mcp_publisher.cli")

    def run(arguments: list[str]) -> int:
        delegated.append(arguments)
        return 6

    publisher.run = run
    imported: list[str] = []

    def import_module(name: str) -> ModuleType:
        imported.append(name)
        return publisher

    monkeypatch.setattr(runtime_cli, "import_module", import_module, raising=False)

    result = runtime_cli.main(["publish", "--manifest", "authoring.json"])

    assert result == 6
    assert imported == ["tesserix_mcp_publisher.cli"]
    assert delegated == [["publish", "--manifest", "authoring.json"]]


def test_root_cli_reports_an_actionable_missing_publisher_extra(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def import_module(name: str) -> ModuleType:
        raise ModuleNotFoundError(name=name)

    monkeypatch.setattr(runtime_cli, "import_module", import_module, raising=False)

    result = runtime_cli.main(["validate"])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "Publisher commands require the optional 'publisher' extra; "
        "install tesserix-mcp-runtime[publisher].\n"
    )
