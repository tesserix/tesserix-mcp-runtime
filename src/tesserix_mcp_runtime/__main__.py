"""Expose metadata and optional publication commands without starting a server."""

from __future__ import annotations

import argparse
import sys
from importlib import import_module
from typing import Protocol, cast

from tesserix_mcp_runtime import __version__

_PUBLISHER_COMMANDS = frozenset({"inspect", "manifest", "publish", "validate"})


class _PublisherCLI(Protocol):
    def run(self, argv: list[str]) -> int: ...


def _run_publisher(argv: list[str]) -> int:
    try:
        publisher = cast(_PublisherCLI, import_module("tesserix_mcp_publisher.cli"))
    except ModuleNotFoundError as error:
        if error.name not in {"tesserix_mcp_publisher", "tesserix_mcp_publisher.cli"}:
            raise
        print(
            "Publisher commands require the optional 'publisher' extra; "
            "install tesserix-mcp-runtime[publisher].",
            file=sys.stderr,
        )
        return 2
    return publisher.run(argv)


def main(argv: list[str] | None = None) -> int:
    """Run metadata commands or lazily delegate publication workflows."""
    arguments = sys.argv[1:] if argv is None else argv
    if arguments and arguments[0] in _PUBLISHER_COMMANDS:
        return _run_publisher(arguments)
    parser = argparse.ArgumentParser(prog="tesserix-mcp-runtime")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.parse_args(arguments)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
