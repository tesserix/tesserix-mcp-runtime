"""Print package metadata without starting a server."""

from __future__ import annotations

import argparse

from tesserix_mcp_runtime import __version__


def main(argv: list[str] | None = None) -> int:
    """Run the metadata-only command."""
    parser = argparse.ArgumentParser(prog="tesserix-mcp-runtime")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
