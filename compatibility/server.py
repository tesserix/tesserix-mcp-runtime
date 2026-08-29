# /// script
# requires-python = ">=3.12,<3.15"
# dependencies = ["mcp==2.1.1"]
# ///
from __future__ import annotations

import argparse

from mcp.server import MCPServer

server = MCPServer("tesserix-mcp-runtime-compatibility")


@server.tool()
def echo(text: str) -> str:
    """Return the supplied text."""
    return text


@server.tool()
def always_fails() -> str:
    """Return a deterministic tool failure."""
    raise ValueError("expected compatibility failure")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    arguments = parser.parse_args()
    server.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=arguments.port,
        streamable_http_path="/mcp",
    )


if __name__ == "__main__":
    main()
