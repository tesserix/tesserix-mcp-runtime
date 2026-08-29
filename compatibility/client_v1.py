from __future__ import annotations

import json
import os
from importlib.metadata import version

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent


async def exercise(expected_sdk: str, lane: str) -> None:
    actual_sdk = version("mcp")
    if actual_sdk != expected_sdk:
        raise RuntimeError(f"expected mcp {expected_sdk}, resolved {actual_sdk}")

    endpoint = os.environ["MCP_COMPAT_URL"]
    async with (
        streamable_http_client(endpoint) as (
            read_stream,
            write_stream,
            _,
        ),
        ClientSession(read_stream, write_stream) as session,
    ):
        initialized = await session.initialize()
        listed = await session.list_tools()
        names = {tool.name for tool in listed.tools}
        if names != {"always_fails", "echo"}:
            raise RuntimeError(f"unexpected tools: {sorted(names)}")

        succeeded = await session.call_tool("echo", {"text": "compatible"})
        if succeeded.isError:
            raise RuntimeError("echo returned an error")
        first = succeeded.content[0]
        if not isinstance(first, TextContent) or first.text != "compatible":
            raise RuntimeError("echo returned an unexpected result")

        failed = await session.call_tool("always_fails")
        if not failed.isError:
            raise RuntimeError("always_fails returned success")

        protocol = str(initialized.protocolVersion)

    print(
        json.dumps(
            {
                "closed": True,
                "lane": lane,
                "operations": [
                    "initialize",
                    "list_tools",
                    "call_tool",
                    "tool_error",
                    "close",
                ],
                "protocols": [protocol],
                "sdk": actual_sdk,
            },
            sort_keys=True,
        )
    )
