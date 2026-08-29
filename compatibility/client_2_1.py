# /// script
# requires-python = ">=3.12,<3.15"
# dependencies = ["mcp==2.1.1"]
# ///
from __future__ import annotations

import asyncio
from importlib.metadata import version
import json
import os

from mcp import Client
from mcp.types import TextContent


async def main() -> None:
    actual_sdk = version("mcp")
    if actual_sdk != "2.1.1":
        raise RuntimeError(f"expected mcp 2.1.1, resolved {actual_sdk}")

    endpoint = os.environ["MCP_COMPAT_URL"]
    async with Client(endpoint) as client:
        modern_protocol = str(client.protocol_version)
        listed = await client.list_tools()
        names = {tool.name for tool in listed.tools}
        if names != {"always_fails", "echo"}:
            raise RuntimeError(f"unexpected tools: {sorted(names)}")

        succeeded = await client.call_tool("echo", {"text": "compatible"})
        if succeeded.is_error:
            raise RuntimeError("echo returned an error")
        first = succeeded.content[0]
        if not isinstance(first, TextContent) or first.text != "compatible":
            raise RuntimeError("echo returned an unexpected result")

        failed = await client.call_tool("always_fails")
        if not failed.is_error:
            raise RuntimeError("always_fails returned success")

    async with Client(endpoint, mode="legacy") as legacy:
        legacy_protocol = str(legacy.protocol_version)
        await legacy.list_tools()

    print(
        json.dumps(
            {
                "closed": True,
                "lane": "current-v2",
                "operations": [
                    "initialize",
                    "list_tools",
                    "call_tool",
                    "tool_error",
                    "close",
                ],
                "protocols": [modern_protocol, legacy_protocol],
                "sdk": actual_sdk,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
