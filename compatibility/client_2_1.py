# /// script
# requires-python = ">=3.12,<3.15"
# dependencies = ["mcp==2.1.1"]
# ///
from __future__ import annotations

import asyncio
import contextlib
import json
import os
from importlib.metadata import version

from mcp import Client
from mcp.types import TextContent


async def main() -> None:
    actual_sdk = version("mcp")
    if actual_sdk != "2.1.1":
        raise RuntimeError(f"expected mcp 2.1.1, resolved {actual_sdk}")

    endpoint = os.environ["MCP_COMPAT_URL"]
    async with Client(endpoint) as client:
        modern_protocol = str(client.protocol_version)
        cursor: str | None = None
        names: set[str] = set()
        pages = 0
        while True:
            listed = await client.list_tools(cursor=cursor, cache_mode="bypass")
            names.update(tool.name for tool in listed.tools)
            pages += 1
            cursor = listed.next_cursor
            if cursor is None:
                break
            if pages >= 4:
                raise RuntimeError("tool pagination did not terminate")
        if names != {"always_fails", "cancellation_probe", "echo"}:
            raise RuntimeError(f"unexpected tools: {sorted(names)}")
        if pages != 2:
            raise RuntimeError(f"expected two tool pages, received {pages}")

        async def probe(action: str) -> dict[str, int]:
            result = await client.call_tool("cancellation_probe", {"action": action})
            if result.is_error or not result.content:
                raise RuntimeError("cancellation probe returned an error")
            content = result.content[0]
            if not isinstance(content, TextContent):
                raise RuntimeError("cancellation probe returned unexpected content")
            document = json.loads(content.text)
            if (
                not isinstance(document, dict)
                or type(document.get("active")) is not int
                or type(document.get("observed")) is not int
            ):
                raise RuntimeError("cancellation probe returned an invalid status")
            return {"active": document["active"], "observed": document["observed"]}

        async def wait_for_cancellation() -> None:
            async with Client(endpoint) as cancellation_client:
                await cancellation_client.call_tool("cancellation_probe", {"action": "wait"})

        baseline = await probe("status")
        pending = asyncio.create_task(wait_for_cancellation())
        async with asyncio.timeout(5):
            # The server process cannot expose a local readiness event to this client.
            while (await probe("status"))["active"] == 0:  # noqa: ASYNC110
                await asyncio.sleep(0.01)
        pending.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await pending
        async with asyncio.timeout(5):
            while True:
                status = await probe("status")
                if status["active"] == 0 and status["observed"] > baseline["observed"]:
                    break
                await asyncio.sleep(0.01)

        succeeded = await client.call_tool("echo", {"text": "compatible"})
        if succeeded.is_error:
            raise RuntimeError("echo returned an error")
        first = succeeded.content[0]
        if not isinstance(first, TextContent) or json.loads(first.text) != {"text": "compatible"}:
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
                    "paginate_tools",
                    "call_tool",
                    "cancel_work",
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
