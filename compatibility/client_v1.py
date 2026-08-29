from __future__ import annotations

import asyncio
import contextlib
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
        cursor: str | None = None
        names: set[str] = set()
        pages = 0
        while True:
            listed = await session.list_tools(cursor=cursor)
            names.update(tool.name for tool in listed.tools)
            pages += 1
            cursor = listed.nextCursor
            if cursor is None:
                break
            if pages >= 4:
                raise RuntimeError("tool pagination did not terminate")
        if names != {"always_fails", "cancellation_probe", "echo"}:
            raise RuntimeError(f"unexpected tools: {sorted(names)}")
        if pages != 2:
            raise RuntimeError(f"expected two tool pages, received {pages}")

        async def probe(action: str) -> dict[str, int]:
            result = await session.call_tool("cancellation_probe", {"action": action})
            if result.isError or not result.content:
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
            async with (
                streamable_http_client(endpoint) as (
                    cancellation_read,
                    cancellation_write,
                    _,
                ),
                ClientSession(cancellation_read, cancellation_write) as cancellation_session,
            ):
                await cancellation_session.initialize()
                await cancellation_session.call_tool("cancellation_probe", {"action": "wait"})

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

        succeeded = await session.call_tool("echo", {"text": "compatible"})
        if succeeded.isError:
            raise RuntimeError("echo returned an error")
        first = succeeded.content[0]
        if not isinstance(first, TextContent) or json.loads(first.text) != {"text": "compatible"}:
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
                    "paginate_tools",
                    "call_tool",
                    "cancel_work",
                    "tool_error",
                    "close",
                ],
                "protocols": [protocol],
                "sdk": actual_sdk,
            },
            sort_keys=True,
        )
    )
