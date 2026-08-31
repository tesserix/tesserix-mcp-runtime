from __future__ import annotations

import asyncio
import contextlib
import json
import os
from contextlib import AsyncExitStack
from importlib.metadata import version

from client_report import ClientEvidence
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import InitializeResult, TextContent


async def _connect(endpoint: str) -> tuple[AsyncExitStack, ClientSession, InitializeResult]:
    stack = AsyncExitStack()
    try:
        streams = await stack.enter_async_context(streamable_http_client(endpoint))
        session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
        initialized = await session.initialize()
    except BaseException:
        await stack.aclose()
        raise
    return stack, session, initialized


async def exercise(expected_sdk: str, lane: str) -> int:
    pagination_gap = (
        os.environ.get("MCP_COMPAT_PAGINATION_MODE", "complete") == "agentgateway-first-page-only"
    )
    evidence = ClientEvidence(
        client="python-sdk",
        lane=lane,
        expected_sdk=expected_sdk,
        supported_features=tuple(
            feature
            for feature in (
                "cancellation",
                "pagination",
                "reconnect",
                "structured_content",
                "tool_errors",
            )
            if feature != "pagination" or not pagination_gap
        ),
        negotiated_out=("prompts", "resources"),
        feature_gaps=("agentgateway_pagination",) if pagination_gap else (),
    )
    actual_sdk = version("mcp")
    endpoint = os.environ["MCP_COMPAT_URL"]
    stack: AsyncExitStack | None = None
    try:
        evidence.begin("sdk_version")
        if actual_sdk != expected_sdk:
            raise RuntimeError("resolved MCP SDK does not match the compatibility lane")
        evidence.complete()

        evidence.begin("initialize")
        stack, session, initialized = await _connect(endpoint)
        protocol = str(initialized.protocolVersion)
        evidence.negotiated(protocol)
        evidence.complete()

        evidence.begin("capabilities")
        capabilities = initialized.capabilities
        if (
            getattr(capabilities, "tools", None) is None
            or getattr(capabilities, "prompts", None) is not None
            or getattr(capabilities, "resources", None) is not None
        ):
            raise RuntimeError("server capabilities do not match the compatibility fixture")
        evidence.complete()

        evidence.begin("list_tools")
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
        expected_names = (
            {"cancellation_probe", "echo"}
            if pagination_gap
            else {"always_fails", "cancellation_probe", "echo", "reliability_probe"}
        )
        if names != expected_names:
            raise RuntimeError("server returned an unexpected tool catalog")
        evidence.complete()

        evidence.begin("paginate_tools")
        expected_pages = 1 if pagination_gap else 2
        if pages != expected_pages:
            raise RuntimeError("server returned an unexpected number of tool pages")
        evidence.complete()

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
            cancellation_stack, cancellation_session, _ = await _connect(endpoint)
            try:
                await cancellation_session.call_tool("cancellation_probe", {"action": "wait"})
            finally:
                await cancellation_stack.aclose()

        evidence.begin("cancel_work")
        baseline = await probe("status")
        pending = asyncio.create_task(wait_for_cancellation())
        async with asyncio.timeout(5):
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
        evidence.complete()

        evidence.begin("call_tool")
        succeeded = await session.call_tool("echo", {"text": "compatible"})
        if succeeded.isError or succeeded.structuredContent != {"text": "compatible"}:
            raise RuntimeError("echo returned an invalid structured result")
        first = succeeded.content[0]
        if not isinstance(first, TextContent) or json.loads(first.text) != {"text": "compatible"}:
            raise RuntimeError("echo returned unexpected text content")
        evidence.complete()

        evidence.begin("tool_error")
        failed = await session.call_tool("always_fails")
        if not failed.isError:
            raise RuntimeError("failure tool returned success")
        evidence.complete()

        evidence.begin("close")
        await stack.aclose()
        stack = None
        evidence.complete()

        evidence.begin("reconnect")
        reconnect_stack, reconnect_session, reinitialized = await _connect(endpoint)
        try:
            if str(reinitialized.protocolVersion) != protocol:
                raise RuntimeError("reconnect negotiated a different protocol")
            reconnected_tools = await reconnect_session.list_tools()
            if not any(tool.name == "echo" for tool in reconnected_tools.tools):
                raise RuntimeError("reconnect did not expose the echo tool")
        finally:
            await reconnect_stack.aclose()
        evidence.complete()
    except Exception as error:
        if stack is not None:
            with contextlib.suppress(Exception):
                await stack.aclose()
        print(json.dumps(evidence.failed(actual_sdk=actual_sdk, error=error), sort_keys=True))
        return 1

    print(json.dumps(evidence.succeeded(actual_sdk=actual_sdk), sort_keys=True))
    return 0
