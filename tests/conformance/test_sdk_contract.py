from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import TypeGuard

import pytest
from mcp.client import Client
from mcp.server import MCPServer
from tesserix_mcp_testkit import (
    CONFORMANCE_CASES,
    CONFORMANCE_TOOL_NAME,
    REQUIRED_CAPABILITIES,
    ConformanceCase,
    ConformanceObservation,
    assert_conformance_case,
)

from tesserix_mcp_runtime import JsonValue

SDK_CASES = tuple(case for case in CONFORMANCE_CASES if case.capability in REQUIRED_CAPABILITIES)


def _is_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    return isinstance(value, Mapping)


class McpSdkConformanceTarget:
    capabilities = REQUIRED_CAPABILITIES

    async def observe(self, case: ConformanceCase) -> ConformanceObservation:
        server = MCPServer("tesserix-conformance")

        async def echo(value: str) -> dict[str, JsonValue]:
            ready = asyncio.Event()
            ready.set()
            await ready.wait()
            return {"echo": value}

        server.tool(
            name=CONFORMANCE_TOOL_NAME,
            title="Conformance echo",
            description="Return one bounded synthetic value.",
            structured_output=True,
        )(echo)
        async with Client(server) as client:
            if case.id == "discovery.tools":
                listed = await client.list_tools()
                return ConformanceObservation(tool_names=tuple(tool.name for tool in listed.tools))
            result = await client.call_tool(CONFORMANCE_TOOL_NAME, {"value": "ok"})

        content: object = result.structured_content
        if result.is_error or not _is_mapping(content):
            return ConformanceObservation()
        value = content.get("echo")
        if not isinstance(value, str):
            return ConformanceObservation()
        return ConformanceObservation(value={"echo": value})


@pytest.mark.parametrize("case", SDK_CASES, ids=lambda case: case.id)
def test_official_sdk_conforms_to_every_applicable_case(case: ConformanceCase) -> None:
    asyncio.run(assert_conformance_case(McpSdkConformanceTarget(), case))
