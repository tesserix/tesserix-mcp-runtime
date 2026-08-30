from __future__ import annotations

import asyncio
import contextlib
import json
import os
from importlib import import_module
from importlib.metadata import version
from typing import Any, Protocol, runtime_checkable

from compatibility.client_report import ClientEvidence


@runtime_checkable
class DevAIConnection(Protocol):
    capabilities: dict[str, Any]

    @property
    def healthy(self) -> bool: ...

    async def connect(self) -> None: ...

    async def close(self) -> None: ...

    async def list_tools(self) -> list[dict[str, Any]]: ...

    async def call_tool(self, wire_name: str, arguments: dict[str, Any]) -> Any: ...


def _validate_echo(result: object) -> None:
    if getattr(result, "isError", True) is not False:
        raise RuntimeError("DevAI echo invocation returned an error")
    if getattr(result, "structuredContent", None) != {"text": "devai-compatible"}:
        raise RuntimeError("DevAI echo invocation returned invalid structured content")
    content = getattr(result, "content", None)
    if not isinstance(content, list) or not content:
        raise RuntimeError("DevAI echo invocation returned no text content")
    text = getattr(content[0], "text", None)
    if not isinstance(text, str) or json.loads(text) != {"text": "devai-compatible"}:
        raise RuntimeError("DevAI echo invocation returned invalid text content")


async def exercise_devai_adapter(
    connection: DevAIConnection,
    evidence: ClientEvidence,
) -> None:
    evidence.begin("initialize")
    await connection.connect()
    if not connection.healthy:
        raise RuntimeError("DevAI adapter did not become healthy")
    evidence.complete()

    evidence.begin("capabilities")
    if connection.capabilities != {"tools": True}:
        raise RuntimeError("DevAI adapter capabilities do not match the fixture")
    evidence.complete()

    evidence.begin("list_tools")
    tools = await connection.list_tools()
    names = {str(tool.get("name")) for tool in tools}
    if names != {"cancellation_probe", "echo"}:
        raise RuntimeError("DevAI adapter did not expose its expected first page")
    evidence.complete()

    evidence.begin("call_tool")
    result = await connection.call_tool("echo", {"text": "devai-compatible"})
    _validate_echo(result)
    evidence.complete()

    evidence.begin("close")
    await connection.close()
    evidence.complete()

    evidence.begin("reconnect")
    await connection.connect()
    try:
        reconnected = await connection.list_tools()
        if not any(tool.get("name") == "echo" for tool in reconnected):
            raise RuntimeError("DevAI adapter reconnect did not expose echo")
    finally:
        await connection.close()
    evidence.complete()


async def main() -> int:
    expected_sdk = "1.28.1"
    evidence = ClientEvidence(
        client="devai-downstream",
        lane="devai-adapter",
        expected_sdk=expected_sdk,
        supported_features=("reconnect", "structured_content", "tool_invocation"),
        negotiated_out=("prompts", "resources"),
        feature_gaps=("devai_adapter_pagination",),
    )
    actual_sdk = version("mcp")
    connection: DevAIConnection | None = None
    try:
        evidence.begin("sdk_version")
        if actual_sdk != expected_sdk:
            raise RuntimeError("DevAI did not resolve the reviewed MCP SDK")
        evidence.complete()

        downstream_module = import_module("devai.mcphub.downstream")
        model_module = import_module("devai.mcphub.model")
        connection_factory = getattr(downstream_module, "DownstreamConnection", None)
        spec_factory = getattr(model_module, "DownstreamSpec", None)
        if not callable(connection_factory) or not callable(spec_factory):
            raise RuntimeError("DevAI adapter surface is unavailable")
        candidate = connection_factory(
            spec_factory(
                name="tesserix-runtime",
                endpoint=os.environ["MCP_COMPAT_URL"],
                transport="streamable-http",
            ),
            timeout=10.0,
        )
        if not isinstance(candidate, DevAIConnection):
            raise RuntimeError("DevAI adapter does not implement the reviewed surface")
        connection = candidate
        await exercise_devai_adapter(connection, evidence)
    except Exception as error:
        if connection is not None:
            with contextlib.suppress(Exception):
                await connection.close()
        print(json.dumps(evidence.failed(actual_sdk=actual_sdk, error=error), sort_keys=True))
        return 1

    print(json.dumps(evidence.succeeded(actual_sdk=actual_sdk), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))


__all__ = ["exercise_devai_adapter"]
