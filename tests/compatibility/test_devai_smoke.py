from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from compatibility.client_report import ClientEvidence
from compatibility.devai_smoke import exercise_devai_adapter


class FakeDevAIConnection:
    def __init__(self) -> None:
        self.capabilities: dict[str, Any] = {}
        self.healthy = False
        self.connects = 0
        self.closes = 0

    async def connect(self) -> None:
        self.connects += 1
        self.healthy = True
        self.capabilities = {"tools": True}

    async def close(self) -> None:
        self.closes += 1
        self.healthy = False

    async def list_tools(self) -> list[dict[str, Any]]:
        return [
            {"name": "echo", "description": "", "inputSchema": {}},
            {"name": "cancellation_probe", "description": "", "inputSchema": {}},
        ]

    async def call_tool(self, wire_name: str, arguments: dict[str, Any]) -> Any:
        assert wire_name == "echo"
        assert arguments == {"text": "devai-compatible"}
        return SimpleNamespace(
            content=[SimpleNamespace(text=json.dumps({"text": "devai-compatible"}))],
            isError=False,
            structuredContent={"text": "devai-compatible"},
        )


async def test_devai_adapter_discovers_invokes_closes_and_reconnects() -> None:
    connection = FakeDevAIConnection()
    evidence = ClientEvidence(
        client="devai-downstream",
        lane="devai-adapter",
        expected_sdk="1.28.1",
        supported_features=("reconnect", "structured_content", "tool_invocation"),
        negotiated_out=("prompts", "resources"),
        feature_gaps=("devai_adapter_pagination",),
    )

    await exercise_devai_adapter(connection, evidence)
    report = evidence.succeeded(actual_sdk="1.28.1")

    assert connection.connects == 2
    assert connection.closes == 2
    assert report["operations"] == [
        "initialize",
        "capabilities",
        "list_tools",
        "call_tool",
        "close",
        "reconnect",
    ]
    assert report["feature_gaps"] == ["devai_adapter_pagination"]
