from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from compatibility.measure_reliability import (
    MCPReliabilityTarget,
    reliability_load_plans,
    reliability_loads_pass,
)
from tesserix_mcp_testkit import (
    ReliabilityLane,
    ReliabilityLoadKind,
    ReliabilityLoadPlan,
    ReliabilityOutcome,
    run_reliability_load,
)

from compatibility import measure_reliability


@dataclass(frozen=True, slots=True)
class _Result:
    is_error: bool
    structured_content: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ListedTool:
    name: str


@dataclass(frozen=True, slots=True)
class _ToolList:
    tools: tuple[_ListedTool, ...]
    next_cursor: str | None = None


class _Client:
    def __init__(self, endpoint: str | None = None) -> None:
        del endpoint
        self.request_sizes: list[int] = []

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(
        self,
        error_type: object,
        error: object,
        traceback: object,
    ) -> None:
        del error_type, error, traceback

    async def list_tools(self, *, cursor: str | None, cache_mode: str) -> _ToolList:
        del cursor, cache_mode
        return _ToolList(tools=(_ListedTool(name="reliability_probe"),))

    async def call_tool(self, name: str, arguments: dict[str, object]) -> _Result:
        assert name == "reliability_probe"
        request = arguments["request"]
        response_bytes = arguments["response_bytes"]
        assert isinstance(request, str)
        assert isinstance(response_bytes, int)
        self.request_sizes.append(len(request.encode("utf-8")))
        return _Result(
            is_error=False,
            structured_content={
                "request_bytes": len(request.encode("utf-8")),
                "response_bytes": response_bytes,
                "chunks": [
                    "s" * min(62_500, response_bytes - offset)
                    for offset in range(0, response_bytes, 62_500)
                ],
            },
        )


def test_mcp_reliability_target_returns_only_sanitized_size_and_outcome_evidence() -> None:
    async def exercise() -> None:
        client = _Client()
        target = MCPReliabilityTarget(lane=ReliabilityLane.DIRECT_HTTP, client=client)
        plan = ReliabilityLoadPlan(
            name="direct-boundary",
            lane=ReliabilityLane.DIRECT_HTTP,
            kind=ReliabilityLoadKind.BOUNDARY,
            requests=2,
            concurrency=2,
            tenants=2,
            request_bytes=60_000,
            response_bytes=500_000,
        )

        evidence = await run_reliability_load(plan, target)

        assert evidence.completed == 2
        assert evidence.successful == 2
        assert evidence.outcome_count(ReliabilityOutcome.SUCCESS) == 2
        assert evidence.response_bytes == 500_000
        assert client.request_sizes == [60_000, 60_000]
        rendered = evidence.model_dump_json()
        assert "reliability-tenant" not in rendered
        assert "content" not in rendered

    asyncio.run(exercise())


def test_container_measurement_can_isolate_one_correlation_window() -> None:
    plans = reliability_load_plans(
        ReliabilityLane.AGENTGATEWAY,
        sustained_requests=100,
        burst_requests=200,
        boundary_requests=4,
        kinds=(ReliabilityLoadKind.BOUNDARY,),
    )

    assert len(plans) == 1
    assert plans[0].kind is ReliabilityLoadKind.BOUNDARY
    assert plans[0].requests == 4


def test_cli_marks_compatibility_smoke_as_nonqualification_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = tmp_path / "smoke.json"
    monkeypatch.setattr(measure_reliability, "Client", _Client)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "measure_reliability.py",
            "--endpoint",
            "http://127.0.0.1:33000/gateway/runtime/mcp",
            "--lane",
            "agentgateway",
            "--sustained-requests",
            "1",
            "--burst-requests",
            "1",
            "--boundary-requests",
            "1",
            "--compatibility-smoke",
            "--report",
            str(report),
        ],
    )

    assert measure_reliability.main() == 0
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["targets"] == {
        "assessment": "compatibility_smoke",
        "burst_requests_per_second": 200,
        "request_bytes": 60_000,
        "response_bytes": 500_000,
        "sustained_requests_per_second": 50,
    }
    assert document["passed"] is True


def test_transport_smoke_cannot_masquerade_as_rate_qualification() -> None:
    async def exercise() -> None:
        target = MCPReliabilityTarget(lane=ReliabilityLane.AGENTGATEWAY, client=_Client())
        loads = tuple(
            [
                await run_reliability_load(plan, target)
                for plan in reliability_load_plans(
                    ReliabilityLane.AGENTGATEWAY,
                    sustained_requests=1,
                    burst_requests=1,
                    boundary_requests=1,
                )
            ]
        )
        slow = tuple(
            load.model_copy(update={"throughput_requests_per_second": 1.0}) for load in loads
        )
        undersized = tuple(
            load.model_copy(update={"request_bytes": 59_999})
            if load.kind is ReliabilityLoadKind.BOUNDARY
            else load
            for load in slow
        )

        assert not reliability_loads_pass(slow)
        assert reliability_loads_pass(slow, enforce_rate_targets=False)
        assert not reliability_loads_pass(undersized, enforce_rate_targets=False)

    asyncio.run(exercise())


def test_isolated_boundary_window_is_assessed_against_only_its_target() -> None:
    async def exercise() -> None:
        evidence = await run_reliability_load(
            reliability_load_plans(
                ReliabilityLane.AGENTGATEWAY,
                sustained_requests=100,
                burst_requests=200,
                boundary_requests=1,
                kinds=(ReliabilityLoadKind.BOUNDARY,),
            )[0],
            MCPReliabilityTarget(lane=ReliabilityLane.AGENTGATEWAY, client=_Client()),
        )

        assert reliability_loads_pass(
            (evidence,),
            required_kinds=(ReliabilityLoadKind.BOUNDARY,),
        )

    asyncio.run(exercise())
