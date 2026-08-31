from __future__ import annotations

import asyncio
from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class _Result:
    is_error: bool
    structured_content: dict[str, object]


class _Client:
    def __init__(self) -> None:
        self.request_sizes: list[int] = []

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
                "chunks": ["s" * 62_500] * (response_bytes // 62_500),
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


def test_burst_window_drives_the_reviewed_tool_concurrency_capacity() -> None:
    plans = reliability_load_plans(
        ReliabilityLane.AGENTGATEWAY,
        sustained_requests=100,
        burst_requests=200,
        boundary_requests=4,
        kinds=(ReliabilityLoadKind.BURST,),
    )

    assert len(plans) == 1
    assert plans[0].concurrency == 32


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
