from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

from mcp import Client
from tesserix_mcp_testkit import (
    ReliabilityLane,
    ReliabilityLoadEvidence,
    ReliabilityLoadKind,
    ReliabilityLoadPlan,
    ReliabilityOutcome,
    ReliabilityRequest,
    ReliabilityTargetResult,
    run_reliability_load,
)

_ALL_LOAD_KINDS = tuple(ReliabilityLoadKind)


class _Client(Protocol):
    async def call_tool(self, name: str, arguments: dict[str, object]) -> Any: ...


class MCPReliabilityTarget:
    def __init__(self, *, lane: ReliabilityLane, client: _Client) -> None:
        if lane not in {ReliabilityLane.DIRECT_HTTP, ReliabilityLane.AGENTGATEWAY}:
            raise ValueError("container measurement requires a network lane")
        self.lane: ReliabilityLane = lane
        self._client = client

    async def invoke(self, request: ReliabilityRequest) -> ReliabilityTargetResult:
        if request.request_bytes > 60_000 or request.response_bytes > 500_000:
            return ReliabilityTargetResult(outcome=ReliabilityOutcome.OVERLOADED)
        result: object = await self._client.call_tool(
            "reliability_probe",
            {
                "request": "r" * request.request_bytes,
                "response_bytes": request.response_bytes,
            },
        )
        is_error: object = getattr(result, "is_error", True)
        structured_value: object = getattr(result, "structured_content", None)
        if is_error is not False or not isinstance(structured_value, dict):
            return ReliabilityTargetResult(outcome=ReliabilityOutcome.UNAVAILABLE)
        untyped_structured = cast(dict[object, object], structured_value)
        if not all(isinstance(key, str) for key in untyped_structured):
            return ReliabilityTargetResult(outcome=ReliabilityOutcome.UNAVAILABLE)
        structured = {str(key): value for key, value in untyped_structured.items()}
        request_bytes = structured.get("request_bytes")
        response_bytes = structured.get("response_bytes")
        chunks = structured.get("chunks")
        if (
            isinstance(request_bytes, bool)
            or not isinstance(request_bytes, int)
            or isinstance(response_bytes, bool)
            or not isinstance(response_bytes, int)
            or not isinstance(chunks, list)
        ):
            return ReliabilityTargetResult(outcome=ReliabilityOutcome.UNAVAILABLE)
        untyped_chunks = cast(list[object], chunks)
        if not all(isinstance(chunk, str) for chunk in untyped_chunks):
            return ReliabilityTargetResult(outcome=ReliabilityOutcome.UNAVAILABLE)
        encoded_chunks = [str(chunk) for chunk in untyped_chunks]
        if (
            request_bytes != request.request_bytes
            or response_bytes != request.response_bytes
            or sum(len(chunk.encode("utf-8")) for chunk in encoded_chunks) != response_bytes
        ):
            return ReliabilityTargetResult(outcome=ReliabilityOutcome.UNAVAILABLE)
        return ReliabilityTargetResult(
            outcome=ReliabilityOutcome.SUCCESS,
            response_bytes=response_bytes,
        )


def _bounded_count(value: str) -> int:
    count = int(value)
    if not 1 <= count <= 10_000:
        raise argparse.ArgumentTypeError("request count must be between 1 and 10000")
    return count


def reliability_load_plans(
    lane: ReliabilityLane,
    *,
    sustained_requests: int,
    burst_requests: int,
    boundary_requests: int,
    kinds: tuple[ReliabilityLoadKind, ...] = _ALL_LOAD_KINDS,
) -> tuple[ReliabilityLoadPlan, ...]:
    prefix = lane.value.replace("_", "-")
    plans = (
        ReliabilityLoadPlan(
            name=f"{prefix}-sustained",
            lane=lane,
            kind=ReliabilityLoadKind.SUSTAINED,
            requests=sustained_requests,
            concurrency=min(16, sustained_requests),
            tenants=min(4, sustained_requests),
            request_bytes=1_024,
            response_bytes=4_096,
        ),
        ReliabilityLoadPlan(
            name=f"{prefix}-burst",
            lane=lane,
            kind=ReliabilityLoadKind.BURST,
            requests=burst_requests,
            concurrency=min(32, burst_requests),
            tenants=min(16, burst_requests),
            request_bytes=1_024,
            response_bytes=4_096,
        ),
        ReliabilityLoadPlan(
            name=f"{prefix}-boundary",
            lane=lane,
            kind=ReliabilityLoadKind.BOUNDARY,
            requests=boundary_requests,
            concurrency=min(4, boundary_requests),
            tenants=min(4, boundary_requests),
            request_bytes=60_000,
            response_bytes=500_000,
        ),
    )
    if (
        not kinds
        or len(set(kinds)) != len(kinds)
        or any(kind not in _ALL_LOAD_KINDS for kind in kinds)
    ):
        raise ValueError("load kinds must contain unique reliability vocabulary values")
    return tuple(plan for plan in plans if plan.kind in kinds)


def _endpoint(value: str, lane: ReliabilityLane) -> str:
    parsed = urlsplit(value)
    expected_path = "/mcp" if lane is ReliabilityLane.DIRECT_HTTP else "/gateway/runtime/mcp"
    if (
        len(value) > 2_048
        or parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != expected_path
    ):
        raise argparse.ArgumentTypeError("endpoint must be the expected loopback route")
    return value


def reliability_loads_pass(
    loads: tuple[ReliabilityLoadEvidence, ...],
    *,
    required_kinds: tuple[ReliabilityLoadKind, ...] = _ALL_LOAD_KINDS,
) -> bool:
    by_kind = {load.kind: load for load in loads}
    if set(by_kind) != set(required_kinds):
        return False
    if any(load.successful != load.completed or load.maximum_queue_depth != 0 for load in loads):
        return False
    sustained = by_kind.get(ReliabilityLoadKind.SUSTAINED)
    burst = by_kind.get(ReliabilityLoadKind.BURST)
    boundary = by_kind.get(ReliabilityLoadKind.BOUNDARY)
    return not (
        (sustained is not None and sustained.throughput_requests_per_second < 50)
        or (burst is not None and burst.throughput_requests_per_second < 200)
        or (
            boundary is not None
            and (boundary.request_bytes < 60_000 or boundary.response_bytes < 500_000)
        )
    )


async def _measure(
    endpoint: str,
    lane: ReliabilityLane,
    *,
    sustained_requests: int,
    burst_requests: int,
    boundary_requests: int,
    kinds: tuple[ReliabilityLoadKind, ...] = _ALL_LOAD_KINDS,
) -> dict[str, object]:
    logging.getLogger("client").setLevel(logging.ERROR)
    async with Client(endpoint) as client:
        cursor: str | None = None
        listed_names: set[str] = set()
        for _ in range(4):
            listed = await client.list_tools(cursor=cursor, cache_mode="bypass")
            listed_names.update(tool.name for tool in listed.tools)
            cursor = listed.next_cursor
            if cursor is None:
                break
        else:
            raise RuntimeError("tool pagination did not terminate")
        if lane is ReliabilityLane.DIRECT_HTTP and "reliability_probe" not in listed_names:
            raise RuntimeError("direct reliability probe is unavailable")
        target = MCPReliabilityTarget(lane=lane, client=client)
        loads = tuple(
            [
                await run_reliability_load(plan, target)
                for plan in reliability_load_plans(
                    lane,
                    sustained_requests=sustained_requests,
                    burst_requests=burst_requests,
                    boundary_requests=boundary_requests,
                    kinds=kinds,
                )
            ]
        )
    return {
        "schema_version": 1,
        "lane": lane.value,
        "route": urlsplit(endpoint).path,
        "targets": {
            "sustained_requests_per_second": 50,
            "burst_requests_per_second": 200,
            "request_bytes": 60_000,
            "response_bytes": 500_000,
        },
        "loads": [load.model_dump(mode="json") for load in loads],
        "passed": reliability_loads_pass(loads, required_kinds=kinds),
    }


def _write_report(path: Path, report: dict[str, object]) -> None:
    target = path.resolve()
    if (
        not target.parent.is_dir()
        or target.is_symlink()
        or (target.exists() and not target.is_file())
    ):
        raise ValueError("reliability report target is invalid")
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument(
        "--lane",
        required=True,
        choices=(ReliabilityLane.DIRECT_HTTP.value, ReliabilityLane.AGENTGATEWAY.value),
    )
    parser.add_argument("--sustained-requests", type=_bounded_count, default=100)
    parser.add_argument("--burst-requests", type=_bounded_count, default=200)
    parser.add_argument("--boundary-requests", type=_bounded_count, default=4)
    parser.add_argument("--kind", choices=tuple(kind.value for kind in ReliabilityLoadKind))
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    lane = ReliabilityLane(arguments.lane)
    kinds = _ALL_LOAD_KINDS if arguments.kind is None else (ReliabilityLoadKind(arguments.kind),)
    try:
        endpoint = _endpoint(arguments.endpoint, lane)
        report = asyncio.run(
            _measure(
                endpoint,
                lane,
                sustained_requests=arguments.sustained_requests,
                burst_requests=arguments.burst_requests,
                boundary_requests=arguments.boundary_requests,
                kinds=kinds,
            )
        )
        _write_report(arguments.report, report)
    except (OSError, RuntimeError, TypeError, ValueError):
        json.dump({"code": "container_reliability_measurement_failed"}, sys.stderr)
        sys.stderr.write("\n")
        return 2
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
