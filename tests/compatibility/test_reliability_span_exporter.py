from __future__ import annotations

import asyncio
import json
import re
from io import StringIO

from compatibility.server import CompatibilityContextProvider, ReliabilitySpanLogExporter

from tesserix_mcp_runtime.adapters.streamable_http import HTTPRequestMetadata
from tesserix_mcp_runtime.observability import (
    RuntimeObservability,
    RuntimeOutcome,
    RuntimeSpanName,
    RuntimeSpanSpec,
)


class _Cancellation:
    @property
    def cancelled(self) -> bool:
        return False

    async def wait(self) -> None:
        await asyncio.Event().wait()


def test_compatibility_exporter_logs_only_sanitized_reliability_execution_spans() -> None:
    output = StringIO()
    observability = RuntimeObservability(
        server_name="compatibility-runtime",
        exporter=ReliabilitySpanLogExporter(stream=output),
    )

    ignored = observability.start_span(
        RuntimeSpanSpec(
            name=RuntimeSpanName.AUTHORIZATION,
            server_name="compatibility-runtime",
            tool_name="reliability_probe",
        )
    )
    with ignored:
        ignored.set_outcome(RuntimeOutcome.SUCCESS)
    captured = observability.start_span(
        RuntimeSpanSpec(
            name=RuntimeSpanName.TOOL_EXECUTION,
            server_name="compatibility-runtime",
            tool_name="reliability_probe",
        )
    )
    with captured:
        captured.set_outcome(RuntimeOutcome.SUCCESS)

    lines = output.getvalue().splitlines()
    assert len(lines) == 1
    prefix = "TESSERIX_RELIABILITY_SPAN "
    assert lines[0].startswith(prefix)
    sample = json.loads(lines[0].removeprefix(prefix))
    assert set(sample) == {"schema_version", "name", "outcome", "duration_seconds"}
    assert sample["schema_version"] == 1
    assert sample["name"] == "mcp.tool.execution"
    assert sample["outcome"] == "success"
    assert isinstance(sample["duration_seconds"], float)
    assert sample["duration_seconds"] > 0
    assert "reliability_probe" not in lines[0]


def test_compatibility_context_creates_fresh_request_ids_without_replica_memory() -> None:
    async def exercise() -> None:
        provider = CompatibilityContextProvider()
        request = HTTPRequestMetadata(method="POST", path="/mcp", headers=())

        first = await provider.create(request, cancellation=_Cancellation())
        second = await provider.create(request, cancellation=_Cancellation())

        assert first.request_id != second.request_id
        assert re.fullmatch(r"compatibility-[0-9a-f]{32}", first.request_id)
        assert re.fullmatch(r"compatibility-[0-9a-f]{32}", second.request_id)
        assert "_requests" not in vars(provider)

    asyncio.run(exercise())
