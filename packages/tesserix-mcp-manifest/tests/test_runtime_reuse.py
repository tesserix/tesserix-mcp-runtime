from __future__ import annotations

from tesserix_mcp_manifest import ToolSummary

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    IdempotencyRequirement,
    ToolEffect,
    ToolManifest,
    ToolMetadata,
)


def test_tool_summary_reuses_the_runtime_manifest_contract() -> None:
    runtime_manifest = ToolManifest(
        metadata=ToolMetadata(
            name="orders.get",
            title="Get order",
            description="Read one bounded synthetic order.",
            effect=ToolEffect.READ,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.NOT_APPLICABLE,
            required_scopes=("orders:read",),
        ),
        normalized_name="orders_get",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
    )

    summary = ToolSummary.from_runtime(runtime_manifest)

    assert summary == ToolSummary(
        name="orders_get",
        description="Read one bounded synthetic order.",
        input_fingerprint=runtime_manifest.input_fingerprint,
        output_fingerprint=runtime_manifest.output_fingerprint,
        required_scopes=("orders:read",),
    )
