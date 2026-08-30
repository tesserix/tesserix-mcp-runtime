from __future__ import annotations

from tesserix_mcp_manifest import ManifestLifecycle, SemanticMetadata, ToolSummary

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    IdempotencyRequirement,
    ToolDiscoveryMetadata,
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


def test_tool_summary_reuses_runtime_discovery_metadata_when_not_overridden() -> None:
    runtime_manifest = ToolManifest(
        metadata=ToolMetadata(
            name="orders.get",
            title="Get order",
            description="Read one bounded synthetic order.",
            effect=ToolEffect.READ,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.NOT_APPLICABLE,
            required_scopes=("orders:read",),
            discovery=ToolDiscoveryMetadata(
                summary="Find one customer order",
                when_to_use="look up a known customer order",
                capabilities=("cap/orders-read",),
                rate_class="interactive",
                lifecycle="deprecated",
                examples=("Where is order A-123?",),
            ),
        ),
        normalized_name="orders.get",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
    )

    summary = ToolSummary.from_runtime(runtime_manifest)

    assert summary.semantic == SemanticMetadata(
        summary="Find one customer order",
        when_to_use=("look up a known customer order",),
        capabilities=("cap/orders-read",),
        examples=("Where is order A-123?",),
    )
    assert summary.lifecycle is ManifestLifecycle.DEPRECATED
