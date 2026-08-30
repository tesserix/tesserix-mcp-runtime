from __future__ import annotations

import pytest
from tesserix_mcp_manifest import (
    CredentialReference,
    DiscoveryRisk,
    ManifestLifecycle,
    ManifestVisibility,
    Ownership,
    RemoteEndpoint,
    Repository,
    RoutePolicy,
    RuntimeAdapter,
    SemanticMetadata,
    ServerAuthoringManifest,
    ToolSummary,
)


@pytest.fixture
def remote_manifest() -> ServerAuthoringManifest:
    return ServerAuthoringManifest(
        name="io.github.tesserix/orders",
        version="1.2.3",
        title="Orders MCP",
        description="Read bounded synthetic order data.",
        repository=Repository(
            url="https://github.com/tesserix/orders-mcp",
            source="github",
            id="123456789",
        ),
        remote=RemoteEndpoint(url="https://mcp.example.com/orders/mcp"),
        ownership=Ownership(
            namespace="tenant-orders",
            tenant_id="tenant-orders",
            visibility=ManifestVisibility.PUBLIC,
            org_id="tesserix",
            labels={"domain": "orders"},
            annotations={"owner": "platform"},
        ),
        adapter=RuntimeAdapter.NATIVE,
        protocol_versions=("2025-11-25", "2026-07-28"),
        lifecycle=ManifestLifecycle.ACTIVE,
        route_policy=RoutePolicy(gateway_path="/gateway/orders/mcp"),
        credential_ref=CredentialReference(
            secret_name="orders-mcp-upstream",
            key="access-credential",
        ),
        semantic=SemanticMetadata(
            capabilities=("cap/orders-read",),
            domains=("commerce",),
            keywords=("orders", "read"),
            risk=DiscoveryRisk.MEDIUM,
            summary="Locate customer orders by stable identifiers.",
            when_to_use=("find a known customer order",),
        ),
        egress_hosts=("orders.example.com",),
        required_scopes=("orders:read",),
        tools=(
            ToolSummary(
                name="orders_get",
                description="Read one order.",
                input_fingerprint="a" * 64,
                output_fingerprint="b" * 64,
                required_scopes=("orders:read",),
                semantic=SemanticMetadata(
                    capabilities=("cap/orders-read",),
                    risk=DiscoveryRisk.LOW,
                    summary="Return a single order by its stable identifier.",
                    when_to_use=("look up one known order",),
                ),
            ),
        ),
    )
