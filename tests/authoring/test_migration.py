from __future__ import annotations

import pytest

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    EgressDestination,
    EgressManifest,
    IdempotencyRequirement,
    JsonValue,
    MigrationRoute,
    MigrationSurface,
    ToolEffect,
    ToolManifest,
    ToolMetadata,
    compare_migration_surfaces,
)


def _tool(
    *,
    description: str = "Return one bounded item.",
    scope: str = "catalog:read",
    maximum: int = 32,
) -> ToolManifest:
    schema: dict[str, JsonValue] = {
        "type": "object",
        "properties": {"query": {"type": "string", "maxLength": maximum}},
        "required": ["query"],
        "additionalProperties": False,
    }
    return ToolManifest(
        metadata=ToolMetadata(
            name="catalog.search",
            title="Search catalog",
            description=description,
            effect=ToolEffect.READ,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.NOT_APPLICABLE,
            required_scopes=(scope,),
        ),
        normalized_name="catalog.search",
        input_schema=schema,
        output_schema=schema,
    )


def _surface(
    tool: ToolManifest,
    *,
    route: str = "/gateway/catalog/mcp",
    egress_host: str = "catalog.example.com",
    stateless: bool = True,
) -> MigrationSurface:
    return MigrationSurface(
        tools=(tool,),
        egress=EgressManifest(destinations=(EgressDestination(host=egress_host),)),
        routes=(
            MigrationRoute(
                name="catalog",
                public_path=route,
                upstream_path="/mcp",
            ),
        ),
        stateless=stateless,
    )


def test_migration_diff_reports_reviewable_drift_and_blocks_breaking_cutover() -> None:
    report = compare_migration_surfaces(
        _surface(_tool()),
        _surface(
            _tool(
                description="Search one bounded catalog.",
                scope="catalog:query",
                maximum=16,
            ),
            route="/gateway/catalog-v2/mcp",
            egress_host="search.example.com",
        ),
    )

    assert report.requires_major_version is True
    assert report.cutover_ready is False
    assert report.tool_diffs[0].input_change.value == "breaking"
    assert report.tool_diffs[0].description_changed is True
    assert report.tool_diffs[0].scope_changed is True
    assert report.added_egress == ("search.example.com:443",)
    assert report.removed_egress == ("catalog.example.com:443",)
    assert report.added_routes == ("catalog:/gateway/catalog-v2/mcp->/mcp",)
    assert report.removed_routes == ("catalog:/gateway/catalog/mcp->/mcp",)


def test_migration_diff_requires_a_stateless_target_even_without_surface_drift() -> None:
    report = compare_migration_surfaces(
        _surface(_tool()),
        _surface(_tool(), stateless=False),
    )

    assert report.requires_major_version is False
    assert report.cutover_ready is False
    assert report.lifecycle_changed is True


def test_migration_diff_marks_policy_and_removed_tools_as_major_changes() -> None:
    previous = _surface(_tool())
    changed = ToolManifest(
        metadata=ToolMetadata(
            name="catalog.search",
            title="Search catalog",
            description="Return one bounded item.",
            effect=ToolEffect.WRITE,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.REQUIRED,
            required_scopes=("catalog:read",),
        ),
        normalized_name="catalog.search",
        input_schema=previous.tools[0].input_schema,
        output_schema=previous.tools[0].output_schema,
    )

    assert compare_migration_surfaces(previous, _surface(changed)).requires_major_version is True
    assert compare_migration_surfaces(
        previous,
        MigrationSurface(
            tools=(),
            egress=previous.egress,
            routes=previous.routes,
            stateless=True,
        ),
    ).removed_tools == ("catalog.search",)


@pytest.mark.parametrize("path", ["catalog", "/catalog?version=2", "/catalog/../mcp"])
def test_migration_routes_reject_ambiguous_paths(path: str) -> None:
    with pytest.raises(ValueError, match="route paths"):
        MigrationRoute(name="catalog", public_path=path, upstream_path="/mcp")


def test_migration_surface_and_comparison_reject_invalid_boundaries() -> None:
    route = MigrationRoute(name="catalog", public_path="/mcp", upstream_path="/mcp")
    with pytest.raises(ValueError, match="unique normalized names"):
        MigrationSurface(
            tools=(_tool(), _tool()),
            egress=EgressManifest(),
            routes=(route,),
            stateless=True,
        )
    with pytest.raises(ValueError, match="two migration surfaces"):
        compare_migration_surfaces(_surface(_tool()), object())  # type: ignore[arg-type]
