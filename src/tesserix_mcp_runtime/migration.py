"""Deterministic pre-cutover comparison for incremental MCP migrations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tesserix_mcp_runtime.egress import EgressManifest
from tesserix_mcp_runtime.schema_compatibility import (
    SchemaChange,
    SchemaDirection,
    classify_schema_change,
)
from tesserix_mcp_runtime.tool_manifest import ToolManifest


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def _route_path(value: str) -> str:
    if (
        not _is_runtime_instance(value, str)
        or not value.startswith("/")
        or len(value) > 512
        or value != value.strip()
        or "?" in value
        or "#" in value
        or "//" in value
        or any(part in {".", ".."} for part in value.split("/"))
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("route paths must be bounded absolute paths without traversal")
    return value


@dataclass(frozen=True, slots=True, kw_only=True)
class MigrationRoute:
    """One exact public-to-upstream route considered during a migration."""

    name: str
    public_path: str
    upstream_path: str

    def __post_init__(self) -> None:
        if (
            not _is_runtime_instance(self.name, str)
            or not self.name
            or self.name != self.name.strip()
            or len(self.name) > 128
            or any(ord(character) < 32 for character in self.name)
        ):
            raise ValueError("route name must be bounded, non-empty text")
        object.__setattr__(self, "public_path", _route_path(self.public_path))
        object.__setattr__(self, "upstream_path", _route_path(self.upstream_path))

    @property
    def identifier(self) -> str:
        return f"{self.name}:{self.public_path}->{self.upstream_path}"


@dataclass(frozen=True, slots=True, kw_only=True)
class MigrationSurface:
    """Handler-free immutable surface captured before a route can change."""

    tools: tuple[ToolManifest, ...]
    egress: EgressManifest
    routes: tuple[MigrationRoute, ...]
    stateless: bool

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.tools, tuple) or any(
            not _is_runtime_instance(tool, ToolManifest) for tool in self.tools
        ):
            raise ValueError("migration tools must be immutable tool manifests")
        names = tuple(tool.normalized_name for tool in self.tools)
        if len(names) != len(set(names)):
            raise ValueError("migration tools must have unique normalized names")
        if not _is_runtime_instance(self.egress, EgressManifest):
            raise ValueError("migration egress must be an egress manifest")
        if not _is_runtime_instance(self.routes, tuple) or any(
            not _is_runtime_instance(route, MigrationRoute) for route in self.routes
        ):
            raise ValueError("migration routes must be immutable route contracts")
        identifiers = tuple(route.identifier for route in self.routes)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("migration routes must be unique")
        if not _is_runtime_instance(self.stateless, bool):
            raise ValueError("migration statelessness must be explicit")


@dataclass(frozen=True, slots=True, kw_only=True)
class MigrationToolDiff:
    """One named tool's schema and reviewed-metadata drift."""

    name: str
    input_change: SchemaChange
    output_change: SchemaChange
    description_changed: bool
    scope_changed: bool
    policy_changed: bool
    lifecycle_changed: bool

    @property
    def breaking(self) -> bool:
        return (
            self.input_change is SchemaChange.BREAKING
            or self.output_change is SchemaChange.BREAKING
            or self.policy_changed
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class MigrationDiff:
    """Review artifact that separates observable drift from cutover eligibility."""

    tool_diffs: tuple[MigrationToolDiff, ...]
    added_tools: tuple[str, ...]
    removed_tools: tuple[str, ...]
    added_egress: tuple[str, ...]
    removed_egress: tuple[str, ...]
    added_routes: tuple[str, ...]
    removed_routes: tuple[str, ...]
    lifecycle_changed: bool
    target_stateless: bool

    @property
    def requires_major_version(self) -> bool:
        return bool(self.removed_tools) or any(item.breaking for item in self.tool_diffs)

    @property
    def cutover_ready(self) -> bool:
        return not self.requires_major_version and self.target_stateless


def _discovery_lifecycle(manifest: ToolManifest) -> str | None:
    discovery = manifest.metadata.discovery
    return None if discovery is None else discovery.lifecycle


def _tool_diff(previous: ToolManifest, current: ToolManifest) -> MigrationToolDiff:
    previous_metadata = previous.metadata
    current_metadata = current.metadata
    return MigrationToolDiff(
        name=current.normalized_name,
        input_change=classify_schema_change(
            previous.input_schema,
            current.input_schema,
            direction=SchemaDirection.INPUT,
        ),
        output_change=classify_schema_change(
            previous.output_schema,
            current.output_schema,
            direction=SchemaDirection.OUTPUT,
        ),
        description_changed=previous_metadata.description != current_metadata.description,
        scope_changed=previous_metadata.required_scopes != current_metadata.required_scopes,
        policy_changed=(
            previous_metadata.effect,
            previous_metadata.approval,
            previous_metadata.idempotency,
        )
        != (
            current_metadata.effect,
            current_metadata.approval,
            current_metadata.idempotency,
        ),
        lifecycle_changed=_discovery_lifecycle(previous) != _discovery_lifecycle(current),
    )


def compare_migration_surfaces(
    previous: MigrationSurface,
    current: MigrationSurface,
) -> MigrationDiff:
    """Return a deterministic review record; never shifts traffic or stores state."""

    if not _is_runtime_instance(previous, MigrationSurface) or not _is_runtime_instance(
        current, MigrationSurface
    ):
        raise ValueError("migration comparison requires two migration surfaces")
    previous_tools = {tool.normalized_name: tool for tool in previous.tools}
    current_tools = {tool.normalized_name: tool for tool in current.tools}
    shared = tuple(sorted(previous_tools.keys() & current_tools.keys()))
    diffs = tuple(_tool_diff(previous_tools[name], current_tools[name]) for name in shared)
    previous_egress = {item.authority for item in previous.egress.destinations}
    current_egress = {item.authority for item in current.egress.destinations}
    previous_routes = {route.identifier for route in previous.routes}
    current_routes = {route.identifier for route in current.routes}
    return MigrationDiff(
        tool_diffs=diffs,
        added_tools=tuple(sorted(current_tools.keys() - previous_tools.keys())),
        removed_tools=tuple(sorted(previous_tools.keys() - current_tools.keys())),
        added_egress=tuple(sorted(current_egress - previous_egress)),
        removed_egress=tuple(sorted(previous_egress - current_egress)),
        added_routes=tuple(sorted(current_routes - previous_routes)),
        removed_routes=tuple(sorted(previous_routes - current_routes)),
        lifecycle_changed=previous.stateless != current.stateless,
        target_stateless=current.stateless,
    )


__all__ = [
    "MigrationDiff",
    "MigrationRoute",
    "MigrationSurface",
    "MigrationToolDiff",
    "compare_migration_surfaces",
]
