"""Optional conversion from an exact Registry result to ADK configuration."""

from __future__ import annotations

from importlib import import_module
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from typing import Any, Literal, Protocol, cast, runtime_checkable

from tesserix_mcp_runtime.adapters.adk import (
    ADK_DISTRIBUTION,
    ADK_RELEASE,
    ADKBridgeDependencyError,
)
from tesserix_mcp_runtime.registry_discovery import RegistryADKServer


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


@runtime_checkable
class ADKMcpServerConfig(Protocol):
    """The ADK declaration fields populated by Registry resolution."""

    name: str
    endpoint: str
    allow: tuple[str, ...]
    deny: tuple[str, ...]
    prefix: str
    max_tools: int
    max_schema_bytes: int
    transport: Literal["http"]


class _ADKMcpServerConfigFactory(Protocol):
    def __call__(
        self,
        *,
        name: str,
        endpoint: str,
        allow: tuple[str, ...],
        deny: tuple[str, ...],
        prefix: str,
        max_tools: int,
        max_schema_bytes: int,
        transport: Literal["http"],
    ) -> ADKMcpServerConfig: ...


def _load_factory() -> _ADKMcpServerConfigFactory:
    try:
        installed = distribution_version(ADK_DISTRIBUTION)
    except PackageNotFoundError as error:
        raise ADKBridgeDependencyError(
            "install tesserix-mcp-runtime[adk] to use the Registry ADK adapter"
        ) from error
    if installed != ADK_RELEASE:
        raise ADKBridgeDependencyError(
            f"the Registry ADK adapter requires {ADK_DISTRIBUTION}=={ADK_RELEASE}; "
            f"found {installed}"
        )
    try:
        module = import_module("tesserix_adk.core.config")
    except ImportError as error:
        raise ADKBridgeDependencyError(
            f"{ADK_DISTRIBUTION} {ADK_RELEASE} does not expose McpServerConfig"
        ) from error
    factory = vars(module).get("McpServerConfig")
    if not callable(factory):
        raise ADKBridgeDependencyError(
            f"{ADK_DISTRIBUTION} {ADK_RELEASE} exposes an invalid McpServerConfig"
        )
    return cast(_ADKMcpServerConfigFactory, factory)


def to_adk_mcp_server_config(server: RegistryADKServer) -> ADKMcpServerConfig:
    """Delegate filtering, namespacing, collisions, and live pins to ADK."""

    if not _is_runtime_instance(server, RegistryADKServer):
        raise TypeError("server must be an exact Registry ADK projection")
    config = _load_factory()(
        name=server.name,
        endpoint=server.endpoint,
        allow=server.allow,
        deny=server.deny,
        prefix=server.prefix,
        max_tools=server.max_tools,
        max_schema_bytes=server.max_schema_bytes,
        transport="http",
    )
    if not _is_runtime_instance(config, ADKMcpServerConfig):
        raise ADKBridgeDependencyError(
            f"{ADK_DISTRIBUTION} {ADK_RELEASE} returned an invalid McpServerConfig"
        )
    return config


__all__ = [
    "ADK_DISTRIBUTION",
    "ADK_RELEASE",
    "ADKBridgeDependencyError",
    "ADKMcpServerConfig",
    "to_adk_mcp_server_config",
]
