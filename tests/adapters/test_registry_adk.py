from __future__ import annotations

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from types import SimpleNamespace
from typing import cast

import pytest

from tesserix_mcp_runtime import RegistryADKServer, RegistryToolPin
from tesserix_mcp_runtime.adapters import registry_adk


@dataclass(frozen=True, slots=True, kw_only=True)
class _McpServerConfig:
    name: str
    endpoint: str
    allow: tuple[str, ...]
    deny: tuple[str, ...]
    prefix: str
    max_tools: int
    max_schema_bytes: int
    transport: str


def _projection() -> RegistryADKServer:
    return RegistryADKServer(
        name="orders",
        endpoint="https://gateway.example.com/gateway/orders/mcp",
        allow=("orders_get",),
        deny=("orders_delete",),
        prefix="orders",
        max_tools=8,
        max_schema_bytes=32 * 1024,
        artifact_ref="mcpservers/tenant-orders/orders@1.2.3",
        artifact_digest=f"sha256:{'a' * 64}",
        tool_pins=(
            RegistryToolPin(
                name="orders_get",
                input_fingerprint="b" * 64,
                output_fingerprint="c" * 64,
            ),
        ),
    )


def _exact_release(distribution: str) -> str:
    assert distribution == registry_adk.ADK_DISTRIBUTION
    return registry_adk.ADK_RELEASE


def test_registry_projection_constructs_the_existing_adk_server_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def module(name: str) -> object:
        assert name == "tesserix_adk.core.config"
        return SimpleNamespace(McpServerConfig=_McpServerConfig)

    monkeypatch.setattr(registry_adk, "distribution_version", _exact_release)
    monkeypatch.setattr(registry_adk, "import_module", module)

    config = registry_adk.to_adk_mcp_server_config(_projection())

    assert (
        config.name,
        config.endpoint,
        config.allow,
        config.deny,
        config.prefix,
        config.max_tools,
        config.max_schema_bytes,
        config.transport,
    ) == (
        "orders",
        "https://gateway.example.com/gateway/orders/mcp",
        ("orders_get",),
        ("orders_delete",),
        "orders",
        8,
        32 * 1024,
        "http",
    )


def test_registry_adk_adapter_reports_a_missing_optional_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(distribution: str) -> str:
        raise PackageNotFoundError(distribution)

    monkeypatch.setattr(registry_adk, "distribution_version", missing)

    with pytest.raises(registry_adk.ADKBridgeDependencyError, match=r"tesserix-adk==0\.53\.1"):
        registry_adk.to_adk_mcp_server_config(_projection())


def test_registry_adk_adapter_rejects_a_different_adk_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def wrong_release(distribution: str) -> str:
        assert distribution == registry_adk.ADK_DISTRIBUTION
        return "0.0.0"

    monkeypatch.setattr(registry_adk, "distribution_version", wrong_release)

    with pytest.raises(registry_adk.ADKBridgeDependencyError, match="requires"):
        registry_adk.to_adk_mcp_server_config(_projection())


def test_registry_adk_adapter_reports_an_unloadable_config_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(name: str) -> object:
        assert name == "tesserix_adk.core.config"
        raise ImportError("private import detail")

    monkeypatch.setattr(registry_adk, "distribution_version", _exact_release)
    monkeypatch.setattr(registry_adk, "import_module", unavailable)

    with pytest.raises(registry_adk.ADKBridgeDependencyError) as caught:
        registry_adk.to_adk_mcp_server_config(_projection())
    assert "private" not in str(caught.value)


@pytest.mark.parametrize(
    "module",
    [SimpleNamespace(), SimpleNamespace(McpServerConfig=42)],
    ids=["missing", "non-callable"],
)
def test_registry_adk_adapter_rejects_an_invalid_config_factory(
    monkeypatch: pytest.MonkeyPatch,
    module: object,
) -> None:
    def import_config(name: str) -> object:
        assert name == "tesserix_adk.core.config"
        return module

    monkeypatch.setattr(registry_adk, "distribution_version", _exact_release)
    monkeypatch.setattr(registry_adk, "import_module", import_config)

    with pytest.raises(registry_adk.ADKBridgeDependencyError, match="invalid"):
        registry_adk.to_adk_mcp_server_config(_projection())


def test_registry_adk_adapter_rejects_an_invalid_config_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def invalid_config(**values: object) -> object:
        del values
        return object()

    def module(name: str) -> object:
        assert name == "tesserix_adk.core.config"
        return SimpleNamespace(McpServerConfig=invalid_config)

    monkeypatch.setattr(registry_adk, "distribution_version", _exact_release)
    monkeypatch.setattr(registry_adk, "import_module", module)

    with pytest.raises(registry_adk.ADKBridgeDependencyError, match="invalid"):
        registry_adk.to_adk_mcp_server_config(_projection())


def test_registry_adk_adapter_requires_an_exact_projection() -> None:
    with pytest.raises(TypeError, match="exact Registry ADK projection"):
        registry_adk.to_adk_mcp_server_config(cast(RegistryADKServer, object()))
