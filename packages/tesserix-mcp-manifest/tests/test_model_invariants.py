from __future__ import annotations

import json

import pytest
from tesserix_mcp_manifest import (
    ManifestVisibility,
    Ownership,
    PackageIdentity,
    PackageRegistry,
    PackageTransport,
    RemoteEndpoint,
    ServerAuthoringManifest,
    extract_server_json,
)


@pytest.mark.parametrize(
    "transport",
    [
        PackageTransport(type="stdio", url=None),
        PackageTransport(type="streamable-http", url="http://127.0.0.1:8000/mcp"),
    ],
)
def test_valid_local_transport_shapes_are_accepted(transport: PackageTransport) -> None:
    assert transport.type in {"stdio", "streamable-http"}
    assert (transport.url is None) is (transport.type == "stdio")


@pytest.mark.parametrize(
    "values",
    [
        {"type": "stdio", "url": "http://127.0.0.1:8000/mcp"},
        {"type": "streamable-http"},
    ],
    ids=["stdio-with-url", "http-without-url"],
)
def test_invalid_local_transport_shapes_are_rejected(values: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        PackageTransport.model_validate(values)


@pytest.mark.parametrize("version", ["latest", "^1.2.3", "1.x", "1.*"])
def test_package_versions_must_be_exact(version: str) -> None:
    with pytest.raises(ValueError):
        PackageIdentity(
            registry_type=PackageRegistry.PYPI,
            identifier="orders-mcp",
            version=version,
            transport=PackageTransport(type="stdio"),
        )


def test_oci_requires_a_separate_digest() -> None:
    with pytest.raises(ValueError):
        PackageIdentity(
            registry_type=PackageRegistry.OCI,
            identifier="ghcr.io/tesserix/orders-mcp",
            transport=PackageTransport(type="stdio"),
        )


def test_non_oci_package_rejects_an_image_digest() -> None:
    with pytest.raises(ValueError):
        PackageIdentity(
            registry_type=PackageRegistry.PYPI,
            identifier="orders-mcp",
            image_digest=f"sha256:{'a' * 64}",
            transport=PackageTransport(type="stdio"),
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://pypi.example.com",
        "https://user:canary@pypi.example.com",
        "https://pypi.example.com?token=canary",
    ],
)
def test_package_registry_url_rejects_unsafe_values(url: str) -> None:
    with pytest.raises(ValueError):
        PackageIdentity(
            registry_type=PackageRegistry.PYPI,
            identifier="orders-mcp",
            registry_base_url=url,
            transport=PackageTransport(type="stdio"),
        )


def test_direct_package_identifier_rejects_query_credentials() -> None:
    with pytest.raises(ValueError):
        PackageIdentity(
            registry_type=PackageRegistry.MCPB,
            identifier="https://downloads.example.com/orders.mcpb?token=canary",
            file_sha256="a" * 64,
            transport=PackageTransport(type="stdio"),
        )


def test_mcpb_package_requires_a_file_digest() -> None:
    with pytest.raises(ValueError):
        PackageIdentity(
            registry_type=PackageRegistry.MCPB,
            identifier="https://downloads.example.com/orders.mcpb",
            transport=PackageTransport(type="stdio"),
        )


def test_ownership_namespace_is_the_tenant_boundary() -> None:
    with pytest.raises(ValueError):
        Ownership(
            namespace="tenant-a",
            tenant_id="tenant-b",
            visibility=ManifestVisibility.PRIVATE,
        )


def test_authoring_manifest_requires_a_portable_delivery(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    document = remote_manifest.model_dump(mode="json")
    document["remote"] = None
    document["package"] = None

    with pytest.raises(ValueError):
        ServerAuthoringManifest.model_validate_json(json.dumps(document))


def test_invalid_url_port_is_rejected() -> None:
    with pytest.raises(ValueError):
        RemoteEndpoint(url="https://mcp.example.com:99999/mcp")


@pytest.mark.parametrize(
    "document",
    [
        {"kind": "Tool", "spec": {}},
        {"kind": "MCPServer", "spec": []},
    ],
    ids=["wrong-kind", "non-object-spec"],
)
def test_round_trip_rejects_non_registry_envelopes(document: object) -> None:
    with pytest.raises(ValueError):
        extract_server_json(json.dumps(document).encode())
