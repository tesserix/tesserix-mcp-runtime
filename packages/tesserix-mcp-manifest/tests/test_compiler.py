from __future__ import annotations

import json
from hashlib import sha256

import pytest
from tesserix_mcp_manifest import (
    OFFICIAL_SCHEMA_URL,
    ManifestValidationCode,
    ManifestValidationError,
    ManifestVersionMismatchError,
    ManifestVisibility,
    PackageIdentity,
    PackageRegistry,
    PackageTransport,
    RemoteEndpoint,
    RuntimeAdapter,
    ServerAuthoringManifest,
    compile_manifests,
    extract_server_json,
)


def test_same_source_compiles_identical_portable_fields_in_both_artifacts(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    manifest = remote_manifest
    compiled = compile_manifests(manifest, runtime_version="1.2.3")
    server = json.loads(compiled.server_json)
    envelope = json.loads(compiled.registry_manifest)

    assert server == json.loads(extract_server_json(compiled.registry_manifest))
    assert server == {
        "$schema": OFFICIAL_SCHEMA_URL,
        "description": "Read bounded synthetic order data.",
        "name": "io.github.tesserix/orders",
        "remotes": [
            {
                "type": "streamable-http",
                "url": "https://mcp.example.com/orders/mcp",
            }
        ],
        "repository": {
            "id": "123456789",
            "source": "github",
            "url": "https://github.com/tesserix/orders-mcp",
        },
        "title": "Orders MCP",
        "version": "1.2.3",
    }
    assert envelope["apiVersion"] == "registry.agentic.dev/v1alpha1"
    assert envelope["kind"] == "MCPServer"
    assert envelope["metadata"] == {
        "annotations": {"owner": "platform"},
        "labels": {"domain": "orders", "transport": "streamable-http"},
        "name": "io.github.tesserix/orders",
        "namespace": "tenant-orders",
        "orgId": "tesserix",
        "tag": "1.2.3",
        "tenantId": "tenant-orders",
        "visibility": "public",
    }
    assert envelope["spec"]["credentialRef"] == {
        "key": "access-credential",
        "secretName": "orders-mcp-upstream",
    }
    assert envelope["spec"]["x-tesserix"]["adapter"] == "native"
    assert envelope["spec"]["x-tesserix"]["tools"][0]["name"] == "orders_get"


def test_runtime_version_mismatch_is_a_typed_build_failure(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    with pytest.raises(ManifestVersionMismatchError) as raised:
        compile_manifests(remote_manifest, runtime_version="1.2.4")

    assert raised.value.component == "runtime"
    assert raised.value.actual_version == "1.2.4"
    assert raised.value.manifest_version == "1.2.3"
    assert str(raised.value) == "runtime version does not match manifest version"


def test_package_version_mismatch_is_a_typed_build_failure(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    manifest = remote_manifest.model_copy(
        update={
            "package": PackageIdentity(
                registry_type=PackageRegistry.PYPI,
                identifier="tesserix-orders-mcp",
                version="1.2.4",
                transport=PackageTransport(type="stdio"),
            )
        }
    )

    with pytest.raises(ManifestVersionMismatchError) as raised:
        compile_manifests(manifest, runtime_version="1.2.3")

    assert raised.value.component == "package"
    assert raised.value.actual_version == "1.2.4"
    assert raised.value.manifest_version == "1.2.3"


def test_compilation_is_byte_stable_and_content_addressed(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    first = compile_manifests(remote_manifest, runtime_version="1.2.3")
    second = compile_manifests(remote_manifest, runtime_version="1.2.3")

    assert first == second
    assert first.server_json.endswith(b"\n")
    assert first.registry_manifest.endswith(b"\n")
    assert first.server_digest == f"sha256:{sha256(first.server_json).hexdigest()}"
    assert first.registry_digest == f"sha256:{sha256(first.registry_manifest).hexdigest()}"
    assert b"timestamp" not in first.server_json.lower()
    assert b"timestamp" not in first.registry_manifest.lower()


def test_compiler_rejects_secret_shaped_metadata_added_after_validation(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    remote_manifest.ownership.annotations["apiToken"] = "compiler-secret-canary"

    with pytest.raises(ManifestValidationError) as raised:
        compile_manifests(remote_manifest, runtime_version="1.2.3")

    assert raised.value.code is ManifestValidationCode.SECRET_FIELD
    assert "compiler-secret-canary" not in str(raised.value)
    assert "compiler-secret-canary" not in repr(raised.value)


def test_unordered_metadata_input_has_one_canonical_order(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    reordered = remote_manifest.model_copy(
        update={
            "protocol_versions": tuple(reversed(remote_manifest.protocol_versions)),
            "semantic": remote_manifest.semantic.model_copy(
                update={"keywords": tuple(reversed(remote_manifest.semantic.keywords))}
            ),
        }
    )

    assert compile_manifests(reordered, runtime_version="1.2.3") == compile_manifests(
        remote_manifest,
        runtime_version="1.2.3",
    )


@pytest.mark.parametrize(
    "url",
    [
        "/relative/mcp",
        "http://mcp.example.com/orders/mcp",
        "https://user:canary@mcp.example.com/orders/mcp",
        "https://mcp.example.com/orders/mcp?token=canary",
        "https://mcp.example.com/orders/mcp#canary",
        "https://mcp.example.com/orders/%2e%2e/admin",
        "https://mcp.example.com/orders/%5cadmin",
        "ftp://mcp.example.com/orders/mcp",
        "https://mcp.example.com/orders/mcp?",
        "https://mcp.example.com/orders/mcp#",
        "https://user%3Acanary%40mcp.example.com/orders/mcp",
        "https://mcp.example.com/orders/%252e%252e/admin",
        "https://mcp.example.com/orders/%zz/admin",
        f"https://mcp.example.com/{'x' * 2_100}",
    ],
    ids=[
        "relative",
        "plaintext-http",
        "userinfo",
        "query",
        "fragment",
        "encoded-traversal",
        "encoded-backslash",
        "unsupported-scheme",
        "empty-query",
        "empty-fragment",
        "encoded-userinfo",
        "double-encoded-traversal",
        "malformed-percent-escape",
        "overlong",
    ],
)
def test_deployed_remote_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(ValueError):
        RemoteEndpoint(url=url)


def test_oci_package_compiles_a_digest_qualified_portable_identifier(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    digest = f"sha256:{'c' * 64}"
    manifest = remote_manifest.model_copy(
        update={
            "remote": None,
            "package": PackageIdentity(
                registry_type=PackageRegistry.OCI,
                identifier="ghcr.io/tesserix/orders-mcp:1.2.3",
                image_digest=digest,
                runtime_hint="docker",
                transport=PackageTransport(type="stdio"),
            ),
        }
    )

    compiled = compile_manifests(manifest, runtime_version="1.2.3")
    server = json.loads(compiled.server_json)

    assert server["packages"] == [
        {
            "identifier": f"ghcr.io/tesserix/orders-mcp:1.2.3@{digest}",
            "registryType": "oci",
            "runtimeHint": "docker",
            "transport": {"type": "stdio"},
        }
    ]
    assert server == json.loads(extract_server_json(compiled.registry_manifest))


def test_registry_package_identity_is_preserved_portably(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    manifest = remote_manifest.model_copy(
        update={
            "remote": None,
            "package": PackageIdentity(
                registry_type=PackageRegistry.PYPI,
                identifier="tesserix-orders-mcp",
                version="1.2.3",
                registry_base_url="https://pypi.org",
                runtime_hint="uvx",
                file_sha256="d" * 64,
                transport=PackageTransport(type="stdio"),
            ),
        }
    )

    server = json.loads(compile_manifests(manifest, runtime_version="1.2.3").server_json)

    assert server["packages"] == [
        {
            "fileSha256": "d" * 64,
            "identifier": "tesserix-orders-mcp",
            "registryBaseUrl": "https://pypi.org",
            "registryType": "pypi",
            "runtimeHint": "uvx",
            "transport": {"type": "stdio"},
            "version": "1.2.3",
        }
    ]


@pytest.mark.parametrize("adapter", list(RuntimeAdapter))
@pytest.mark.parametrize("visibility", list(ManifestVisibility))
def test_registry_envelope_covers_every_adapter_and_visibility(
    remote_manifest: ServerAuthoringManifest,
    adapter: RuntimeAdapter,
    visibility: ManifestVisibility,
) -> None:
    manifest = remote_manifest.model_copy(
        update={
            "adapter": adapter,
            "ownership": remote_manifest.ownership.model_copy(update={"visibility": visibility}),
        }
    )

    envelope = json.loads(compile_manifests(manifest, runtime_version="1.2.3").registry_manifest)

    assert envelope["metadata"]["visibility"] == visibility.value
    assert envelope["spec"]["x-tesserix"]["adapter"] == adapter.value
