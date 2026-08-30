from __future__ import annotations

import json
from difflib import unified_diff
from pathlib import Path

import pytest
from tesserix_mcp_manifest import (
    ManifestVisibility,
    RuntimeAdapter,
    ServerAuthoringManifest,
    compile_manifests,
    extract_server_json,
    load_authoring_manifest,
)

GOLDENS = Path(__file__).with_name("goldens")


@pytest.mark.parametrize(
    ("case", "visibility", "adapter"),
    [
        ("remote-public-native", ManifestVisibility.PUBLIC, RuntimeAdapter.NATIVE),
        ("package-internal-adk", ManifestVisibility.INTERNAL, RuntimeAdapter.ADK),
        ("oci-private-native", ManifestVisibility.PRIVATE, RuntimeAdapter.NATIVE),
    ],
)
def test_checked_in_goldens_round_trip_without_drift(
    case: str,
    visibility: ManifestVisibility,
    adapter: RuntimeAdapter,
) -> None:
    directory = GOLDENS / case
    manifest = load_authoring_manifest((directory / "authoring.json").read_bytes())
    compiled = compile_manifests(manifest, runtime_version=manifest.version)

    assert compiled.server_json == (directory / "server.json").read_bytes()
    assert compiled.registry_manifest == (directory / "registry.json").read_bytes()
    assert extract_server_json(compiled.registry_manifest) == compiled.server_json

    envelope = json.loads(compiled.registry_manifest)
    assert envelope["metadata"]["visibility"] == visibility.value
    assert envelope["spec"]["x-tesserix"]["adapter"] == adapter.value
    assert "credentialRef" not in json.loads(compiled.server_json)
    assert b'"password"' not in compiled.registry_manifest
    assert b'"token"' not in compiled.registry_manifest
    assert b"timestamp" not in compiled.registry_manifest.lower()


def test_semantic_and_schema_fingerprint_changes_produce_a_reviewable_diff(
    remote_manifest: ServerAuthoringManifest,
) -> None:
    changed = remote_manifest.model_copy(
        update={
            "semantic": remote_manifest.semantic.model_copy(
                update={"keywords": (*remote_manifest.semantic.keywords, "fulfillment")}
            ),
            "tools": (remote_manifest.tools[0].model_copy(update={"input_fingerprint": "c" * 64}),),
        }
    )
    before = compile_manifests(remote_manifest, runtime_version="1.2.3")
    after = compile_manifests(changed, runtime_version="1.2.3")

    assert after.server_json == before.server_json
    diff = "".join(
        unified_diff(
            before.registry_manifest.decode().splitlines(keepends=True),
            after.registry_manifest.decode().splitlines(keepends=True),
        )
    )
    assert '+          "fulfillment",\n' in diff
    assert f'-          "inputFingerprint": "{"a" * 64}",\n' in diff
    assert f'+          "inputFingerprint": "{"c" * 64}",\n' in diff
