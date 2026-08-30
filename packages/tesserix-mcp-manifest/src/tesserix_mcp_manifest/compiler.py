from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from pydantic import TypeAdapter, ValidationError

from tesserix_mcp_manifest._annotations import is_reserved_annotation
from tesserix_mcp_manifest._secret_fields import is_secret_key
from tesserix_mcp_manifest.constants import (
    AUTHORING_MANIFEST_VERSION,
    DISCOVERY_CAPABILITIES_ANNOTATION,
    DISCOVERY_REQUIRES_ANNOTATION,
    DISCOVERY_SUMMARY_ANNOTATION,
    DISCOVERY_WHEN_TO_USE_ANNOTATION,
    OFFICIAL_SCHEMA_URL,
    REGISTRY_API_VERSION,
    REGISTRY_EXTENSION_KEY,
)
from tesserix_mcp_manifest.errors import (
    ManifestValidationCode,
    ManifestValidationError,
    ManifestVersionMismatchError,
)
from tesserix_mcp_manifest.models import PackageIdentity, ServerAuthoringManifest, ToolSummary
from tesserix_mcp_runtime import JsonValue

_JSON_OBJECT_ADAPTER = TypeAdapter(dict[str, JsonValue])


def _canonical_json(document: dict[str, JsonValue]) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()


def _without_none(document: dict[str, JsonValue | None]) -> dict[str, JsonValue]:
    return {key: value for key, value in document.items() if value is not None}


def _sorted_strings(values: Iterable[str]) -> list[JsonValue]:
    result: list[JsonValue] = []
    result.extend(sorted(values))
    return result


def _string_map(values: Mapping[str, str]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    result.update(values)
    return result


def _optional_sorted_strings(values: Iterable[str]) -> list[JsonValue] | None:
    result = _sorted_strings(values)
    return result or None


def _semantic_annotations(manifest: ServerAuthoringManifest) -> dict[str, str]:
    semantic = manifest.semantic
    annotations: dict[str, str] = {}
    if semantic.summary is not None:
        annotations[DISCOVERY_SUMMARY_ANNOTATION] = semantic.summary
    if semantic.when_to_use:
        annotations[DISCOVERY_WHEN_TO_USE_ANNOTATION] = "; ".join(sorted(semantic.when_to_use))
    if semantic.capabilities:
        annotations[DISCOVERY_CAPABILITIES_ANNOTATION] = ", ".join(sorted(semantic.capabilities))
    if semantic.requires:
        annotations[DISCOVERY_REQUIRES_ANNOTATION] = ", ".join(sorted(semantic.requires))
    return annotations


def _package_document(package: PackageIdentity) -> dict[str, JsonValue]:
    identifier = package.identifier
    if package.image_digest is not None:
        identifier = f"{identifier}@{package.image_digest}"
    transport = _without_none(
        {
            "type": package.transport.type,
            "url": package.transport.url,
        }
    )
    return _without_none(
        {
            "fileSha256": package.file_sha256,
            "identifier": identifier,
            "registryBaseUrl": package.registry_base_url,
            "registryType": package.registry_type.value,
            "runtimeHint": package.runtime_hint,
            "transport": transport,
            "version": package.version,
        }
    )


def _tool_document(tool: ToolSummary) -> dict[str, JsonValue]:
    properties: dict[str, JsonValue] = {}
    required: list[JsonValue] = []
    for input_field in sorted(tool.inputs, key=lambda item: item.name):
        properties[input_field.name] = _without_none(
            {
                "description": input_field.description,
                "type": input_field.json_type,
            }
        )
        if input_field.required:
            required.append(input_field.name)
    return _without_none(
        {
            "capabilities": _sorted_strings(tool.semantic.capabilities),
            "description": tool.description,
            "inputFingerprint": tool.input_fingerprint,
            "inputSchema": {
                "properties": properties,
                "required": required,
                "type": "object",
            },
            "name": tool.name,
            "outputFingerprint": tool.output_fingerprint,
            "requires": _sorted_strings(tool.semantic.requires),
            "requiredScopes": _sorted_strings(tool.required_scopes),
            "riskLevel": tool.semantic.risk.value if tool.semantic.risk is not None else None,
            "semantic": _without_none(
                {
                    "examples": _optional_sorted_strings(tool.semantic.examples),
                    "notFor": _optional_sorted_strings(tool.semantic.not_for),
                    "summary": tool.semantic.summary,
                    "whenToUse": _optional_sorted_strings(tool.semantic.when_to_use),
                }
            ),
            "status": tool.lifecycle.value,
        }
    )


def _portable_document(manifest: ServerAuthoringManifest) -> dict[str, JsonValue]:
    repository = _without_none(
        {
            "id": manifest.repository.id,
            "source": manifest.repository.source,
            "subfolder": manifest.repository.subfolder,
            "url": manifest.repository.url,
        }
    )
    document: dict[str, JsonValue | None] = {
        "$schema": OFFICIAL_SCHEMA_URL,
        "description": manifest.description,
        "name": manifest.name,
        "repository": repository,
        "title": manifest.title,
        "version": manifest.version,
    }
    if manifest.remote is not None:
        document["remotes"] = [
            {
                "type": "streamable-http",
                "url": manifest.remote.url,
            }
        ]
    if manifest.package is not None:
        document["packages"] = [_package_document(manifest.package)]
    return _without_none(document)


def _registry_document(
    manifest: ServerAuthoringManifest,
    portable: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    labels = dict(manifest.ownership.labels)
    labels["transport"] = "streamable-http" if manifest.remote is not None else "package"
    annotations = dict(manifest.ownership.annotations)
    annotations.update(_semantic_annotations(manifest))
    metadata = _without_none(
        {
            "annotations": _string_map(annotations) or None,
            "labels": _string_map(labels),
            "name": manifest.name,
            "namespace": manifest.ownership.namespace,
            "orgId": manifest.ownership.org_id,
            "tag": manifest.version,
            "teamId": manifest.ownership.team_id,
            "tenantId": manifest.ownership.tenant_id,
            "visibility": manifest.ownership.visibility.value,
        }
    )
    extension: dict[str, JsonValue] = {
        "adapter": manifest.adapter.value,
        "authoringVersion": AUTHORING_MANIFEST_VERSION,
        "egressHosts": _sorted_strings(manifest.egress_hosts),
        "lifecycle": manifest.lifecycle.value,
        "protocolVersions": _sorted_strings(manifest.protocol_versions),
        "requiredScopes": _sorted_strings(manifest.required_scopes),
        "routePolicy": {
            "directAccess": manifest.route_policy.direct_access,
            "gatewayPath": manifest.route_policy.gateway_path,
        },
        "semantic": _without_none(
            {
                "capabilities": _sorted_strings(manifest.semantic.capabilities),
                "domains": _sorted_strings(manifest.semantic.domains),
                "examples": _optional_sorted_strings(manifest.semantic.examples),
                "keywords": _sorted_strings(manifest.semantic.keywords),
                "notFor": _optional_sorted_strings(manifest.semantic.not_for),
                "requires": _optional_sorted_strings(manifest.semantic.requires),
                "risk": (
                    manifest.semantic.risk.value if manifest.semantic.risk is not None else None
                ),
                "summary": manifest.semantic.summary,
                "whenToUse": _optional_sorted_strings(manifest.semantic.when_to_use),
            }
        ),
        "tools": [
            _tool_document(tool) for tool in sorted(manifest.tools, key=lambda item: item.name)
        ],
    }
    spec = dict(portable)
    spec[REGISTRY_EXTENSION_KEY] = extension
    if manifest.credential_ref is not None:
        spec["credentialRef"] = {
            "key": manifest.credential_ref.key,
            "secretName": manifest.credential_ref.secret_name,
        }
    return {
        "apiVersion": REGISTRY_API_VERSION,
        "kind": "MCPServer",
        "metadata": metadata,
        "spec": spec,
    }


@dataclass(frozen=True, slots=True, kw_only=True)
class CompiledManifests:
    server_json: bytes
    registry_manifest: bytes

    @property
    def server_digest(self) -> str:
        return f"sha256:{hashlib.sha256(self.server_json).hexdigest()}"

    @property
    def registry_digest(self) -> str:
        return f"sha256:{hashlib.sha256(self.registry_manifest).hexdigest()}"


def compile_manifests(
    manifest: ServerAuthoringManifest,
    *,
    runtime_version: str,
) -> CompiledManifests:
    if any(is_reserved_annotation(key) for key in manifest.ownership.annotations):
        raise ManifestValidationError(ManifestValidationCode.RESERVED_ANNOTATION)
    if any(is_secret_key(key) for key in manifest.ownership.labels) or any(
        is_secret_key(key) for key in manifest.ownership.annotations
    ):
        raise ManifestValidationError(ManifestValidationCode.SECRET_FIELD)
    try:
        manifest = ServerAuthoringManifest.model_validate(manifest.model_dump())
    except ValidationError:
        raise ManifestValidationError(ManifestValidationCode.INVALID_MANIFEST) from None
    if runtime_version != manifest.version:
        raise ManifestVersionMismatchError(
            component="runtime",
            actual_version=runtime_version,
            manifest_version=manifest.version,
        )
    package_version = manifest.package.version if manifest.package is not None else None
    if package_version is not None and package_version != manifest.version:
        raise ManifestVersionMismatchError(
            component="package",
            actual_version=package_version,
            manifest_version=manifest.version,
        )
    portable = _portable_document(manifest)
    registry = _registry_document(manifest, portable)
    return CompiledManifests(
        server_json=_canonical_json(portable),
        registry_manifest=_canonical_json(registry),
    )


def extract_server_json(registry_manifest: bytes) -> bytes:
    try:
        document = _JSON_OBJECT_ADAPTER.validate_json(registry_manifest, strict=True)
    except ValidationError:
        raise ValueError("invalid_registry_manifest") from None
    if document.get("kind") != "MCPServer":
        raise ValueError("invalid_registry_manifest")
    spec = document.get("spec")
    if not isinstance(spec, dict):
        raise ValueError("invalid_registry_spec")
    portable: dict[str, JsonValue] = {
        key: value
        for key, value in spec.items()
        if key not in {REGISTRY_EXTENSION_KEY, "credentialRef"}
    }
    return _canonical_json(portable)


__all__ = ["CompiledManifests", "compile_manifests", "extract_server_json"]
