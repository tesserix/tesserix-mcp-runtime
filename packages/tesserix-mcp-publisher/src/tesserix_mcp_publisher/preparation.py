"""Deterministic local preparation before any publication write."""

from __future__ import annotations

import json
from typing import Any, cast

from tesserix_mcp_manifest import (
    ManifestError,
    PackageRegistry,
    compile_manifests,
    lint_semantic_manifest,
    load_authoring_manifest,
)

from tesserix_mcp_runtime import JsonValue, SecretRedactor, registry_artifact_digest

from .errors import PublicationErrorCode, PublicationValidationError
from .models import PreparedPublication, PublicationEvidence


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def _canonical_json(document: dict[str, JsonValue]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _mapping(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)
    return value


def _text(value: JsonValue) -> str:
    if not isinstance(value, str):
        raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)
    return value


def _registry_labels(metadata: dict[str, JsonValue], *, namespace: str) -> dict[str, str]:
    raw_labels = metadata.get("labels")
    if not isinstance(raw_labels, dict) or not all(
        isinstance(value, str) for value in raw_labels.values()
    ):
        raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)
    labels = cast(dict[str, str], dict(raw_labels))
    tenant = metadata.get("tenantId") or namespace
    visibility = metadata.get("visibility") or "private"
    if not isinstance(tenant, str) or not isinstance(visibility, str):
        raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)
    labels["registry.agentic.dev/tenant"] = tenant
    labels["registry.agentic.dev/visibility"] = visibility
    org = metadata.get("orgId")
    if org:
        if not isinstance(org, str):
            raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)
        labels["registry.agentic.dev/org"] = org
    return labels


def _validate_delivery_digest(
    *,
    manifest_package: object,
    evidence: PublicationEvidence,
) -> None:
    if manifest_package is None:
        raise PublicationValidationError(PublicationErrorCode.EVIDENCE_REQUIRED)
    package = manifest_package
    registry_type = getattr(package, "registry_type", None)
    image_digest = getattr(package, "image_digest", None)
    file_sha256 = getattr(package, "file_sha256", None)
    if registry_type is PackageRegistry.OCI and image_digest != evidence.artifact.digest:
        raise PublicationValidationError(PublicationErrorCode.ARTIFACT_DIGEST_MISMATCH)
    if _is_runtime_instance(file_sha256, str) and (
        f"sha256:{file_sha256}" != evidence.artifact.digest
    ):
        raise PublicationValidationError(PublicationErrorCode.ARTIFACT_DIGEST_MISMATCH)


def prepare_publication(
    source: bytes,
    *,
    runtime_version: str,
    evidence: PublicationEvidence | None,
) -> PreparedPublication:
    """Validate and compile one immutable MCP publication without I/O mutation."""

    if evidence is None or not _is_runtime_instance(evidence, PublicationEvidence):
        raise PublicationValidationError(PublicationErrorCode.EVIDENCE_REQUIRED)
    try:
        if not _is_runtime_instance(source, bytes) or not _is_runtime_instance(
            runtime_version, str
        ):
            raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)
        text = source.decode("utf-8")
        if SecretRedactor().redact_text(text) != text:
            raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)
        manifest = load_authoring_manifest(source)
        if lint_semantic_manifest(manifest):
            raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID)
        _validate_delivery_digest(manifest_package=manifest.package, evidence=evidence)
        compiled = compile_manifests(manifest, runtime_version=runtime_version)
        document = cast(dict[str, JsonValue], json.loads(compiled.registry_manifest))
        metadata = _mapping(document.get("metadata"))
        spec = _mapping(document.get("spec"))
        extension = _mapping(spec.get("x-tesserix"))
        extension["publication"] = evidence.to_document()
        registry_manifest = _canonical_json(document)
        name = _text(metadata.get("name"))
        namespace = _text(metadata.get("namespace"))
        version = _text(metadata.get("tag"))
        digest = registry_artifact_digest(
            kind=_text(document.get("kind")),
            name=name,
            namespace=namespace,
            tag=version,
            labels=_registry_labels(metadata, namespace=namespace),
            spec=spec,
        )
        return PreparedPublication(
            name=name,
            namespace=namespace,
            version=version,
            ref=f"mcpservers/{namespace}/{name}@{version}",
            server_json=compiled.server_json,
            registry_manifest=registry_manifest,
            registry_digest=digest,
            evidence=evidence,
        )
    except PublicationValidationError:
        raise
    except (ManifestError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
        raise PublicationValidationError(PublicationErrorCode.MANIFEST_INVALID) from None
