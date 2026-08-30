from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Literal, cast

_MAX_SBOM_BYTES = 16_777_216
_MAX_LOCK_BYTES = 16_777_216
_MAX_COMPONENTS = 8_192
_CYCLONEDX_VERSIONS = frozenset({"1.5", "1.6", "1.7"})
_WORKSPACE_PACKAGES = (
    "tesserix-mcp-manifest",
    "tesserix-mcp-publisher",
    "tesserix-mcp-runtime",
    "tesserix-mcp-testkit",
)
_REQUIRED_LOCKED_PACKAGES = frozenset({"mcp", "tesserix-adk"})
_REMOVABLE_BASE_PACKAGES = frozenset({"pip"})
_IMAGE_REFERENCE = re.compile(
    r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}\Z"
)
_NORMALIZE_NAME = re.compile(r"[-_.]+")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _read_bounded(path: Path, *, maximum: int, description: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{description} must be a regular file")
    size = path.stat().st_size
    if not 1 <= size <= maximum:
        raise ValueError(f"{description} size is invalid")
    return path.read_bytes()


def _read_cyclonedx(path: Path) -> dict[str, object]:
    encoded = _read_bounded(path, maximum=_MAX_SBOM_BYTES, description="CycloneDX SBOM")
    try:
        value = json.loads(encoded)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("CycloneDX SBOM is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("CycloneDX SBOM must be an object")
    document = cast(dict[str, object], value)
    if (
        document.get("bomFormat") != "CycloneDX"
        or document.get("specVersion") not in _CYCLONEDX_VERSIONS
    ):
        raise ValueError("CycloneDX SBOM format or version is unsupported")
    components_value = document.get("components")
    if not isinstance(components_value, list):
        raise ValueError("CycloneDX SBOM component count is invalid")
    components = cast(list[object], components_value)
    if not 1 <= len(components) <= _MAX_COMPONENTS:
        raise ValueError("CycloneDX SBOM component count is invalid")
    if any(not isinstance(component, dict) for component in components):
        raise ValueError("CycloneDX SBOM components are invalid")
    return document


def _components(document: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], document["components"])


def _normalized(name: str) -> str:
    return _NORMALIZE_NAME.sub("-", name).lower()


def _named_components(
    document: dict[str, object],
    name: str,
) -> list[dict[str, object]]:
    expected = _normalized(name)
    return [
        component
        for component in _components(document)
        if isinstance(component.get("name"), str)
        and _normalized(cast(str, component["name"])) == expected
    ]


def _require_workspace_versions(document: dict[str, object], version: str) -> None:
    for name in _WORKSPACE_PACKAGES:
        matches = _named_components(document, name)
        expected_purl = f"pkg:pypi/{name}@{version}"
        if len(matches) != 1 or matches[0].get("version") != version:
            raise ValueError(f"Python artifact SBOM does not report {name} at {version}")
        if matches[0].get("purl") != expected_purl:
            raise ValueError(f"Python artifact SBOM purl is invalid for {name}")


def _bind_workspace_versions(document: dict[str, object], version: str) -> None:
    for name in _WORKSPACE_PACKAGES:
        matches = _named_components(document, name)
        if len(matches) != 1:
            raise ValueError(f"dependency SBOM must contain exactly one {name} component")
        component = matches[0]
        expected_purl = f"pkg:pypi/{name}@{version}"
        current_version = component.get("version")
        current_purl = component.get("purl")
        if current_version not in (None, version) or current_purl not in (None, expected_purl):
            raise ValueError(f"dependency SBOM conflicts with release version for {name}")
        component["version"] = version
        component["purl"] = expected_purl

    metadata_value = document.get("metadata")
    if not isinstance(metadata_value, dict):
        raise ValueError("dependency SBOM metadata component is invalid")
    metadata = cast(dict[str, object], metadata_value)
    root_value = metadata.get("component")
    if not isinstance(root_value, dict):
        raise ValueError("dependency SBOM metadata component is invalid")
    root = cast(dict[str, object], root_value)
    if _normalized(str(root.get("name", ""))) != "tesserix-mcp-runtime":
        raise ValueError("dependency SBOM root component is invalid")
    root["version"] = version
    root["purl"] = f"pkg:pypi/tesserix-mcp-runtime@{version}"


def _locked_versions(path: Path) -> set[tuple[str, str]]:
    encoded = _read_bounded(path, maximum=_MAX_LOCK_BYTES, description="uv lockfile")
    try:
        document = cast(dict[str, object], tomllib.loads(encoded.decode("utf-8")))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError("uv lockfile is invalid") from error
    packages_value = document.get("package")
    if not isinstance(packages_value, list) or not packages_value:
        raise ValueError("uv lockfile has no packages")
    packages = cast(list[object], packages_value)
    versions: set[tuple[str, str]] = set()
    for package_value in packages:
        if not isinstance(package_value, dict):
            raise ValueError("uv lockfile package is invalid")
        package = cast(dict[str, object], package_value)
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str) and name and version:
            versions.add((_normalized(name), version))
    return versions


def _verify_dependency_components(
    document: dict[str, object],
    locked: set[tuple[str, str]],
) -> int:
    observed: set[tuple[str, str]] = set()
    workspace = set(_WORKSPACE_PACKAGES)
    for component in _components(document):
        name = component.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("dependency SBOM component name is invalid")
        normalized = _normalized(name)
        if normalized in workspace:
            continue
        version = component.get("version")
        purl = component.get("purl")
        if not isinstance(version, str) or not version:
            raise ValueError(f"dependency SBOM component {name} has no version")
        if not isinstance(purl, str) or not purl.startswith("pkg:pypi/"):
            raise ValueError(f"dependency SBOM component {name} has no PyPI purl")
        identity = (normalized, version)
        if identity not in locked:
            raise ValueError(
                f"dependency SBOM component {name}=={version} is not present in uv.lock"
            )
        observed.add(identity)
    missing = sorted(
        name
        for name in _REQUIRED_LOCKED_PACKAGES
        if not any(observed_name == name for observed_name, _ in observed)
    )
    if missing:
        raise ValueError(f"dependency SBOM omits required locked packages: {', '.join(missing)}")
    return len(observed)


def _write_json(path: Path, document: object, *, description: str) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()) or not path.parent.is_dir():
        raise ValueError(f"{description} target is invalid")
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def bind_python_sbom(
    *,
    source: Path,
    target: Path,
    artifact_sbom: Path,
    uv_lock: Path,
    version: str,
) -> dict[str, object]:
    if not version or len(version) > 64:
        raise ValueError("Python release version is invalid")
    artifacts = _read_cyclonedx(artifact_sbom)
    dependencies = _read_cyclonedx(source)
    _require_workspace_versions(artifacts, version)
    _bind_workspace_versions(dependencies, version)
    locked = _locked_versions(uv_lock)
    dependency_count = _verify_dependency_components(dependencies, locked)
    _write_json(target, dependencies, description="bound dependency SBOM")
    return {
        "schema_version": 1,
        "kind": "python",
        "version": version,
        "workspace_packages": list(_WORKSPACE_PACKAGES),
        "artifact_components": len(_components(artifacts)),
        "locked_dependency_components": dependency_count,
        "artifact_sbom_sha256": _sha256(artifact_sbom),
        "dependency_sbom_sha256": _sha256(target),
        "uv_lock_sha256": _sha256(uv_lock),
        "passed": True,
    }


def _validate_image_reference(reference: str) -> str:
    if _IMAGE_REFERENCE.fullmatch(reference) is None:
        raise ValueError("image reference must contain an exact GHCR tag and sha256 digest")
    return reference.rsplit("@", 1)[1]


def _require_sbom_source(document: dict[str, object], reference: str) -> None:
    digest = _validate_image_reference(reference)
    metadata_value = document.get("metadata")
    if not isinstance(metadata_value, dict):
        raise ValueError("image SBOM metadata component is invalid")
    metadata = cast(dict[str, object], metadata_value)
    component_value = metadata.get("component")
    if not isinstance(component_value, dict):
        raise ValueError("image SBOM metadata component is invalid")
    component = cast(dict[str, object], component_value)
    if component.get("name") != reference or component.get("version") != digest:
        raise ValueError("image SBOM source identity is invalid")


def _component_identity(component: dict[str, object]) -> str:
    purl = component.get("purl")
    if isinstance(purl, str) and purl:
        return purl
    name = component.get("name")
    version = component.get("version")
    kind = component.get("type")
    if (
        not isinstance(kind, str)
        or not kind
        or not isinstance(name, str)
        or not name
        or not isinstance(version, str)
        or not version
    ):
        raise ValueError("image SBOM component identity is invalid")
    return f"{kind}:{name}@{version}"


def _component_identities(document: dict[str, object]) -> set[str]:
    return {_component_identity(component) for component in _components(document)}


def _allowed_base_removal(identity: str) -> bool:
    prefix = "pkg:pypi/"
    if not identity.startswith(prefix) or "@" not in identity:
        return False
    name = identity.removeprefix(prefix).split("@", 1)[0]
    return _normalized(name) in _REMOVABLE_BASE_PACKAGES


def _pip_owned_component_identities(document: dict[str, object]) -> set[str]:
    allowed: set[str] = set()
    for component in _components(document):
        identity = _component_identity(component)
        if _allowed_base_removal(identity):
            allowed.add(identity)
            continue
        properties_value = component.get("properties")
        if not isinstance(properties_value, list):
            continue
        for property_value in cast(list[object], properties_value):
            if not isinstance(property_value, dict):
                continue
            prop = cast(dict[str, object], property_value)
            name = prop.get("name")
            value = prop.get("value")
            if (
                isinstance(name, str)
                and name.startswith("syft:location:")
                and name.endswith(":path")
                and isinstance(value, str)
                and "/site-packages/pip/" in value
            ):
                allowed.add(identity)
                break
    return allowed


def verify_image_sbom(
    *,
    image_sbom: Path,
    base_sbom: Path,
    image: str,
    base_image: str,
    variant: Literal["core", "adk"],
    version: str,
) -> dict[str, object]:
    if variant not in {"core", "adk"} or not version or len(version) > 64:
        raise ValueError("image SBOM release identity is invalid")
    image_document = _read_cyclonedx(image_sbom)
    base_document = _read_cyclonedx(base_sbom)
    _require_sbom_source(image_document, image)
    _require_sbom_source(base_document, base_image)
    runtime = _named_components(image_document, "tesserix-mcp-runtime")
    if len(runtime) != 1 or runtime[0].get("version") != version:
        raise ValueError("image SBOM does not report the release runtime version")
    base_components = _component_identities(base_document)
    image_components = _component_identities(image_document)
    missing = base_components - image_components
    removed = sorted(missing & _pip_owned_component_identities(base_document))
    unexpected = sorted(missing - set(removed))
    if unexpected:
        raise ValueError(f"image SBOM omits base-image components: {', '.join(unexpected[:5])}")
    return {
        "schema_version": 1,
        "kind": "image",
        "variant": variant,
        "version": version,
        "runtime_version": version,
        "image": image,
        "base_image": base_image,
        "image_components": len(image_components),
        "base_components": len(base_components),
        "removed_base_components": removed,
        "image_sbom_sha256": _sha256(image_sbom),
        "base_sbom_sha256": _sha256(base_sbom),
        "passed": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    python = commands.add_parser("python")
    python.add_argument("--source", type=Path, required=True)
    python.add_argument("--target", type=Path, required=True)
    python.add_argument("--artifact-sbom", type=Path, required=True)
    python.add_argument("--uv-lock", type=Path, required=True)
    python.add_argument("--version", required=True)
    python.add_argument("--report", type=Path, required=True)
    image = commands.add_parser("image")
    image.add_argument("--image-sbom", type=Path, required=True)
    image.add_argument("--base-sbom", type=Path, required=True)
    image.add_argument("--image", required=True)
    image.add_argument("--base-image", required=True)
    image.add_argument("--variant", choices=("core", "adk"), required=True)
    image.add_argument("--version", required=True)
    image.add_argument("--report", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    report: dict[str, object]
    if arguments.command == "python":
        report = bind_python_sbom(
            source=arguments.source,
            target=arguments.target,
            artifact_sbom=arguments.artifact_sbom,
            uv_lock=arguments.uv_lock,
            version=arguments.version,
        )
    else:
        report = verify_image_sbom(
            image_sbom=arguments.image_sbom,
            base_sbom=arguments.base_sbom,
            image=arguments.image,
            base_image=arguments.base_image,
            variant=cast(Literal["core", "adk"], arguments.variant),
            version=arguments.version,
        )
    _write_json(arguments.report, report, description="SBOM verification report")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["bind_python_sbom", "main", "verify_image_sbom"]
