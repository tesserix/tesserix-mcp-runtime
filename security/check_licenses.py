from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Any

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).parents[1]
ROOT_DISTRIBUTION = "tesserix-mcp-runtime"
DEFAULT_POLICY = ROOT / "security" / "license-policy.json"
LICENSE_ALIASES = {
    "Apache 2.0": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "BSD License": "BSD-3-Clause",
    "MIT License": "MIT",
    "Python Software Foundation License": "PSF-2.0",
}
CLASSIFIER_LICENSES = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: BSD License": "BSD-3-Clause",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
}


class LicensePolicyError(ValueError):
    pass


@dataclass(frozen=True)
class PackageRecord:
    name: str
    version: str
    license: str
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class LicensePolicy:
    allowed: frozenset[str]
    overrides: dict[str, str]


def _object(value: object, location: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise LicensePolicyError(f"{location} must be an object with string keys")
    return value


def _text(value: object, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LicensePolicyError(f"{location} must be a non-empty string")
    return value.strip()


def _string_list(value: object, location: str) -> list[str]:
    if not isinstance(value, list):
        raise LicensePolicyError(f"{location} must be an array")
    return [_text(item, f"{location}[{index}]") for index, item in enumerate(value)]


def load_policy(path: Path) -> LicensePolicy:
    document = _object(json.loads(path.read_text(encoding="utf-8")), "policy")
    if document.get("schema_version") != 1:
        raise LicensePolicyError("policy.schema_version must be 1")
    allowed = frozenset(_string_list(document.get("allowed_licenses"), "allowed_licenses"))
    if not allowed:
        raise LicensePolicyError("allowed_licenses must not be empty")
    raw_overrides = _object(document.get("license_overrides"), "license_overrides")
    overrides = {
        canonicalize_name(name): _text(value, f"license_overrides.{name}")
        for name, value in raw_overrides.items()
    }
    unknown_overrides = set(overrides.values()) - allowed
    if unknown_overrides:
        raise LicensePolicyError(
            f"license overrides are not allowlisted: {', '.join(sorted(unknown_overrides))}"
        )
    return LicensePolicy(allowed=allowed, overrides=overrides)


def _metadata_license(name: str) -> str:
    metadata = distribution(name).metadata
    declared = metadata.get("License-Expression") or metadata.get("License")
    if declared and declared.strip():
        return LICENSE_ALIASES.get(declared.strip(), declared.strip())
    classifiers = metadata.get_all("Classifier", [])
    matches = {
        CLASSIFIER_LICENSES[classifier]
        for classifier in classifiers
        if classifier in CLASSIFIER_LICENSES
    }
    if len(matches) == 1:
        return matches.pop()
    return "UNKNOWN"


def installed_inventory(root: str = ROOT_DISTRIBUTION) -> tuple[str, dict[str, PackageRecord]]:
    environment = default_environment()
    root_name = canonicalize_name(root)
    pending = deque([(root_name, frozenset[str]())])
    selected_extras: dict[str, frozenset[str]] = {}
    packages: dict[str, PackageRecord] = {}
    while pending:
        requested, new_extras = pending.popleft()
        name = canonicalize_name(requested)
        extras = selected_extras.get(name, frozenset()) | new_extras
        if name in packages and extras == selected_extras[name]:
            continue
        selected_extras[name] = extras
        try:
            installed = distribution(name)
        except PackageNotFoundError as error:
            raise LicensePolicyError(f"required distribution is not installed: {name}") from error
        dependencies: set[str] = set()
        for raw_requirement in installed.requires or []:
            try:
                requirement = Requirement(raw_requirement)
            except InvalidRequirement as error:
                raise LicensePolicyError(
                    f"{name} has invalid dependency metadata: {raw_requirement}"
                ) from error
            marker_environments = (
                environment | {"extra": extra_name} for extra_name in {"", *extras}
            )
            if requirement.marker is None or any(
                requirement.marker.evaluate(marker_environment)
                for marker_environment in marker_environments
            ):
                dependency = canonicalize_name(requirement.name)
                dependencies.add(dependency)
                pending.append((dependency, frozenset(requirement.extras)))
        packages[name] = PackageRecord(
            name=name,
            version=installed.version,
            license=_metadata_license(name),
            dependencies=tuple(sorted(dependencies)),
        )
    return root_name, packages


def load_inventory(path: Path) -> tuple[str, dict[str, PackageRecord]]:
    document = _object(json.loads(path.read_text(encoding="utf-8")), "inventory")
    if document.get("schema_version") != 1:
        raise LicensePolicyError("inventory.schema_version must be 1")
    root = canonicalize_name(_text(document.get("root"), "inventory.root"))
    raw_packages = document.get("packages")
    if not isinstance(raw_packages, list):
        raise LicensePolicyError("inventory.packages must be an array")
    packages: dict[str, PackageRecord] = {}
    for index, raw_package in enumerate(raw_packages):
        package = _object(raw_package, f"inventory.packages[{index}]")
        name = canonicalize_name(_text(package.get("name"), f"packages[{index}].name"))
        if name in packages:
            raise LicensePolicyError(f"inventory contains duplicate package {name}")
        packages[name] = PackageRecord(
            name=name,
            version=_text(package.get("version"), f"packages[{index}].version"),
            license=_text(package.get("license"), f"packages[{index}].license"),
            dependencies=tuple(
                canonicalize_name(dependency)
                for dependency in _string_list(
                    package.get("dependencies"), f"packages[{index}].dependencies"
                )
            ),
        )
    if root not in packages:
        raise LicensePolicyError(f"inventory root is missing: {root}")
    return root, packages


def _paths(root: str, packages: dict[str, PackageRecord]) -> dict[str, tuple[str, ...]]:
    paths = {root: (root,)}
    pending = deque([root])
    while pending:
        name = pending.popleft()
        package = packages.get(name)
        if package is None:
            continue
        for dependency in package.dependencies:
            if dependency not in paths:
                paths[dependency] = (*paths[name], dependency)
                pending.append(dependency)
    return paths


def check(
    root: str,
    packages: dict[str, PackageRecord],
    policy: LicensePolicy,
) -> dict[str, object]:
    paths = _paths(root, packages)
    violations: list[str] = []
    for name, path in sorted(paths.items()):
        package = packages.get(name)
        dependency_path = " -> ".join(path)
        if package is None:
            violations.append(f"missing dependency metadata via {dependency_path}")
            continue
        license_name = policy.overrides.get(name, package.license)
        if license_name not in policy.allowed:
            violations.append(
                f"{name}=={package.version} uses {license_name} via {dependency_path}"
            )
    unreachable = set(packages) - set(paths)
    if unreachable:
        violations.append(
            f"inventory contains unreachable packages: {', '.join(sorted(unreachable))}"
        )
    if violations:
        raise LicensePolicyError("\n".join(violations))
    return {
        "allowed_licenses": sorted(policy.allowed),
        "distribution_count": len(paths),
        "packages": sorted(paths),
        "root": root,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    args = parser.parse_args()
    try:
        policy = load_policy(args.policy)
        inventory = (
            installed_inventory() if args.inventory is None else load_inventory(args.inventory)
        )
        report = check(*inventory, policy)
    except (json.JSONDecodeError, LicensePolicyError, OSError) as error:
        print(f"license policy failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
