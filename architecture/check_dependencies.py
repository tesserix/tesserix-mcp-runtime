from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
DEPENDENCY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def canonical_name(requirement: str) -> str:
    match = DEPENDENCY_NAME.match(requirement)
    if match is None:
        raise ValueError(f"Cannot read dependency name from {requirement!r}")
    return re.sub(r"[-_.]+", "-", match.group()).lower()


def declared_profiles(pyproject_path: Path) -> tuple[str, dict[str, list[str]]]:
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = pyproject["project"]
    core = sorted(project.get("dependencies", []))
    profiles = {"core": core}
    for extra, dependencies in sorted(project.get("optional-dependencies", {}).items()):
        profiles[extra] = sorted([*core, *dependencies])
    return project["name"], profiles


def resolved_dependencies(profile: str) -> list[str]:
    command = [
        "uv",
        "export",
        "--frozen",
        "--no-dev",
        "--no-hashes",
        "--no-header",
        "--no-emit-project",
        "--format",
        "requirements-txt",
    ]
    if profile != "core":
        command.extend(["--extra", profile])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        check=True,
        text=True,
    )
    return sorted(
        line.strip()
        for line in completed.stdout.splitlines()
        if line and not line[0].isspace() and not line.startswith("#")
    )


def file_bytes(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(
        candidate.stat().st_size for candidate in path.rglob("*") if candidate.is_file()
    )


def check(
    report_path: Path,
    *,
    wheel: Path | None,
    site_packages: Path | None,
) -> dict[str, Any]:
    policy = json.loads(report_path.read_text(encoding="utf-8"))
    root_distribution, declared = declared_profiles(ROOT / "pyproject.toml")
    expected_profiles = policy["profiles"]
    forbidden = {canonical_name(name) for name in policy["forbidden_dependencies"]}
    violations: list[dict[str, Any]] = []
    profiles: dict[str, Any] = {}

    if policy.get("schema_version") != 1:
        violations.append(
            {
                "actual": policy.get("schema_version"),
                "expected": 1,
                "reason": "unsupported dependency report schema",
            }
        )
    if root_distribution != policy.get("root_distribution"):
        violations.append(
            {
                "actual": root_distribution,
                "expected": policy.get("root_distribution"),
                "reason": "root distribution changed",
            }
        )

    if set(declared) != set(expected_profiles):
        violations.append(
            {
                "actual_profiles": sorted(declared),
                "expected_profiles": sorted(expected_profiles),
                "reason": "dependency profiles changed",
            }
        )

    for profile in sorted(set(declared) & set(expected_profiles)):
        expected = expected_profiles[profile]
        resolved = resolved_dependencies(profile)
        distribution_count = len(resolved) + 1
        profile_result = {
            "declared_dependencies": declared[profile],
            "distribution_count": distribution_count,
            "installed_bytes": None,
            "resolved_dependencies": resolved,
            "wheel_bytes": None,
        }
        profiles[profile] = profile_result

        if declared[profile] != expected["declared_dependencies"]:
            violations.append(
                {
                    "actual": declared[profile],
                    "expected": expected["declared_dependencies"],
                    "profile": profile,
                    "reason": "declared dependencies changed",
                }
            )
        if resolved != expected["resolved_dependencies"]:
            violations.append(
                {
                    "actual": resolved,
                    "expected": expected["resolved_dependencies"],
                    "profile": profile,
                    "reason": "frozen dependency resolution changed",
                }
            )
        if distribution_count > expected["max_distribution_count"]:
            violations.append(
                {
                    "actual_count": distribution_count,
                    "maximum_count": expected["max_distribution_count"],
                    "profile": profile,
                    "reason": "distribution count budget exceeded",
                }
            )

        for dependency in sorted(
            {canonical_name(item) for item in resolved} & forbidden
        ):
            violations.append(
                {
                    "dependency": dependency,
                    "profile": profile,
                    "reason": "forbidden dependency resolved",
                }
            )

        if profile == "core" and wheel is not None:
            wheel_bytes = file_bytes(wheel)
            profile_result["wheel_bytes"] = wheel_bytes
            if wheel_bytes > expected["max_wheel_bytes"]:
                violations.append(
                    {
                        "actual_bytes": wheel_bytes,
                        "maximum_bytes": expected["max_wheel_bytes"],
                        "profile": profile,
                        "reason": "wheel size budget exceeded",
                    }
                )
        if profile == "core" and site_packages is not None:
            installed_bytes = file_bytes(site_packages)
            profile_result["installed_bytes"] = installed_bytes
            if installed_bytes > expected["max_installed_bytes"]:
                violations.append(
                    {
                        "actual_bytes": installed_bytes,
                        "maximum_bytes": expected["max_installed_bytes"],
                        "profile": profile,
                        "reason": "installed size budget exceeded",
                    }
                )

    return {"passed": not violations, "profiles": profiles, "violations": violations}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report",
        type=Path,
        default=Path(__file__).with_name("dependency-report.json"),
    )
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--site-packages", type=Path)
    arguments = parser.parse_args()
    result = check(
        arguments.report,
        wheel=arguments.wheel,
        site_packages=arguments.site_packages,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
