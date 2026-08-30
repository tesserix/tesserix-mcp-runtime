from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

IMPORT_CHECK = """
import json
import sys
from importlib import import_module
from importlib.metadata import distribution, version

distribution_name = sys.argv[1]
module_name = sys.argv[2]
should_import = sys.argv[3] == "true"
module = import_module(module_name) if should_import else None

installed = distribution(distribution_name)
package_version = version(distribution_name)
print(json.dumps({
    "typed": installed.locate_file(f"{module_name}/py.typed").is_file(),
    "version": package_version,
    "version_export_matches": (
        module is None or getattr(module, "__version__", package_version) == package_version
    ),
}))
"""
DISTRIBUTIONS = {
    "tesserix-mcp-manifest": "tesserix_mcp_manifest",
    "tesserix-mcp-runtime": "tesserix_mcp_runtime",
    "tesserix-mcp-testkit": "tesserix_mcp_testkit",
}


class SmokeInstallError(RuntimeError):
    pass


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise SmokeInstallError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stderr}"
        )
    return completed


def _python_in(environment: Path) -> Path:
    posix = environment / "bin" / "python"
    if posix.exists():
        return posix
    return environment / "Scripts" / "python.exe"


def _install_and_probe(
    uv: str,
    artifact: Path,
    environment: Path,
    *,
    companions: tuple[Path, ...],
    distribution_name: str,
    install_dependencies: bool,
    module_name: str,
    offline: bool,
    probe_import: bool,
) -> dict[str, Any]:
    _run([uv, "venv", "--python", sys.executable, str(environment)], cwd=environment.parent)
    python = _python_in(environment)
    install = [uv, "pip", "install", "--python", str(python)]
    if offline:
        install.append("--offline")
    if not install_dependencies:
        install.append("--no-deps")
    install.extend(str(companion) for companion in companions)
    install.append(str(artifact))
    _run(install, cwd=environment.parent)
    completed = _run(
        [
            str(python),
            "-I",
            "-c",
            IMPORT_CHECK,
            distribution_name,
            module_name,
            str(probe_import).lower(),
        ],
        cwd=environment.parent,
    )
    result = json.loads(completed.stdout)
    if result.get("typed") is not True or result.get("version_export_matches") is not True:
        raise SmokeInstallError(f"{artifact.name}: installed metadata probe failed: {result}")
    result["dependencies_installed"] = install_dependencies
    return result


def _distribution_artifact(
    artifacts: list[Path],
    *,
    distribution: str,
    suffix: str,
) -> Path:
    prefix = f"{distribution.replace('-', '_')}-"
    matches = [artifact for artifact in artifacts if artifact.name.startswith(prefix)]
    if len(matches) != 1:
        raise SmokeInstallError(f"{distribution}: expected one {suffix}, found {len(matches)}")
    return matches[0]


def check(
    directory: Path,
    *,
    install_dependencies: bool,
    offline: bool,
) -> dict[str, dict[str, Any]]:
    directory = directory.resolve(strict=True)
    uv = shutil.which("uv")
    if uv is None:
        raise SmokeInstallError("uv is not installed")
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != len(DISTRIBUTIONS) or len(sdists) != len(DISTRIBUTIONS):
        raise SmokeInstallError(
            f"{directory}: expected {len(DISTRIBUTIONS)} wheels and sdists, "
            f"found {len(wheels)} and {len(sdists)}"
        )

    with tempfile.TemporaryDirectory(prefix="tesserix-mcp-artifacts-") as temporary:
        temporary_root = Path(temporary)
        runtime_wheel = _distribution_artifact(
            wheels,
            distribution="tesserix-mcp-runtime",
            suffix="wheel",
        )
        runtime_sdist = _distribution_artifact(
            sdists,
            distribution="tesserix-mcp-runtime",
            suffix="sdist",
        )
        report: dict[str, dict[str, dict[str, Any]]] = {}
        versions: set[str] = set()
        for distribution_name, module_name in DISTRIBUTIONS.items():
            wheel = _distribution_artifact(
                wheels,
                distribution=distribution_name,
                suffix="wheel",
            )
            sdist = _distribution_artifact(
                sdists,
                distribution=distribution_name,
                suffix="sdist",
            )
            wheel_companions = (
                (runtime_wheel,) if distribution_name != "tesserix-mcp-runtime" else ()
            )
            sdist_companions = (
                (runtime_sdist,) if distribution_name != "tesserix-mcp-runtime" else ()
            )
            distribution_report = {
                "wheel": _install_and_probe(
                    uv,
                    wheel,
                    temporary_root / f"{module_name}-wheel-env",
                    companions=wheel_companions,
                    distribution_name=distribution_name,
                    install_dependencies=install_dependencies,
                    module_name=module_name,
                    offline=offline,
                    probe_import=(
                        install_dependencies or distribution_name == "tesserix-mcp-runtime"
                    ),
                ),
                "sdist": _install_and_probe(
                    uv,
                    sdist,
                    temporary_root / f"{module_name}-sdist-env",
                    companions=sdist_companions,
                    distribution_name=distribution_name,
                    install_dependencies=install_dependencies,
                    module_name=module_name,
                    offline=offline,
                    probe_import=(
                        install_dependencies or distribution_name == "tesserix-mcp-runtime"
                    ),
                ),
            }
            if distribution_report["wheel"]["version"] != distribution_report["sdist"]["version"]:
                raise SmokeInstallError(
                    f"{distribution_name}: wheel and sdist installed different versions"
                )
            versions.add(str(distribution_report["wheel"]["version"]))
            report[distribution_name] = distribution_report
    if len(versions) != 1:
        raise SmokeInstallError(f"workspace distribution versions differ: {sorted(versions)}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-deps", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        report = check(
            args.directory,
            install_dependencies=not args.no_deps,
            offline=args.offline,
        )
    except (OSError, json.JSONDecodeError, SmokeInstallError) as error:
        print(f"artifact install smoke test failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
