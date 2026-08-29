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
from importlib.metadata import distribution, version

import tesserix_mcp_runtime

installed = distribution("tesserix-mcp-runtime")
package_version = version("tesserix-mcp-runtime")
print(json.dumps({
    "typed": installed.locate_file("tesserix_mcp_runtime/py.typed").is_file(),
    "version": package_version,
    "version_export_matches": tesserix_mcp_runtime.__version__ == package_version,
}))
"""


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
    install_dependencies: bool,
    offline: bool,
) -> dict[str, Any]:
    _run([uv, "venv", "--python", sys.executable, str(environment)], cwd=environment.parent)
    python = _python_in(environment)
    install = [uv, "pip", "install", "--python", str(python)]
    if offline:
        install.append("--offline")
    if not install_dependencies:
        install.append("--no-deps")
    install.append(str(artifact))
    _run(install, cwd=environment.parent)
    completed = _run([str(python), "-I", "-c", IMPORT_CHECK], cwd=environment.parent)
    result = json.loads(completed.stdout)
    if result.get("typed") is not True or result.get("version_export_matches") is not True:
        raise SmokeInstallError(f"{artifact.name}: installed metadata probe failed: {result}")
    result["dependencies_installed"] = install_dependencies
    return result


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
    if len(wheels) != 1 or len(sdists) != 1:
        raise SmokeInstallError(
            f"{directory}: expected one wheel and one sdist, found {len(wheels)} and {len(sdists)}"
        )

    with tempfile.TemporaryDirectory(prefix="tesserix-mcp-artifacts-") as temporary:
        temporary_root = Path(temporary)
        report = {
            "wheel": _install_and_probe(
                uv,
                wheels[0],
                temporary_root / "wheel-env",
                install_dependencies=install_dependencies,
                offline=offline,
            ),
            "sdist": _install_and_probe(
                uv,
                sdists[0],
                temporary_root / "sdist-env",
                install_dependencies=install_dependencies,
                offline=offline,
            ),
        }
    if report["wheel"]["version"] != report["sdist"]["version"]:
        raise SmokeInstallError("wheel and sdist installed different versions")
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
