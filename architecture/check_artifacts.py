from __future__ import annotations

import argparse
import json
import sys
import tarfile
import zipfile
from email.message import Message
from email.parser import BytesParser
from email.policy import default
from pathlib import Path

ROOT = Path(__file__).parents[1]
DISTRIBUTIONS = {
    "tesserix-mcp-manifest": "tesserix_mcp_manifest",
    "tesserix-mcp-runtime": "tesserix_mcp_runtime",
    "tesserix-mcp-testkit": "tesserix_mcp_testkit",
}
FALLBACK_VERSION = "0.0.0"


class ArtifactPolicyError(ValueError):
    pass


def _only_member(names: list[str], suffix: str, artifact: Path) -> str:
    matches = [name for name in names if name.endswith(suffix)]
    if len(matches) != 1:
        raise ArtifactPolicyError(
            f"{artifact.name}: expected one {suffix} member, found {len(matches)}"
        )
    return matches[0]


def _root_member(names: list[str], filename: str, artifact: Path) -> str:
    matches = [name for name in names if len(Path(name).parts) == 2 and name.endswith(filename)]
    if len(matches) != 1:
        raise ArtifactPolicyError(
            f"{artifact.name}: expected one root {filename} member, found {len(matches)}"
        )
    return matches[0]


def _metadata(raw: bytes, artifact: Path) -> Message:
    message = BytesParser(policy=default).parsebytes(raw)
    for field in ("Name", "Version", "License-Expression", "License-File"):
        if message[field] is None:
            raise ArtifactPolicyError(f"{artifact.name}: missing {field} metadata")
    return message


def _validate_metadata(message: Message, artifact: Path, distribution: str) -> str:
    name = str(message["Name"])
    version = str(message["Version"])
    if name != distribution:
        raise ArtifactPolicyError(f"{artifact.name}: unexpected distribution {name!r}")
    if version == FALLBACK_VERSION:
        raise ArtifactPolicyError(f"{artifact.name}: VCS version fell back to {FALLBACK_VERSION}")
    if message["License-Expression"] != "Apache-2.0":
        raise ArtifactPolicyError(f"{artifact.name}: license expression is not Apache-2.0")
    if message["License-File"] != "LICENSE":
        raise ArtifactPolicyError(f"{artifact.name}: license file metadata is not LICENSE")
    if "Typing :: Typed" not in message.get_all("Classifier", []):
        raise ArtifactPolicyError(f"{artifact.name}: missing Typing :: Typed classifier")
    return version


def _check_wheel(
    wheel: Path,
    expected_license: bytes,
    *,
    distribution: str,
    package: str,
) -> str:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        metadata_name = _only_member(names, ".dist-info/METADATA", wheel)
        license_name = _only_member(names, ".dist-info/licenses/LICENSE", wheel)
        _only_member(names, f"{package}/py.typed", wheel)
        if archive.read(license_name) != expected_license:
            raise ArtifactPolicyError(f"{wheel.name}: packaged license differs from LICENSE")
        return _validate_metadata(
            _metadata(archive.read(metadata_name), wheel),
            wheel,
            distribution,
        )


def _check_sdist(
    sdist: Path,
    expected_license: bytes,
    *,
    distribution: str,
    package: str,
) -> str:
    with tarfile.open(sdist, mode="r:gz") as archive:
        files = {member.name: member for member in archive.getmembers() if member.isfile()}
        names = list(files)
        metadata_name = _root_member(names, "PKG-INFO", sdist)
        license_name = _root_member(names, "LICENSE", sdist)
        _only_member(names, f"/src/{package}/py.typed", sdist)
        license_file = archive.extractfile(files[license_name])
        metadata_file = archive.extractfile(files[metadata_name])
        if license_file is None or license_file.read() != expected_license:
            raise ArtifactPolicyError(f"{sdist.name}: packaged license differs from LICENSE")
        if metadata_file is None:
            raise ArtifactPolicyError(f"{sdist.name}: PKG-INFO is not readable")
        return _validate_metadata(
            _metadata(metadata_file.read(), sdist),
            sdist,
            distribution,
        )


def _distribution_artifact(
    artifacts: list[Path],
    *,
    distribution: str,
    suffix: str,
) -> Path:
    prefix = f"{distribution.replace('-', '_')}-"
    matches = [artifact for artifact in artifacts if artifact.name.startswith(prefix)]
    if len(matches) != 1:
        raise ArtifactPolicyError(f"{distribution}: expected one {suffix}, found {len(matches)}")
    return matches[0]


def check(directory: Path) -> dict[str, object]:
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != len(DISTRIBUTIONS) or len(sdists) != len(DISTRIBUTIONS):
        raise ArtifactPolicyError(
            f"{directory}: expected {len(DISTRIBUTIONS)} wheels and sdists, "
            f"found {len(wheels)} and {len(sdists)}"
        )

    expected_license = (ROOT / "LICENSE").read_bytes()
    reports: dict[str, dict[str, str | int]] = {}
    versions: set[str] = set()
    for distribution, package in DISTRIBUTIONS.items():
        wheel = _distribution_artifact(
            wheels,
            distribution=distribution,
            suffix="wheel",
        )
        sdist = _distribution_artifact(
            sdists,
            distribution=distribution,
            suffix="sdist",
        )
        wheel_version = _check_wheel(
            wheel,
            expected_license,
            distribution=distribution,
            package=package,
        )
        sdist_version = _check_sdist(
            sdist,
            expected_license,
            distribution=distribution,
            package=package,
        )
        if wheel_version != sdist_version:
            raise ArtifactPolicyError(
                f"{distribution}: wheel and sdist versions differ: "
                f"wheel={wheel_version}, sdist={sdist_version}"
            )
        versions.add(wheel_version)
        reports[distribution] = {
            "sdist_bytes": sdist.stat().st_size,
            "version": wheel_version,
            "wheel_bytes": wheel.stat().st_size,
        }
    if len(versions) != 1:
        raise ArtifactPolicyError(f"workspace distribution versions differ: {sorted(versions)}")

    return {"distributions": reports, "version": versions.pop()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        report = check(args.directory)
    except (ArtifactPolicyError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"artifact policy failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
