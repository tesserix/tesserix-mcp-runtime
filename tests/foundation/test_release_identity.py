from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from release.guard import write_identity_outputs
from release.identity import ReleaseIdentity


@pytest.mark.parametrize(
    ("tag", "version", "prerelease"),
    [
        ("v0.1.0", "0.1.0", False),
        ("v0.1.0-rc.1", "0.1.0rc1", True),
        ("v12.34.56-rc.789", "12.34.56rc789", True),
    ],
)
def test_release_identity_derives_python_and_oci_versions(
    tag: str,
    version: str,
    prerelease: bool,
) -> None:
    identity = ReleaseIdentity.parse(tag)

    assert identity.tag == tag
    assert identity.version == version
    assert identity.oci_tag == tag.removeprefix("v")
    assert identity.prerelease is prerelease


@pytest.mark.parametrize(
    "tag",
    [
        "0.1.0",
        "v0.1",
        "v0.1.0-rc.0",
        "v0.1.0+rebuilt",
        "v01.1.0",
        "v1.01.0",
        "v1.0.01",
        "v1.0.0-rc.01",
        "v1.0.0\nrelease",
        "v" + "9" * 124 + ".0.0",
        "latest",
    ],
)
def test_release_identity_rejects_ambiguous_or_mutable_tags(tag: str) -> None:
    with pytest.raises(ValueError, match="release tag"):
        ReleaseIdentity.parse(tag)


def test_release_identity_writes_bounded_github_outputs(tmp_path: Path) -> None:
    output = tmp_path / "github-output"
    output.touch()

    document = write_identity_outputs("v1.2.3-rc.4", output)

    assert document == {
        "oci_tag": "1.2.3-rc.4",
        "prerelease": True,
        "tag": "v1.2.3-rc.4",
        "version": "1.2.3rc4",
    }
    assert output.read_text(encoding="utf-8") == (
        "oci_tag=1.2.3-rc.4\nprerelease=true\ntag=v1.2.3-rc.4\nversion=1.2.3rc4\n"
    )


def test_release_identity_rejects_output_append_past_github_limit(tmp_path: Path) -> None:
    output = tmp_path / "github-output"
    output.write_bytes(b"x" * 1_048_560)

    with pytest.raises(ValueError, match="bounded regular file"):
        write_identity_outputs("v1.2.3", output)


def test_release_guard_module_runs_without_eager_import_warning(tmp_path: Path) -> None:
    output = tmp_path / "github-output"
    output.touch()

    completed = subprocess.run(
        (
            sys.executable,
            "-m",
            "release.guard",
            "--tag",
            "v1.2.3",
            "--github-output",
            str(output),
        ),
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0
    assert "RuntimeWarning" not in completed.stderr
