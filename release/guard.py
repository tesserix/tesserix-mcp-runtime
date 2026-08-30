from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from release.identity import ReleaseIdentity

_MAX_GITHUB_OUTPUT_BYTES = 1_048_576


def write_identity_outputs(tag: str, output: Path) -> dict[str, str | bool]:
    identity = ReleaseIdentity.parse(tag)
    lines = {
        "oci_tag": identity.oci_tag,
        "prerelease": str(identity.prerelease).lower(),
        "tag": identity.tag,
        "version": identity.version,
    }
    encoded = "".join(f"{name}={value}\n" for name, value in lines.items())
    if (
        output.is_symlink()
        or not output.is_file()
        or output.stat().st_size + len(encoded.encode("utf-8")) > _MAX_GITHUB_OUTPUT_BYTES
    ):
        raise ValueError("GitHub output must be a bounded regular file")
    document: dict[str, str | bool] = {
        "oci_tag": identity.oci_tag,
        "prerelease": identity.prerelease,
        "tag": identity.tag,
        "version": identity.version,
    }
    with output.open("a", encoding="utf-8") as destination:
        destination.write(encoded)
    return document


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    document = write_identity_outputs(arguments.tag, arguments.github_output)
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "write_identity_outputs"]
