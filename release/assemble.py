from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from release.evidence import ImageEvidence, write_release_evidence
from release.identity import ReleaseIdentity
from release.notes import write_release_notes


def _image(value: str) -> ImageEvidence:
    variant, separator, reference = value.partition("=")
    if separator != "=":
        raise argparse.ArgumentTypeError("image must be core=<reference> or adk=<reference>")
    narrowed: Literal["core", "adk"]
    if variant == "core":
        narrowed = "core"
    elif variant == "adk":
        narrowed = "adk"
    else:
        raise argparse.ArgumentTypeError("image must be core=<reference> or adk=<reference>")
    return ImageEvidence(variant=narrowed, reference=reference)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--support-matrix", type=Path, required=True)
    parser.add_argument("--image", action="append", type=_image, required=True)
    arguments = parser.parse_args(argv)
    identity = ReleaseIdentity.parse(arguments.tag)
    images = tuple(arguments.image)
    write_release_notes(
        arguments.directory / "release-notes.md",
        identity=identity,
        images=images,
        repository=arguments.repository,
        source_sha=arguments.source_sha,
        support_matrix=arguments.support_matrix,
    )
    document = write_release_evidence(
        arguments.directory,
        identity=identity,
        images=images,
        repository=arguments.repository,
        source_sha=arguments.source_sha,
        workflow_ref=arguments.workflow_ref,
    )
    print(json.dumps(document, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
