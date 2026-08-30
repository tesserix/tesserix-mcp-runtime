from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Self

_NUMBER = r"(?:0|[1-9][0-9]*)"
_TAG = re.compile(
    rf"v(?P<major>{_NUMBER})\.(?P<minor>{_NUMBER})\.(?P<patch>{_NUMBER})"
    rf"(?:-rc\.(?P<rc>[1-9][0-9]*))?\Z"
)
_MAX_OCI_TAG_BYTES = 128
_LONGEST_VARIANT_SUFFIX = "-core"


@dataclass(frozen=True, slots=True, kw_only=True)
class ReleaseIdentity:
    tag: str
    version: str
    oci_tag: str
    prerelease: bool

    @classmethod
    def parse(cls, tag: str) -> Self:
        match = _TAG.fullmatch(tag)
        if match is None:
            raise ValueError("release tag must be an exact vX.Y.Z or vX.Y.Z-rc.N")
        oci_tag = tag.removeprefix("v")
        if len((oci_tag + _LONGEST_VARIANT_SUFFIX).encode("ascii")) > _MAX_OCI_TAG_BYTES:
            raise ValueError("release tag exceeds the immutable OCI tag limit")
        base = ".".join(match.group(name) for name in ("major", "minor", "patch"))
        candidate = match.group("rc")
        return cls(
            tag=tag,
            version=f"{base}rc{candidate}" if candidate is not None else base,
            oci_tag=oci_tag,
            prerelease=candidate is not None,
        )


__all__ = ["ReleaseIdentity"]
