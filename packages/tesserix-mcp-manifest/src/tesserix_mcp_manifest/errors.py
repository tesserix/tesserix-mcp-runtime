from __future__ import annotations

from enum import StrEnum
from typing import Literal


class ManifestError(Exception):
    pass


class ManifestValidationCode(StrEnum):
    DUPLICATE_KEY = "duplicate_key"
    INVALID_JSON = "invalid_json"
    INVALID_MANIFEST = "invalid_manifest"
    RESERVED_ANNOTATION = "reserved_annotation"
    SECRET_FIELD = "secret_field"
    SOURCE_TOO_LARGE = "source_too_large"
    TOO_COMPLEX = "too_complex"
    TOO_DEEP = "too_deep"


class ManifestValidationError(ManifestError):
    def __init__(self, code: ManifestValidationCode) -> None:
        self.code = code
        super().__init__(f"authoring manifest validation failed ({code})")


class ManifestVersionMismatchError(ManifestError):
    def __init__(
        self,
        *,
        component: Literal["runtime", "package"],
        actual_version: str,
        manifest_version: str,
    ) -> None:
        self.component = component
        self.actual_version = actual_version
        self.manifest_version = manifest_version
        super().__init__(f"{component} version does not match manifest version")


__all__ = [
    "ManifestError",
    "ManifestValidationCode",
    "ManifestValidationError",
    "ManifestVersionMismatchError",
]
