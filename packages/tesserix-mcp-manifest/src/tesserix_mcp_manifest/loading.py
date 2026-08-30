from __future__ import annotations

import json
from typing import NoReturn, TypeGuard, cast

from pydantic import ValidationError

from tesserix_mcp_manifest._secret_fields import is_secret_key
from tesserix_mcp_manifest.constants import (
    AUTHORING_MANIFEST_MAX_BYTES,
    AUTHORING_MANIFEST_MAX_DEPTH,
    AUTHORING_MANIFEST_MAX_NODES,
)
from tesserix_mcp_manifest.errors import ManifestValidationCode, ManifestValidationError
from tesserix_mcp_manifest.models import ServerAuthoringManifest


class _DuplicateKeyError(Exception):
    pass


class _InvalidJsonConstantError(Exception):
    pass


def _reject_json_constant(_: str) -> NoReturn:
    raise _InvalidJsonConstantError


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _is_allowed_reference_key(path: tuple[str, ...], key: str) -> bool:
    return (not path and key == "credential_ref") or (
        path == ("credential_ref",) and key == "secret_name"
    )


def _is_object(value: object) -> TypeGuard[dict[str, object]]:
    if not isinstance(value, dict):
        return False
    mapping = cast(dict[object, object], value)
    return all(isinstance(key, str) for key in mapping)


def _is_array(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _enforce_structure_limits(document: object) -> None:
    pending: list[tuple[object, int, tuple[str, ...]]] = [(document, 1, ())]
    nodes = 0
    while pending:
        value, depth, path = pending.pop()
        nodes += 1
        if nodes > AUTHORING_MANIFEST_MAX_NODES:
            raise ManifestValidationError(ManifestValidationCode.TOO_COMPLEX)
        if depth > AUTHORING_MANIFEST_MAX_DEPTH:
            raise ManifestValidationError(ManifestValidationCode.TOO_DEEP)
        if _is_object(value):
            for key, child in value.items():
                if is_secret_key(key) and not _is_allowed_reference_key(path, key):
                    raise ManifestValidationError(ManifestValidationCode.SECRET_FIELD)
                pending.append((child, depth + 1, (*path, key)))
        elif _is_array(value):
            pending.extend((child, depth + 1, path) for child in value)


def load_authoring_manifest(source: bytes) -> ServerAuthoringManifest:
    if len(source) > AUTHORING_MANIFEST_MAX_BYTES:
        raise ManifestValidationError(ManifestValidationCode.SOURCE_TOO_LARGE)
    try:
        text = source.decode("utf-8")
        document: object = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateKeyError:
        raise ManifestValidationError(ManifestValidationCode.DUPLICATE_KEY) from None
    except (UnicodeDecodeError, ValueError, _InvalidJsonConstantError):
        raise ManifestValidationError(ManifestValidationCode.INVALID_JSON) from None
    _enforce_structure_limits(document)
    try:
        return ServerAuthoringManifest.model_validate_json(source)
    except ValidationError:
        raise ManifestValidationError(ManifestValidationCode.INVALID_MANIFEST) from None


__all__ = ["load_authoring_manifest"]
