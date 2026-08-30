"""Immutable, handler-free metadata snapshots for registered tools."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypeGuard, cast

from tesserix_mcp_runtime.contracts import JsonValue, ToolMetadata


def _is_json_value(value: object) -> TypeGuard[JsonValue]:
    if value is None or isinstance(value, str | bool | int):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        items = cast(list[object], value)
        return all(_is_json_value(item) for item in items)
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        return all(isinstance(key, str) and _is_json_value(item) for key, item in mapping.items())
    return False


def _is_json_object(value: object) -> TypeGuard[dict[str, JsonValue]]:
    if not isinstance(value, dict):
        return False
    mapping = cast(dict[object, object], value)
    return all(isinstance(key, str) and _is_json_value(item) for key, item in mapping.items())


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (RecursionError, TypeError, ValueError) as error:
        raise ValueError("manifest content must be bounded JSON") from error


def _decode_object(document: str) -> dict[str, JsonValue]:
    decoded: object = json.loads(document)
    if not _is_json_object(decoded):
        raise ValueError("manifest schema must be a JSON object")
    return decoded


def _digest(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


canonical_json = _canonical_json
digest_text = _digest


def schema_fingerprint(schema: Mapping[str, JsonValue]) -> str:
    """Fingerprint canonical UTF-8 JSON independently of mapping order."""

    return _digest(_canonical_json(schema))


@dataclass(frozen=True, slots=True, init=False)
class ToolManifest:
    """Snapshot schemas and public metadata without retaining executable code."""

    metadata: ToolMetadata
    normalized_name: str
    input_fingerprint: str
    output_fingerprint: str
    contract_fingerprint: str
    _input_schema_json: str
    _output_schema_json: str

    def __init__(
        self,
        *,
        metadata: ToolMetadata,
        normalized_name: str,
        input_schema: Mapping[str, JsonValue],
        output_schema: Mapping[str, JsonValue],
    ) -> None:
        input_document = _canonical_json(input_schema)
        output_document = _canonical_json(output_schema)
        contract_document = _canonical_json(
            {
                "input_schema": _decode_object(input_document),
                "output_schema": _decode_object(output_document),
            }
        )
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "normalized_name", normalized_name)
        object.__setattr__(self, "input_fingerprint", _digest(input_document))
        object.__setattr__(self, "output_fingerprint", _digest(output_document))
        object.__setattr__(self, "contract_fingerprint", _digest(contract_document))
        object.__setattr__(self, "_input_schema_json", input_document)
        object.__setattr__(self, "_output_schema_json", output_document)

    @property
    def input_schema(self) -> dict[str, JsonValue]:
        return _decode_object(self._input_schema_json)

    @property
    def output_schema(self) -> dict[str, JsonValue]:
        return _decode_object(self._output_schema_json)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "metadata": self.metadata.to_dict(),
            "normalized_name": self.normalized_name,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "fingerprints": {
                "input": self.input_fingerprint,
                "output": self.output_fingerprint,
                "contract": self.contract_fingerprint,
            },
        }


__all__ = ["ToolManifest", "schema_fingerprint"]
