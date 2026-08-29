"""Registration-time validation for typed tool definitions."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from tesserix_mcp_runtime.contracts import ToolDefinition, ToolHandler, ToolMetadata

_SCHEMA_TYPES = frozenset(
    {"array", "boolean", "integer", "null", "number", "object", "string"}
)
_COMMON_SCHEMA_KEYWORDS = frozenset(
    {"$comment", "const", "default", "description", "enum", "examples", "title", "type"}
)
_SCHEMA_KEYWORDS_BY_TYPE = {
    "array": frozenset({"items", "maxItems", "minItems", "uniqueItems"}),
    "boolean": frozenset(),
    "integer": frozenset(
        {"exclusiveMaximum", "exclusiveMinimum", "maximum", "minimum", "multipleOf"}
    ),
    "null": frozenset(),
    "number": frozenset(
        {"exclusiveMaximum", "exclusiveMinimum", "maximum", "minimum", "multipleOf"}
    ),
    "object": frozenset(
        {
            "additionalProperties",
            "maxProperties",
            "minProperties",
            "properties",
            "required",
        }
    ),
    "string": frozenset({"format", "maxLength", "minLength"}),
}
_ROOT_SCHEMA_KEYWORDS = frozenset({"$id", "$schema"})


class ContractViolation(ValueError):
    """Identify a deterministic authoring-time contract failure."""

    def __init__(self, code: str, path: str) -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code} at {path}")


@dataclass(frozen=True, slots=True, kw_only=True)
class SchemaPolicy:
    """Registration limits for the supported closed JSON Schema subset."""

    max_schema_bytes: int = 65_536
    max_depth: int = 16
    max_properties: int = 128
    max_string_length: int = 65_536
    max_array_items: int = 1_024

    def __post_init__(self) -> None:
        for name in (
            "max_schema_bytes",
            "max_depth",
            "max_properties",
            "max_string_length",
            "max_array_items",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


def _is_non_negative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_schema_node(
    schema: object,
    path: str,
    *,
    policy: SchemaPolicy,
    depth: int = 1,
    root: bool = False,
) -> None:
    if not isinstance(schema, Mapping):
        raise ContractViolation("invalid_schema", path)
    if depth > policy.max_depth:
        raise ContractViolation("schema_limit_exceeded", path)
    if root:
        try:
            encoded = json.dumps(
                schema,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise ContractViolation("invalid_schema", path) from error
        if len(encoded) > policy.max_schema_bytes:
            raise ContractViolation("schema_limit_exceeded", path)
    if any(not isinstance(key, str) for key in schema):
        raise ContractViolation("invalid_schema", path)
    schema_type = schema.get("type")
    unsupported_keywords = set(schema) - _COMMON_SCHEMA_KEYWORDS
    if isinstance(schema_type, str) and schema_type in _SCHEMA_TYPES:
        unsupported_keywords -= _SCHEMA_KEYWORDS_BY_TYPE[schema_type]
    if root:
        unsupported_keywords -= _ROOT_SCHEMA_KEYWORDS
    if unsupported_keywords:
        keyword = min(unsupported_keywords)
        raise ContractViolation("unsupported_schema_keyword", f"{path}.{keyword}")
    if schema_type is None:
        raise ContractViolation("invalid_schema", f"{path}.type")
    if not isinstance(schema_type, str) or schema_type not in _SCHEMA_TYPES:
        raise ContractViolation("unsupported_schema_type", f"{path}.type")
    if root and schema_type != "object":
        raise ContractViolation("invalid_object_schema", path)
    if schema_type == "object":
        if schema.get("additionalProperties") is not False:
            raise ContractViolation(
                "open_object_schema",
                f"{path}.additionalProperties",
            )
        properties = schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise ContractViolation("invalid_object_schema", f"{path}.properties")
        if any(not isinstance(name, str) for name in properties):
            raise ContractViolation("invalid_object_schema", f"{path}.properties")
        if len(properties) > policy.max_properties:
            raise ContractViolation("schema_limit_exceeded", f"{path}.properties")
        required = schema.get("required", [])
        if not isinstance(required, list):
            raise ContractViolation("invalid_object_schema", f"{path}.required")
        seen_required: set[str] = set()
        for index, name in enumerate(required):
            if (
                not isinstance(name, str)
                or name not in properties
                or name in seen_required
            ):
                raise ContractViolation(
                    "invalid_object_schema",
                    f"{path}.required[{index}]",
                )
            seen_required.add(name)
        for name, child in properties.items():
            _validate_schema_node(
                child,
                f"{path}.properties.{name}",
                policy=policy,
                depth=depth + 1,
            )
    elif schema_type == "string":
        if not _is_non_negative_integer(schema.get("maxLength")):
            raise ContractViolation(
                "unbounded_string_schema",
                f"{path}.maxLength",
            )
        if schema["maxLength"] > policy.max_string_length:
            raise ContractViolation("schema_limit_exceeded", f"{path}.maxLength")
    elif schema_type == "array":
        if not _is_non_negative_integer(schema.get("maxItems")):
            raise ContractViolation(
                "unbounded_array_schema",
                f"{path}.maxItems",
            )
        if schema["maxItems"] > policy.max_array_items:
            raise ContractViolation("schema_limit_exceeded", f"{path}.maxItems")
        _validate_schema_node(
            schema.get("items"),
            f"{path}.items",
            policy=policy,
            depth=depth + 1,
        )


class ToolCatalog:
    """Immutable, validated set of exposed tool definitions."""

    def __init__(
        self,
        definitions: Iterable[ToolDefinition[Any, Any]],
        *,
        schema_policy: SchemaPolicy = SchemaPolicy(),
    ) -> None:
        tools = tuple(definitions)
        by_name: dict[str, ToolDefinition[Any, Any]] = {}
        for index, definition in enumerate(tools):
            if not isinstance(definition, ToolDefinition):
                raise ContractViolation("invalid_tool_definition", f"tools[{index}]")
            try:
                metadata = definition.metadata
                input_schema = definition.input_schema
                output_schema = definition.output_schema
                handler = definition.handler
                parse_input = definition.parse_input
                serialize_output = definition.serialize_output
            except Exception as error:
                raise ContractViolation(
                    "invalid_tool_definition", f"tools[{index}]"
                ) from error
            if not isinstance(metadata, ToolMetadata):
                raise ContractViolation(
                    "invalid_tool_definition", f"tools[{index}].metadata"
                )
            if not isinstance(handler, ToolHandler):
                raise ContractViolation(
                    "invalid_tool_definition", f"tools[{index}].handler"
                )
            if not callable(parse_input) or not callable(serialize_output):
                raise ContractViolation("invalid_tool_definition", f"tools[{index}]")
            name = metadata.name
            if name in by_name:
                raise ContractViolation(
                    "duplicate_tool_name",
                    f"tools[{index}].metadata.name",
                )
            _validate_schema_node(
                input_schema,
                f"tools[{index}].input_schema",
                policy=schema_policy,
                root=True,
            )
            _validate_schema_node(
                output_schema,
                f"tools[{index}].output_schema",
                policy=schema_policy,
                root=True,
            )
            by_name[name] = definition
        self._tools = tools
        self._by_name = MappingProxyType(by_name)

    def __iter__(self) -> Iterator[ToolDefinition[Any, Any]]:
        return iter(self._tools)

    def __len__(self) -> int:
        return len(self._tools)

    def get(self, name: str) -> ToolDefinition[Any, Any] | None:
        return self._by_name.get(name)


__all__ = ["ContractViolation", "SchemaPolicy", "ToolCatalog"]
