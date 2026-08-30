"""Registration-time validation for typed tool definitions."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, TypeGuard

from tesserix_mcp_runtime.contracts import JsonValue, ToolDefinition, ToolHandler, ToolMetadata
from tesserix_mcp_runtime.tool_manifest import ToolManifest

_SCHEMA_TYPES: frozenset[str] = frozenset(
    {"array", "boolean", "integer", "null", "number", "object", "string"}
)
_COMMON_SCHEMA_KEYWORDS: frozenset[str] = frozenset(
    {
        "$comment",
        "$ref",
        "anyOf",
        "const",
        "default",
        "description",
        "enum",
        "examples",
        "title",
        "type",
    }
)
_SCHEMA_KEYWORDS_BY_TYPE: dict[str, frozenset[str]] = {
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
            "propertyNames",
            "properties",
            "required",
        }
    ),
    "string": frozenset({"format", "maxLength", "minLength"}),
}
_ROOT_SCHEMA_KEYWORDS: frozenset[str] = frozenset({"$defs", "$id", "$schema"})
_DEFINITION_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")
_LOCAL_DEFINITION_PREFIX = "#/$defs/"


class ContractViolation(ValueError):
    """Identify a deterministic authoring-time contract failure."""

    def __init__(self, code: str, path: str) -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code} at {path}")


class DuplicateToolName(ContractViolation):
    """Report both definitions that collide under portable name normalization."""

    def __init__(
        self,
        *,
        first_name: str,
        first_path: str,
        second_name: str,
        second_path: str,
    ) -> None:
        self.first_name = first_name
        self.first_path = first_path
        self.second_name = second_name
        self.normalized_name = normalize_tool_name(second_name)
        super().__init__("duplicate_tool_name", second_path)
        self.args = (
            f"duplicate_tool_name: {first_name!r} at {first_path} and "
            f"{second_name!r} at {second_path} normalize to {self.normalized_name!r}",
        )


def normalize_tool_name(name: str) -> str:
    """Return the case-insensitive name used across registry and gateway metadata."""

    return name.casefold()


_SCHEMA_POLICY_MAXIMA: Final = (
    ("max_schema_bytes", 262_144),
    ("max_depth", 32),
    ("max_properties", 256),
    ("max_string_length", 65_536),
    ("max_array_items", 4_096),
    ("max_definitions", 256),
    ("max_schema_nodes", 16_384),
    ("max_union_variants", 64),
)


@dataclass(frozen=True, slots=True, kw_only=True)
class SchemaPolicy:
    """Registration limits for the supported closed JSON Schema subset."""

    max_schema_bytes: int = 65_536
    max_depth: int = 16
    max_properties: int = 128
    max_string_length: int = 65_536
    max_array_items: int = 1_024
    max_definitions: int = 128
    max_schema_nodes: int = 4_096
    max_union_variants: int = 16

    def __post_init__(self) -> None:
        for name, maximum in _SCHEMA_POLICY_MAXIMA:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be a positive integer at most {maximum}")


_DEFAULT_SCHEMA_POLICY = SchemaPolicy()


_METADATA_POLICY_MAXIMA: Final = (
    ("max_description_bytes", 4_096),
    ("max_description_tokens", 512),
    ("max_summary_bytes", 512),
    ("max_summary_tokens", 128),
    ("max_when_to_use_bytes", 2_048),
    ("max_when_to_use_tokens", 256),
    ("max_examples", 8),
    ("max_example_bytes", 1_024),
    ("max_example_tokens", 128),
    ("max_total_example_bytes", 4_096),
    ("max_total_example_tokens", 512),
)


@dataclass(frozen=True, slots=True, kw_only=True)
class MetadataPolicy:
    """Deterministic UTF-8 and portable-token budgets for public tool text."""

    max_description_bytes: int = 4_096
    max_description_tokens: int = 512
    max_summary_bytes: int = 512
    max_summary_tokens: int = 128
    max_when_to_use_bytes: int = 2_048
    max_when_to_use_tokens: int = 256
    max_examples: int = 8
    max_example_bytes: int = 1_024
    max_example_tokens: int = 128
    max_total_example_bytes: int = 4_096
    max_total_example_tokens: int = 512

    def __post_init__(self) -> None:
        for name, maximum in _METADATA_POLICY_MAXIMA:
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be a positive integer at most {maximum}")

    def validate(self, metadata: ToolMetadata) -> None:
        _validate_text_budget(
            metadata.description,
            path="metadata.description",
            max_bytes=self.max_description_bytes,
            max_tokens=self.max_description_tokens,
        )
        discovery = metadata.discovery
        if discovery is None:
            return
        _validate_text_budget(
            discovery.summary,
            path="metadata.discovery.summary",
            max_bytes=self.max_summary_bytes,
            max_tokens=self.max_summary_tokens,
        )
        _validate_text_budget(
            discovery.when_to_use,
            path="metadata.discovery.when_to_use",
            max_bytes=self.max_when_to_use_bytes,
            max_tokens=self.max_when_to_use_tokens,
        )
        if len(discovery.examples) > self.max_examples:
            raise ContractViolation("metadata_limit_exceeded", "metadata.discovery.examples")
        total_bytes = 0
        total_tokens = 0
        for index, example in enumerate(discovery.examples):
            _validate_text_budget(
                example,
                path=f"metadata.discovery.examples[{index}]",
                max_bytes=self.max_example_bytes,
                max_tokens=self.max_example_tokens,
            )
            total_bytes += len(example.encode("utf-8"))
            total_tokens += _portable_token_count(example)
        if (
            total_bytes > self.max_total_example_bytes
            or total_tokens > self.max_total_example_tokens
        ):
            raise ContractViolation("metadata_limit_exceeded", "metadata.discovery.examples")


_PORTABLE_TOKEN = re.compile(r"\w+|[^\w\s]", re.UNICODE)
_DEFAULT_METADATA_POLICY = MetadataPolicy()


def _portable_token_count(value: str) -> int:
    return len(_PORTABLE_TOKEN.findall(value))


def _validate_text_budget(
    value: str,
    *,
    path: str,
    max_bytes: int,
    max_tokens: int,
) -> None:
    if len(value.encode("utf-8")) > max_bytes or _portable_token_count(value) > max_tokens:
        raise ContractViolation("metadata_limit_exceeded", path)


def _is_non_negative_integer(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_object_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    return isinstance(value, Mapping)


def _is_string_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    return _is_object_mapping(value) and all(isinstance(key, str) for key in value)


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


class _SchemaValidationState:
    __slots__ = ("definition_depths", "definitions", "nodes", "policy", "root_path")

    def __init__(
        self,
        *,
        definitions: Mapping[str, object],
        policy: SchemaPolicy,
        root_path: str,
    ) -> None:
        self.definitions = definitions
        self.policy = policy
        self.root_path = root_path
        self.nodes = 0
        self.definition_depths: dict[str, int] = {}


def _validate_schema_node(
    schema: object,
    path: str,
    *,
    policy: SchemaPolicy,
    depth: int = 1,
    root: bool = False,
) -> None:
    if not _is_string_mapping(schema):
        raise ContractViolation("invalid_schema", path)
    if root:
        try:
            encoded = json.dumps(
                schema,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (RecursionError, TypeError, ValueError) as error:
            raise ContractViolation("invalid_schema", path) from error
        if len(encoded) > policy.max_schema_bytes:
            raise ContractViolation("schema_limit_exceeded", path)
    definitions_value: object = schema.get("$defs", {}) if root else {}
    if not _is_string_mapping(definitions_value):
        raise ContractViolation("invalid_schema", f"{path}.$defs")
    if len(definitions_value) > policy.max_definitions:
        raise ContractViolation("schema_limit_exceeded", f"{path}.$defs")
    for name in definitions_value:
        if _DEFINITION_NAME.fullmatch(name) is None:
            raise ContractViolation("invalid_schema", f"{path}.$defs")
    state = _SchemaValidationState(
        definitions=definitions_value,
        policy=policy,
        root_path=path,
    )
    _validate_schema_value(
        schema,
        path,
        depth=depth,
        root=root,
        state=state,
        reference_stack=(),
    )
    for name in definitions_value:
        if name not in state.definition_depths:
            _validate_definition(
                name,
                path=f"{path}.$defs.{name}",
                depth=depth + 1,
                state=state,
                reference_stack=(),
            )


def _validate_schema_value(
    schema: object,
    path: str,
    *,
    depth: int,
    root: bool,
    state: _SchemaValidationState,
    reference_stack: tuple[str, ...],
) -> None:
    if not _is_string_mapping(schema):
        raise ContractViolation("invalid_schema", path)
    if depth > state.policy.max_depth:
        raise ContractViolation("schema_limit_exceeded", path)
    state.nodes += 1
    if state.nodes > state.policy.max_schema_nodes:
        raise ContractViolation("schema_limit_exceeded", path)

    schema_type = schema.get("type")
    unsupported_keywords = set(schema) - _COMMON_SCHEMA_KEYWORDS
    if isinstance(schema_type, str) and schema_type in _SCHEMA_TYPES:
        unsupported_keywords -= _SCHEMA_KEYWORDS_BY_TYPE[schema_type]
    if root:
        unsupported_keywords -= _ROOT_SCHEMA_KEYWORDS
    if unsupported_keywords:
        keyword = min(unsupported_keywords)
        raise ContractViolation("unsupported_schema_keyword", f"{path}.{keyword}")

    variants = schema.get("anyOf")
    if variants is not None:
        if not _is_object_list(variants) or len(variants) < 2:
            raise ContractViolation("invalid_schema", f"{path}.anyOf")
        if len(variants) > state.policy.max_union_variants:
            raise ContractViolation("schema_limit_exceeded", f"{path}.anyOf")
        for index, variant in enumerate(variants):
            _validate_schema_value(
                variant,
                f"{path}.anyOf[{index}]",
                depth=depth + 1,
                root=False,
                state=state,
                reference_stack=reference_stack,
            )

    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str) or not reference.startswith(_LOCAL_DEFINITION_PREFIX):
            raise ContractViolation("unsupported_schema_reference", f"{path}.$ref")
        name = reference.removeprefix(_LOCAL_DEFINITION_PREFIX)
        _validate_definition(
            name,
            path=f"{path}.$ref",
            depth=depth + 1,
            state=state,
            reference_stack=reference_stack,
        )

    if schema_type is None and (variants is not None or reference is not None):
        return
    if schema_type is None:
        raise ContractViolation("invalid_schema", f"{path}.type")
    if not isinstance(schema_type, str) or schema_type not in _SCHEMA_TYPES:
        raise ContractViolation("unsupported_schema_type", f"{path}.type")
    if root and schema_type != "object":
        raise ContractViolation("invalid_object_schema", path)

    _validate_enum(schema, path, schema_type=schema_type, policy=state.policy)
    if schema_type == "object":
        _validate_object_schema(
            schema,
            path,
            depth=depth,
            state=state,
            reference_stack=reference_stack,
        )
    elif schema_type == "string":
        max_length = schema.get("maxLength")
        enum_values = schema.get("enum")
        if max_length is None and _is_object_list(enum_values) and enum_values:
            max_length = max(len(value) for value in enum_values if isinstance(value, str))
        if not _is_non_negative_integer(max_length):
            raise ContractViolation(
                "unbounded_string_schema",
                f"{path}.maxLength",
            )
        if max_length > state.policy.max_string_length:
            raise ContractViolation("schema_limit_exceeded", f"{path}.maxLength")
    elif schema_type == "array":
        max_items = schema.get("maxItems")
        if not _is_non_negative_integer(max_items):
            raise ContractViolation(
                "unbounded_array_schema",
                f"{path}.maxItems",
            )
        if max_items > state.policy.max_array_items:
            raise ContractViolation("schema_limit_exceeded", f"{path}.maxItems")
        _validate_schema_value(
            schema.get("items"),
            f"{path}.items",
            depth=depth + 1,
            root=False,
            state=state,
            reference_stack=reference_stack,
        )


def _validate_definition(
    name: str,
    *,
    path: str,
    depth: int,
    state: _SchemaValidationState,
    reference_stack: tuple[str, ...],
) -> None:
    if name not in state.definitions or _DEFINITION_NAME.fullmatch(name) is None:
        raise ContractViolation("invalid_schema_reference", path)
    if name in reference_stack:
        raise ContractViolation("recursive_schema", path)
    previous_depth = state.definition_depths.get(name)
    if previous_depth is not None and previous_depth >= depth:
        return
    state.definition_depths[name] = depth
    _validate_schema_value(
        state.definitions[name],
        f"{state.root_path}.$defs.{name}",
        depth=depth,
        root=False,
        state=state,
        reference_stack=(*reference_stack, name),
    )


def _validate_enum(
    schema: Mapping[str, object],
    path: str,
    *,
    schema_type: str,
    policy: SchemaPolicy,
) -> None:
    values = schema.get("enum")
    if values is None:
        return
    if not _is_object_list(values) or not values or len(values) > policy.max_properties:
        raise ContractViolation("invalid_schema", f"{path}.enum")
    for index, value in enumerate(values):
        valid = (
            (schema_type == "null" and value is None)
            or (schema_type == "string" and isinstance(value, str))
            or (schema_type == "boolean" and isinstance(value, bool))
            or (schema_type == "integer" and isinstance(value, int) and not isinstance(value, bool))
            or (
                schema_type == "number"
                and isinstance(value, int | float)
                and not isinstance(value, bool)
                and math.isfinite(value)
            )
        )
        if not valid:
            raise ContractViolation("invalid_schema", f"{path}.enum[{index}]")


def _validate_object_schema(
    schema: Mapping[str, object],
    path: str,
    *,
    depth: int,
    state: _SchemaValidationState,
    reference_stack: tuple[str, ...],
) -> None:
    properties_value = schema.get("properties")
    additional = schema.get("additionalProperties")
    is_mapping = properties_value is None and _is_string_mapping(additional)

    if is_mapping:
        max_properties = schema.get("maxProperties")
        if not _is_non_negative_integer(max_properties):
            raise ContractViolation("unbounded_object_schema", f"{path}.maxProperties")
        if max_properties > state.policy.max_properties:
            raise ContractViolation("schema_limit_exceeded", f"{path}.maxProperties")
        _validate_property_names(schema.get("propertyNames"), path, policy=state.policy)
        _validate_schema_value(
            additional,
            f"{path}.additionalProperties",
            depth=depth + 1,
            root=False,
            state=state,
            reference_stack=reference_stack,
        )
        return

    if additional is not False:
        raise ContractViolation("open_object_schema", f"{path}.additionalProperties")
    properties: object = {} if properties_value is None else properties_value
    if not _is_string_mapping(properties):
        raise ContractViolation("invalid_object_schema", f"{path}.properties")
    if len(properties) > state.policy.max_properties:
        raise ContractViolation("schema_limit_exceeded", f"{path}.properties")
    required = schema.get("required", [])
    if not _is_object_list(required):
        raise ContractViolation("invalid_object_schema", f"{path}.required")
    seen_required: set[str] = set()
    for index, name in enumerate(required):
        if not isinstance(name, str) or name not in properties or name in seen_required:
            raise ContractViolation("invalid_object_schema", f"{path}.required[{index}]")
        seen_required.add(name)
    for name, child in properties.items():
        _validate_schema_value(
            child,
            f"{path}.properties.{name}",
            depth=depth + 1,
            root=False,
            state=state,
            reference_stack=reference_stack,
        )


def _validate_property_names(value: object, path: str, *, policy: SchemaPolicy) -> None:
    if not _is_string_mapping(value) or set(value) - {"maxLength", "minLength"}:
        raise ContractViolation("invalid_schema", f"{path}.propertyNames")
    max_length = value.get("maxLength")
    if not _is_non_negative_integer(max_length):
        raise ContractViolation("unbounded_string_schema", f"{path}.propertyNames.maxLength")
    if max_length > policy.max_string_length:
        raise ContractViolation("schema_limit_exceeded", f"{path}.propertyNames.maxLength")


def validate_schema(
    schema: Mapping[str, JsonValue],
    *,
    path: str,
    policy: SchemaPolicy,
) -> None:
    """Validate one root schema against the supported bounded subset."""

    _validate_schema_node(schema, path, policy=policy, root=True)


class ToolCatalog:
    """Immutable, validated set of exposed tool definitions."""

    def __init__(
        self,
        definitions: Iterable[ToolDefinition[Any, Any]],
        *,
        schema_policy: SchemaPolicy = _DEFAULT_SCHEMA_POLICY,
        metadata_policy: MetadataPolicy = _DEFAULT_METADATA_POLICY,
    ) -> None:
        tools = tuple(definitions)
        by_name: dict[str, ToolDefinition[Any, Any]] = {}
        by_normalized_name: dict[str, tuple[int, str]] = {}
        manifests: list[ToolManifest] = []
        for index, definition in enumerate(tools):
            if not _is_runtime_instance(definition, ToolDefinition):
                raise ContractViolation("invalid_tool_definition", f"tools[{index}]")
            try:
                metadata = definition.metadata
                input_schema = definition.input_schema
                output_schema = definition.output_schema
                handler = definition.handler
                parse_input = definition.parse_input
                serialize_output = definition.serialize_output
            except Exception as error:
                raise ContractViolation("invalid_tool_definition", f"tools[{index}]") from error
            if not _is_runtime_instance(metadata, ToolMetadata):
                raise ContractViolation("invalid_tool_definition", f"tools[{index}].metadata")
            metadata_policy.validate(metadata)
            if not _is_runtime_instance(handler, ToolHandler):
                raise ContractViolation("invalid_tool_definition", f"tools[{index}].handler")
            if not callable(parse_input) or not callable(serialize_output):
                raise ContractViolation("invalid_tool_definition", f"tools[{index}]")
            name = metadata.name
            normalized_name = normalize_tool_name(name)
            existing = by_normalized_name.get(normalized_name)
            if existing is not None:
                first_index, first_name = existing
                raise DuplicateToolName(
                    first_name=first_name,
                    first_path=f"tools[{first_index}].metadata.name",
                    second_name=name,
                    second_path=f"tools[{index}].metadata.name",
                )
            validate_schema(
                input_schema,
                path=f"tools[{index}].input_schema",
                policy=schema_policy,
            )
            validate_schema(
                output_schema,
                path=f"tools[{index}].output_schema",
                policy=schema_policy,
            )
            by_name[name] = definition
            by_normalized_name[normalized_name] = (index, name)
            manifests.append(
                ToolManifest(
                    metadata=metadata,
                    normalized_name=normalized_name,
                    input_schema=input_schema,
                    output_schema=output_schema,
                )
            )
        self._tools = tools
        self._by_name = MappingProxyType(by_name)
        self._manifests = tuple(manifests)

    def __iter__(self) -> Iterator[ToolDefinition[Any, Any]]:
        return iter(self._tools)

    def __len__(self) -> int:
        return len(self._tools)

    def get(self, name: str) -> ToolDefinition[Any, Any] | None:
        return self._by_name.get(name)

    @property
    def manifests(self) -> tuple[ToolManifest, ...]:
        return self._manifests

    def export_metadata(self) -> list[dict[str, JsonValue]]:
        return [manifest.to_dict() for manifest in self._manifests]


__all__ = [
    "ContractViolation",
    "DuplicateToolName",
    "MetadataPolicy",
    "SchemaPolicy",
    "ToolCatalog",
    "normalize_tool_name",
]
