"""Create runtime tool definitions from typed callables through the MCP SDK."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Mapping
from typing import Any, TypeGuard, cast

from mcp.server.mcpserver.exceptions import InvalidSignature
from mcp.server.mcpserver.tools import Tool
from mcp.server.mcpserver.utilities.func_metadata import FuncMetadata
from mcp.types import CallToolResult

from tesserix_mcp_runtime.contracts import (
    CallContext,
    JsonValue,
    ToolHandler,
    ToolMetadata,
)
from tesserix_mcp_runtime.tool import (
    ContractViolation,
    MetadataPolicy,
    SchemaPolicy,
    validate_schema,
)

_DEFAULT_METADATA_POLICY = MetadataPolicy()
_DEFAULT_SCHEMA_POLICY = SchemaPolicy()
_FORBIDDEN_IDENTITY_FIELDS = frozenset(
    {
        "apikey",
        "authorization",
        "context",
        "credential",
        "credentials",
        "identity",
        "principal",
        "role",
        "roles",
        "scope",
        "scopes",
        "secret",
        "subject",
        "tenant",
        "tenantid",
        "token",
        "accesstoken",
        "refreshtoken",
        "user",
        "userid",
    }
)


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


def _schema_document(schema: Mapping[str, Any], *, close_root: bool) -> dict[str, JsonValue]:
    candidate = dict(schema)
    if close_root:
        candidate["additionalProperties"] = False
    try:
        decoded: object = json.loads(
            json.dumps(
                candidate,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
    except (TypeError, ValueError) as error:
        raise ContractViolation("invalid_callable_schema", "callable") from error
    if not _is_json_object(decoded):
        raise ContractViolation("invalid_callable_schema", "callable")
    return decoded


class CallableToolDefinition:
    """Adapt one typed callable to the transport-neutral tool contract."""

    def __init__(
        self,
        function: Callable[..., Any],
        *,
        metadata: ToolMetadata,
        metadata_policy: MetadataPolicy = _DEFAULT_METADATA_POLICY,
        schema_policy: SchemaPolicy = _DEFAULT_SCHEMA_POLICY,
    ) -> None:
        metadata_policy.validate(metadata)
        try:
            tool = Tool.from_function(
                function,
                name=metadata.name,
                title=metadata.title,
                description=metadata.description,
                structured_output=True,
            )
        except (InvalidSignature, RuntimeError, TypeError, ValueError) as error:
            raise ContractViolation("invalid_callable_schema", "callable") from error
        if tool.output_schema is None:
            raise ContractViolation("invalid_callable_schema", "callable.return")

        self._function = function
        self._metadata = metadata
        self._function_metadata: FuncMetadata = tool.fn_metadata
        self._is_async = tool.is_async
        self._input_schema = _schema_document(tool.parameters, close_root=True)
        self._output_schema = _schema_document(tool.output_schema, close_root=False)
        validate_schema(self._input_schema, path="input_schema", policy=schema_policy)
        _validate_identity_fields(self._input_schema)
        validate_schema(self._output_schema, path="output_schema", policy=schema_policy)
        self._argument_names = frozenset(
            field.alias or name
            for name, field in self._function_metadata.arg_model.model_fields.items()
        )

    @property
    def metadata(self) -> ToolMetadata:
        return self._metadata

    @property
    def input_schema(self) -> Mapping[str, JsonValue]:
        return _schema_document(self._input_schema, close_root=False)

    @property
    def output_schema(self) -> Mapping[str, JsonValue]:
        return _schema_document(self._output_schema, close_root=False)

    @property
    def handler(self) -> ToolHandler[dict[str, Any], Any]:
        return self

    def parse_input(self, arguments: Mapping[str, JsonValue]) -> dict[str, Any]:
        values = dict(arguments)
        if not values.keys() <= self._argument_names:
            raise ValueError("arguments contain an unknown field")
        return self._function_metadata.validate_arguments(values)

    async def __call__(
        self,
        input_model: dict[str, Any],
        *,
        context: CallContext,
    ) -> Any:
        del context
        return await self._function_metadata.call_fn(
            self._function,
            self._is_async,
            input_model,
        )

    def serialize_output(self, output_model: Any) -> JsonValue:
        try:
            converted = self._function_metadata.convert_result(output_model)
        except (TypeError, ValueError) as error:
            raise ValueError("callable returned invalid structured content") from error
        if not isinstance(converted, CallToolResult):
            raise ValueError("callable returned an unsupported control result")
        structured = converted.structured_content
        if not _is_json_object(structured):
            raise ValueError("callable returned invalid structured content")
        return structured


def callable_tool(
    function: Callable[..., Any],
    *,
    metadata: ToolMetadata,
    metadata_policy: MetadataPolicy = _DEFAULT_METADATA_POLICY,
    schema_policy: SchemaPolicy = _DEFAULT_SCHEMA_POLICY,
) -> CallableToolDefinition:
    """Register one typed callable without copying its schema."""

    return CallableToolDefinition(
        function,
        metadata=metadata,
        metadata_policy=metadata_policy,
        schema_policy=schema_policy,
    )


def _validate_identity_fields(schema: Mapping[str, JsonValue]) -> None:
    pending: list[tuple[object, str]] = [(schema, "input_schema")]
    while pending:
        value, path = pending.pop()
        if isinstance(value, dict):
            mapping = cast(dict[object, object], value)
            for key, child in mapping.items():
                if not isinstance(key, str):
                    raise ContractViolation("invalid_callable_schema", path)
                child_path = f"{path}.{key}"
                if key == "properties" and isinstance(child, dict):
                    properties = cast(dict[object, object], child)
                    for field_name, field_schema in properties.items():
                        if not isinstance(field_name, str):
                            raise ContractViolation("invalid_callable_schema", child_path)
                        normalized = re.sub(r"[^a-z0-9]", "", field_name.casefold())
                        field_path = f"{child_path}.{field_name}"
                        if normalized in _FORBIDDEN_IDENTITY_FIELDS:
                            raise ContractViolation("forbidden_identity_field", field_path)
                        pending.append((field_schema, field_path))
                else:
                    pending.append((child, child_path))
        elif isinstance(value, list):
            items = cast(list[object], value)
            pending.extend((item, f"{path}[{index}]") for index, item in enumerate(items))


__all__ = ["CallableToolDefinition", "callable_tool"]
