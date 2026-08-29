from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    ContractViolation,
    IdempotencyRequirement,
    JsonValue,
    SchemaPolicy,
    ToolCatalog,
    ToolDefinition,
    ToolEffect,
    ToolHandler,
    ToolMetadata,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_tool_metadata_is_typed_and_immutable() -> None:
    metadata = ToolMetadata(
        name="orders.get",
        title="Get an order",
        description="Return one synthetic order by identifier.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("orders:read",),
    )

    assert metadata.name == "orders.get"
    assert metadata.effect is ToolEffect.READ
    assert metadata.required_scopes == ("orders:read",)

    with pytest.raises(FrozenInstanceError):
        metadata.name = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"name": "orders get"},
        {"title": ""},
        {"description": "x" * 2049},
        {"effect": "delete"},
        {"approval": "sometimes"},
        {"idempotency": "best_effort"},
        {"required_scopes": ["orders:read"]},
        {"required_scopes": ("orders:read", "orders:read")},
        {"required_scopes": ("orders read",)},
        {
            "effect": ToolEffect.WRITE,
            "idempotency": IdempotencyRequirement.NOT_APPLICABLE,
        },
        {
            "effect": ToolEffect.EXTERNAL_EFFECT,
            "idempotency": IdempotencyRequirement.NOT_APPLICABLE,
        },
    ],
)
def test_tool_metadata_rejects_invalid_or_unsafe_values(
    overrides: dict[str, Any],
) -> None:
    values: dict[str, Any] = {
        "name": "orders.get",
        "title": "Get an order",
        "description": "Return one synthetic order by identifier.",
        "effect": ToolEffect.READ,
        "approval": ApprovalRequirement.NOT_REQUIRED,
        "idempotency": IdempotencyRequirement.NOT_APPLICABLE,
        "required_scopes": ("orders:read",),
    }
    values.update(overrides)

    with pytest.raises(ValueError):
        ToolMetadata(**values)


def test_write_metadata_requires_an_explicit_idempotency_contract() -> None:
    with pytest.raises(TypeError):
        ToolMetadata(  # type: ignore[call-arg]
            name="orders.update",
            title="Update an order",
            description="Apply one synthetic order update.",
            effect=ToolEffect.WRITE,
            approval=ApprovalRequirement.REQUIRED,
            required_scopes=("orders:write",),
        )


@dataclass(frozen=True, slots=True)
class EchoInput:
    text: str


@dataclass(frozen=True, slots=True)
class EchoOutput:
    text: str


class EchoHandler:
    async def __call__(
        self,
        input_model: EchoInput,
        *,
        context: Any,
    ) -> EchoOutput:
        del context
        return EchoOutput(text=input_model.text)


@dataclass(frozen=True, slots=True)
class EchoDefinition:
    metadata: ToolMetadata
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    handler: EchoHandler

    def parse_input(self, arguments: Mapping[str, Any]) -> EchoInput:
        return EchoInput(text=str(arguments["text"]))

    def serialize_output(self, output_model: EchoOutput) -> dict[str, JsonValue]:
        return {"text": output_model.text}


def echo_definition(
    *,
    name: str = "example.echo",
    input_schema: Mapping[str, Any] | None = None,
    output_schema: Mapping[str, Any] | None = None,
) -> EchoDefinition:
    return EchoDefinition(
        metadata=ToolMetadata(
            name=name,
            title="Echo text",
            description="Return bounded synthetic text.",
            effect=ToolEffect.READ,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.NOT_APPLICABLE,
            required_scopes=("example:read",),
        ),
        input_schema=input_schema
        if input_schema is not None
        else {
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 128}},
            "required": ["text"],
            "additionalProperties": False,
        },
        output_schema=output_schema
        if output_schema is not None
        else {
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 128}},
            "required": ["text"],
            "additionalProperties": False,
        },
        handler=EchoHandler(),
    )


def test_typed_tool_definition_and_handler_are_structural_contracts() -> None:
    definition = echo_definition()

    assert isinstance(definition, ToolDefinition)
    assert isinstance(definition.handler, ToolHandler)
    assert definition.parse_input({"text": "hello"}) == EchoInput(text="hello")


def test_tool_catalog_rejects_non_structural_definitions_with_a_contract_error() -> None:
    malformed: Any = object()

    with pytest.raises(ContractViolation) as captured:
        ToolCatalog([malformed])

    assert captured.value.code == "invalid_tool_definition"
    assert captured.value.path == "tools[0]"


def test_tool_catalog_rejects_structurally_present_but_invalid_fields() -> None:
    valid = echo_definition()
    malformed: Any = SimpleNamespace(
        metadata=object(),
        input_schema=valid.input_schema,
        output_schema=valid.output_schema,
        handler=valid.handler,
        parse_input=valid.parse_input,
        serialize_output=valid.serialize_output,
    )

    with pytest.raises(ContractViolation) as captured:
        ToolCatalog([malformed])

    assert captured.value.code == "invalid_tool_definition"
    assert captured.value.path == "tools[0].metadata"


def test_tool_catalog_rejects_an_invalid_handler_field() -> None:
    valid = echo_definition()
    malformed: Any = SimpleNamespace(
        metadata=valid.metadata,
        input_schema=valid.input_schema,
        output_schema=valid.output_schema,
        handler=object(),
        parse_input=valid.parse_input,
        serialize_output=valid.serialize_output,
    )

    with pytest.raises(ContractViolation) as captured:
        ToolCatalog([malformed])

    assert captured.value.code == "invalid_tool_definition"
    assert captured.value.path == "tools[0].handler"


def test_tool_catalog_rejects_duplicate_exposed_names() -> None:
    with pytest.raises(ContractViolation) as captured:
        ToolCatalog([echo_definition(), echo_definition()])

    assert captured.value.code == "duplicate_tool_name"
    assert captured.value.path == "tools[1].metadata.name"


def test_tool_catalog_rejects_an_open_input_schema() -> None:
    definition = echo_definition(
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string", "maxLength": 128}},
            "required": ["text"],
        }
    )

    with pytest.raises(ContractViolation) as captured:
        ToolCatalog([definition])

    assert captured.value.code == "open_object_schema"
    assert captured.value.path == "tools[0].input_schema.additionalProperties"


@pytest.mark.parametrize(
    ("schema_field", "schema", "code", "path"),
    [
        (
            "input_schema",
            {
                "type": "object",
                "properties": {
                    "nested": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": True,
                    }
                },
                "additionalProperties": False,
            },
            "open_object_schema",
            "tools[0].input_schema.properties.nested.additionalProperties",
        ),
        (
            "input_schema",
            {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "additionalProperties": False,
            },
            "unbounded_string_schema",
            "tools[0].input_schema.properties.text.maxLength",
        ),
        (
            "input_schema",
            {
                "type": "object",
                "properties": {
                    "tags": {
                        "type": "array",
                        "items": {"type": "string", "maxLength": 32},
                    }
                },
                "additionalProperties": False,
            },
            "unbounded_array_schema",
            "tools[0].input_schema.properties.tags.maxItems",
        ),
        (
            "output_schema",
            {
                "type": "object",
                "properties": {"text": {"type": "string", "maxLength": 128}},
                "additionalProperties": True,
            },
            "open_object_schema",
            "tools[0].output_schema.additionalProperties",
        ),
    ],
)
def test_tool_catalog_recursively_rejects_open_or_unbounded_schemas(
    schema_field: str,
    schema: Mapping[str, Any],
    code: str,
    path: str,
) -> None:
    definition = echo_definition(**{schema_field: schema})  # type: ignore[arg-type]

    with pytest.raises(ContractViolation) as captured:
        ToolCatalog([definition])

    assert captured.value.code == code
    assert captured.value.path == path


@pytest.mark.parametrize(
    ("schema", "code", "path"),
    [
        (
            {
                "type": "object",
                "properties": {"value": {}},
                "additionalProperties": False,
            },
            "invalid_schema",
            "tools[0].input_schema.properties.value.type",
        ),
        (
            {
                "type": "object",
                "properties": {"value": {"type": "binary"}},
                "additionalProperties": False,
            },
            "unsupported_schema_type",
            "tools[0].input_schema.properties.value.type",
        ),
        (
            {
                "type": "object",
                "properties": {"value": {"type": "boolean"}},
                "required": "value",
                "additionalProperties": False,
            },
            "invalid_object_schema",
            "tools[0].input_schema.required",
        ),
        (
            {
                "type": "object",
                "properties": {"value": {"type": "boolean"}},
                "required": ["missing"],
                "additionalProperties": False,
            },
            "invalid_object_schema",
            "tools[0].input_schema.required[0]",
        ),
        (
            {
                "type": "object",
                "properties": {1: {"type": "boolean"}},
                "additionalProperties": False,
            },
            "invalid_object_schema",
            "tools[0].input_schema.properties",
        ),
        (
            {
                "type": "object",
                "properties": {},
                "default": math.nan,
                "additionalProperties": False,
            },
            "invalid_schema",
            "tools[0].input_schema",
        ),
        (
            {
                "type": "object",
                "properties": {
                    "value": {
                        "oneOf": [
                            {"type": "string", "maxLength": 8},
                            {"type": "string"},
                        ]
                    }
                },
                "additionalProperties": False,
            },
            "unsupported_schema_keyword",
            "tools[0].input_schema.properties.value.oneOf",
        ),
    ],
    ids=[
        "missing-type",
        "unsupported-type",
        "malformed-required",
        "unknown-required-property",
        "non-text-property-name",
        "non-json-number",
        "unsupported-composition",
    ],
)
def test_tool_catalog_rejects_invalid_or_unsupported_schema_constructs(
    schema: Mapping[str, Any],
    code: str,
    path: str,
) -> None:
    with pytest.raises(ContractViolation) as captured:
        ToolCatalog([echo_definition(input_schema=schema)])

    assert captured.value.code == code
    assert captured.value.path == path


def test_tool_metadata_serialization_matches_the_golden_contract() -> None:
    metadata = ToolMetadata(
        name="orders.update",
        title="Update an order",
        description="Apply one synthetic order update.",
        effect=ToolEffect.WRITE,
        approval=ApprovalRequirement.REQUIRED,
        idempotency=IdempotencyRequirement.REQUIRED,
        required_scopes=("orders:write",),
    )
    expected = json.loads((FIXTURES / "tool-metadata.json").read_text(encoding="utf-8"))

    assert metadata.to_dict() == expected


@given(
    properties=st.dictionaries(
        keys=st.from_regex(r"[a-z][a-z0-9_]{0,15}", fullmatch=True),
        values=st.sampled_from(
            [
                {"type": "boolean"},
                {"type": "integer"},
                {"type": "string", "maxLength": 32},
            ]
        ),
        max_size=8,
    ),
    additional_properties=st.one_of(st.none(), st.just(True), st.just({})),
)
def test_all_generated_open_object_schemas_are_rejected(
    properties: dict[str, Any],
    additional_properties: Any,
) -> None:
    definition = echo_definition(
        input_schema={
            "type": "object",
            "properties": properties,
            "additionalProperties": additional_properties,
        }
    )

    with pytest.raises(ContractViolation) as captured:
        ToolCatalog([definition])

    assert captured.value.code == "open_object_schema"


@pytest.mark.parametrize(
    ("schema", "code", "path"),
    [
        (
            {
                "type": "object",
                "properties": {"text": {"type": "string", "maxLength": 129}},
                "additionalProperties": False,
            },
            "schema_limit_exceeded",
            "tools[0].input_schema.properties.text.maxLength",
        ),
        (
            {
                "type": "object",
                "properties": {
                    "tags": {
                        "type": "array",
                        "maxItems": 9,
                        "items": {"type": "string", "maxLength": 32},
                    }
                },
                "additionalProperties": False,
            },
            "schema_limit_exceeded",
            "tools[0].input_schema.properties.tags.maxItems",
        ),
        (
            {
                "type": "object",
                "properties": {
                    "first": {"type": "boolean"},
                    "second": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            "schema_limit_exceeded",
            "tools[0].input_schema.properties",
        ),
    ],
)
def test_schema_policy_enforces_reviewed_registration_limits(
    schema: Mapping[str, Any],
    code: str,
    path: str,
) -> None:
    policy = SchemaPolicy(
        max_schema_bytes=4096,
        max_depth=8,
        max_properties=1,
        max_string_length=128,
        max_array_items=8,
    )

    with pytest.raises(ContractViolation) as captured:
        ToolCatalog([echo_definition(input_schema=schema)], schema_policy=policy)

    assert captured.value.code == code
    assert captured.value.path == path


def test_schema_policy_enforces_the_serialized_byte_budget() -> None:
    schema = {
        "type": "object",
        "properties": {"text": {"type": "string", "maxLength": 128}},
        "description": "é" * 64,
        "additionalProperties": False,
    }
    encoded_size = len(
        json.dumps(
            schema,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )

    with pytest.raises(ContractViolation) as captured:
        ToolCatalog(
            [echo_definition(input_schema=schema)],
            schema_policy=SchemaPolicy(max_schema_bytes=encoded_size - 1),
        )

    assert captured.value.code == "schema_limit_exceeded"
    assert captured.value.path == "tools[0].input_schema"
    assert (
        len(
            ToolCatalog(
                [echo_definition(input_schema=schema)],
                schema_policy=SchemaPolicy(max_schema_bytes=encoded_size),
            )
        )
        == 1
    )


def test_schema_policy_enforces_the_recursive_depth_budget() -> None:
    schema = {
        "type": "object",
        "properties": {
            "payload": {
                "type": "object",
                "properties": {"value": {"type": "string", "maxLength": 128}},
                "additionalProperties": False,
            }
        },
        "additionalProperties": False,
    }

    with pytest.raises(ContractViolation) as captured:
        ToolCatalog(
            [echo_definition(input_schema=schema)],
            schema_policy=SchemaPolicy(max_depth=2),
        )

    assert captured.value.code == "schema_limit_exceeded"
    assert captured.value.path == "tools[0].input_schema.properties.payload.properties.value"
    assert (
        len(
            ToolCatalog(
                [echo_definition(input_schema=schema)],
                schema_policy=SchemaPolicy(max_depth=3),
            )
        )
        == 1
    )
