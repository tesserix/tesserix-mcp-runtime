from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Mapping

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tesserix_mcp_runtime import (
    JsonValue,
    SchemaChange,
    SchemaDirection,
    classify_schema_change,
    schema_fingerprint,
)


def object_schema(
    properties: Mapping[str, JsonValue],
    *,
    required: list[str],
) -> dict[str, JsonValue]:
    required_values: list[JsonValue] = list(required)
    document: dict[str, JsonValue] = {
        "type": "object",
        "properties": dict(properties),
        "required": required_values,
        "additionalProperties": False,
    }
    return document


MALFORMED_SCHEMA_SHAPES: list[dict[str, JsonValue]] = [
    {"anyOf": []},
    {"anyOf": ["not-a-schema"]},
    {"type": ["string", "null"]},
    {"type": "array", "items": True},
    {"type": "object", "properties": []},
    {"type": "object", "properties": {"value": "not-a-schema"}},
    {"type": "object", "required": "value", "properties": {}},
    {"type": "object", "required": [{}], "properties": {}},
]


@given(
    st.dictionaries(
        keys=st.text(
            alphabet=st.characters(categories=("Ll", "Lu", "Nd")),
            min_size=1,
            max_size=12,
        ),
        values=st.integers(min_value=-1_000, max_value=1_000),
        min_size=1,
        max_size=20,
    )
)
def test_schema_fingerprint_is_independent_of_mapping_order(values: dict[str, int]) -> None:
    forward: dict[str, JsonValue] = dict(values)
    reversed_order: dict[str, JsonValue] = dict(reversed(tuple(values.items())))

    assert schema_fingerprint(forward) == schema_fingerprint(reversed_order)


def test_schema_fingerprint_is_stable_across_process_hash_seeds() -> None:
    script = """
from tesserix_mcp_runtime import schema_fingerprint
schema = {
    "required": ["text"],
    "properties": {"text": {"maxLength": 64, "type": "string"}},
    "additionalProperties": False,
    "type": "object",
}
print(schema_fingerprint(schema))
"""

    fingerprints: list[str] = []
    for seed in ("1", "8675309"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=10,
        )
        assert completed.returncode == 0, completed.stderr
        fingerprints.append(completed.stdout.strip())

    assert len(set(fingerprints)) == 1


def test_input_schema_widening_is_non_breaking_but_tightening_is_breaking() -> None:
    previous = object_schema(
        {"query": {"type": "string", "maxLength": 64}},
        required=["query"],
    )
    widened = object_schema(
        {
            "query": {"type": "string", "maxLength": 128},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        },
        required=["query"],
    )
    tightened = object_schema(
        {"query": {"type": "string", "maxLength": 32}},
        required=["query"],
    )

    assert (
        classify_schema_change(previous, widened, direction=SchemaDirection.INPUT)
        is SchemaChange.NON_BREAKING
    )
    assert (
        classify_schema_change(previous, tightened, direction=SchemaDirection.INPUT)
        is SchemaChange.BREAKING
    )


def test_output_schema_narrowing_is_non_breaking_but_widening_is_breaking() -> None:
    previous = object_schema(
        {"text": {"type": "string", "maxLength": 128}},
        required=["text"],
    )
    narrowed = object_schema(
        {"text": {"type": "string", "maxLength": 64}},
        required=["text"],
    )
    widened = object_schema(
        {"text": {"type": "string", "maxLength": 256}},
        required=["text"],
    )

    assert (
        classify_schema_change(previous, narrowed, direction=SchemaDirection.OUTPUT)
        is SchemaChange.NON_BREAKING
    )
    assert (
        classify_schema_change(previous, widened, direction=SchemaDirection.OUTPUT)
        is SchemaChange.BREAKING
    )


def test_schema_change_classification_is_deterministic_for_docs_and_required_fields() -> None:
    previous = object_schema(
        {"query": {"type": "string", "maxLength": 64, "description": "Old text"}},
        required=["query"],
    )
    documentation_only = object_schema(
        {"query": {"type": "string", "maxLength": 64, "description": "New text"}},
        required=["query"],
    )
    newly_required = object_schema(
        {
            "query": {"type": "string", "maxLength": 64},
            "region": {"type": "string", "maxLength": 16},
        },
        required=["query", "region"],
    )

    assert (
        classify_schema_change(
            previous,
            dict(reversed(tuple(previous.items()))),
            direction=SchemaDirection.INPUT,
        )
        is SchemaChange.IDENTICAL
    )
    assert (
        classify_schema_change(previous, documentation_only, direction=SchemaDirection.INPUT)
        is SchemaChange.NON_BREAKING
    )
    assert (
        classify_schema_change(previous, newly_required, direction=SchemaDirection.INPUT)
        is SchemaChange.BREAKING
    )


@pytest.mark.parametrize(
    ("previous", "current", "expected"),
    [
        (
            {"type": "string", "minLength": 2, "maxLength": 64},
            {"type": "string", "maxLength": 128},
            SchemaChange.NON_BREAKING,
        ),
        (
            {"type": "string", "maxLength": 64},
            {"type": "string", "minLength": 2, "maxLength": 64},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "string", "format": "email", "maxLength": 64},
            {"type": "string", "maxLength": 64},
            SchemaChange.NON_BREAKING,
        ),
        (
            {"type": "string", "maxLength": 64},
            {"type": "string", "format": "email", "maxLength": 64},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "string", "enum": ["a", "b"]},
            {"type": "string", "enum": ["a", "b", "c"]},
            SchemaChange.NON_BREAKING,
        ),
        (
            {"type": "string", "enum": ["a", "b"]},
            {"type": "string", "const": "a"},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "string"},
            {"type": "string", "enum": ["a", "b"]},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "integer", "minimum": 0, "maximum": 10},
            {"type": "number", "minimum": -1, "maximum": 20},
            SchemaChange.NON_BREAKING,
        ),
        (
            {"type": "number", "minimum": 0},
            {"type": "integer", "minimum": 0},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 10},
            {"type": "number", "minimum": 0, "maximum": 10},
            SchemaChange.NON_BREAKING,
        ),
        (
            {"type": "number", "minimum": 0, "maximum": 10},
            {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 10},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "number", "multipleOf": 2},
            {"type": "number"},
            SchemaChange.NON_BREAKING,
        ),
        (
            {"type": "number"},
            {"type": "number", "multipleOf": 2},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "number"},
            {"type": "number", "minimum": 1},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "number"},
            {"type": "number", "maximum": 9},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "number", "minimum": 0, "maximum": 10},
            {"type": "number", "minimum": 1, "maximum": 9},
            SchemaChange.BREAKING,
        ),
        (
            {
                "type": "array",
                "items": {"type": "integer"},
                "minItems": 2,
                "maxItems": 4,
                "uniqueItems": True,
            },
            {
                "type": "array",
                "items": {"type": "number"},
                "minItems": 1,
                "maxItems": 8,
            },
            SchemaChange.NON_BREAKING,
        ),
        (
            {
                "type": "array",
                "items": {"type": "string", "maxLength": 64},
                "maxItems": 8,
            },
            {
                "type": "array",
                "items": {"type": "string", "maxLength": 32},
                "maxItems": 4,
                "uniqueItems": True,
            },
            SchemaChange.BREAKING,
        ),
        (
            {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            {
                "anyOf": [
                    {"type": "string"},
                    {"type": "integer"},
                    {"type": "boolean"},
                ]
            },
            SchemaChange.NON_BREAKING,
        ),
        (
            {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            {"anyOf": [{"type": "string"}]},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "string", "pattern": "^[a-z]+$"},
            {"type": "string", "pattern": "^[A-Z]+$"},
            SchemaChange.BREAKING,
        ),
        (
            {"type": "boolean", "description": "old"},
            {"type": "boolean", "description": "new"},
            SchemaChange.NON_BREAKING,
        ),
    ],
    ids=[
        "string-bounds-widen",
        "string-minimum-tighten",
        "format-remove",
        "format-add",
        "enum-expand",
        "enum-narrow-to-const",
        "enum-add-to-unrestricted",
        "integer-to-number-and-bounds-widen",
        "number-to-integer",
        "exclusive-to-inclusive-bounds",
        "inclusive-to-exclusive-bounds",
        "multiple-remove",
        "multiple-add",
        "lower-bound-add",
        "upper-bound-add",
        "numeric-bounds-tighten",
        "array-and-items-widen",
        "array-and-items-tighten",
        "union-expand",
        "union-narrow",
        "unknown-constraint-change",
        "primitive-annotations-only",
    ],
)
def test_input_schema_compatibility_matrix(
    previous: dict[str, JsonValue],
    current: dict[str, JsonValue],
    expected: SchemaChange,
) -> None:
    assert classify_schema_change(previous, current, direction=SchemaDirection.INPUT) is expected


def test_object_compatibility_covers_additional_properties_and_property_name_bounds() -> None:
    previous: dict[str, JsonValue] = {
        "type": "object",
        "properties": {"fixed": {"type": "integer"}},
        "required": ["fixed"],
        "additionalProperties": {"type": "integer"},
        "minProperties": 2,
        "maxProperties": 4,
        "propertyNames": {"type": "string", "minLength": 2, "maxLength": 16},
    }
    widened: dict[str, JsonValue] = {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": {"type": "number"},
        "minProperties": 1,
        "maxProperties": 8,
        "propertyNames": {"type": "string", "minLength": 1, "maxLength": 32},
    }
    closed: dict[str, JsonValue] = {**widened, "additionalProperties": False}
    tightened_names: dict[str, JsonValue] = {
        **widened,
        "propertyNames": {"type": "string", "minLength": 3, "maxLength": 8},
    }
    closed_with_declared_property: dict[str, JsonValue] = {
        **widened,
        "properties": {"fixed": {"type": "number"}},
        "additionalProperties": False,
    }

    assert (
        classify_schema_change(previous, widened, direction=SchemaDirection.INPUT)
        is SchemaChange.NON_BREAKING
    )
    for tightened in (
        closed,
        closed_with_declared_property,
        tightened_names,
    ):
        assert (
            classify_schema_change(previous, tightened, direction=SchemaDirection.INPUT)
            is SchemaChange.BREAKING
        )

    unconstrained_names = {key: value for key, value in previous.items() if key != "propertyNames"}
    newly_constrained_names: dict[str, JsonValue] = {
        **unconstrained_names,
        "propertyNames": {"type": "string", "maxLength": 32},
    }
    assert (
        classify_schema_change(
            unconstrained_names,
            newly_constrained_names,
            direction=SchemaDirection.INPUT,
        )
        is SchemaChange.BREAKING
    )


def test_local_definition_references_are_resolved_and_invalid_references_fail_closed() -> None:
    previous: dict[str, JsonValue] = {
        "$defs": {"Value": {"type": "integer", "minimum": 0}},
        "$ref": "#/$defs/Value",
    }
    widened: dict[str, JsonValue] = {
        "$defs": {"Value": {"type": "number", "minimum": -1}},
        "$ref": "#/$defs/Value",
    }
    missing: dict[str, JsonValue] = {"$defs": {}, "$ref": "#/$defs/Missing"}
    recursive: dict[str, JsonValue] = {
        "$defs": {"Value": {"$ref": "#/$defs/Value"}},
        "$ref": "#/$defs/Value",
    }

    assert (
        classify_schema_change(previous, widened, direction=SchemaDirection.INPUT)
        is SchemaChange.NON_BREAKING
    )
    for invalid in (
        missing,
        recursive,
        {"$ref": "#/$defs/Missing"},
        {"$ref": "https://example.test/schema"},
    ):
        assert (
            classify_schema_change(previous, invalid, direction=SchemaDirection.INPUT)
            is SchemaChange.BREAKING
        )


@pytest.mark.parametrize(
    "invalid",
    MALFORMED_SCHEMA_SHAPES,
    ids=[
        "empty-union",
        "non-object-union-member",
        "non-string-type",
        "non-object-items",
        "non-object-properties",
        "non-object-property-schema",
        "non-array-required",
        "non-string-required-entry",
    ],
)
def test_malformed_schema_shapes_fail_closed(invalid: dict[str, JsonValue]) -> None:
    if "anyOf" in invalid:
        baseline: dict[str, JsonValue] = {"anyOf": [{"type": "string"}, {"type": "integer"}]}
    elif invalid.get("type") == "array":
        baseline = {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 8,
        }
    elif invalid.get("type") == "object":
        baseline = object_schema({}, required=[])
    else:
        baseline = {"type": "string"}

    assert (
        classify_schema_change(baseline, invalid, direction=SchemaDirection.INPUT)
        is SchemaChange.BREAKING
    )
