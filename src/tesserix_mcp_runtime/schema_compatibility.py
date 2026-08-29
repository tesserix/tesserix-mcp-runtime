"""Deterministic compatibility classification for bounded tool schemas."""

from __future__ import annotations

import math
from collections.abc import Mapping
from enum import StrEnum
from typing import TypeGuard, cast

from tesserix_mcp_runtime.contracts import JsonValue
from tesserix_mcp_runtime.tool_manifest import schema_fingerprint

_ANNOTATION_KEYS = frozenset(
    {"$comment", "$defs", "$id", "$schema", "default", "description", "examples", "title"}
)
_KNOWN_KEYS = frozenset(
    {
        "$ref",
        "additionalProperties",
        "anyOf",
        "const",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "format",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "multipleOf",
        "properties",
        "propertyNames",
        "required",
        "type",
        "uniqueItems",
    }
)
_LOCAL_DEFINITION_PREFIX = "#/$defs/"


class SchemaChange(StrEnum):
    IDENTICAL = "identical"
    NON_BREAKING = "non_breaking"
    BREAKING = "breaking"


class SchemaDirection(StrEnum):
    INPUT = "input"
    OUTPUT = "output"


class _ComparisonState:
    __slots__ = ("remaining",)

    def __init__(self) -> None:
        self.remaining = 10_000

    def consume(self) -> bool:
        self.remaining -= 1
        return self.remaining >= 0


def _is_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    if not isinstance(value, Mapping):
        return False
    mapping = cast(Mapping[object, object], value)
    return all(isinstance(key, str) for key in mapping)


def _is_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _resolve(
    schema: Mapping[str, object],
    root: Mapping[str, object],
    *,
    stack: tuple[str, ...] = (),
) -> Mapping[str, object] | None:
    reference = schema.get("$ref")
    if reference is None:
        return schema
    if (
        not isinstance(reference, str)
        or not reference.startswith(_LOCAL_DEFINITION_PREFIX)
        or set(schema) - _ANNOTATION_KEYS - {"$ref"}
    ):
        return None
    name = reference.removeprefix(_LOCAL_DEFINITION_PREFIX)
    if name in stack:
        return None
    definitions = root.get("$defs")
    if not _is_mapping(definitions):
        return None
    target = definitions.get(name)
    if not _is_mapping(target):
        return None
    return _resolve(target, root, stack=(*stack, name))


def _variant_list(schema: Mapping[str, object]) -> list[Mapping[str, object]] | None:
    variants = schema.get("anyOf")
    if variants is None:
        return [schema]
    if not _is_list(variants) or not variants:
        return None
    result: list[Mapping[str, object]] = []
    for variant in variants:
        if not _is_mapping(variant):
            return None
        result.append(variant)
    return result


def _allowed_values(schema: Mapping[str, object]) -> list[object] | None:
    if "const" in schema:
        return [schema["const"]]
    values = schema.get("enum")
    if values is None:
        return None
    return values if _is_list(values) else []


def _allows_every_value(
    candidate: Mapping[str, object],
    baseline: Mapping[str, object],
) -> bool:
    candidate_values = _allowed_values(candidate)
    if candidate_values is None:
        return True
    baseline_values = _allowed_values(baseline)
    if baseline_values is None:
        return False
    return all(any(value == allowed for allowed in candidate_values) for value in baseline_values)


def _numeric(value: object) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _lower_bound(schema: Mapping[str, object]) -> tuple[int | float, bool] | None:
    inclusive_value = _numeric(schema.get("minimum"))
    exclusive_value = _numeric(schema.get("exclusiveMinimum"))
    candidates: list[tuple[int | float, bool]] = []
    if inclusive_value is not None:
        candidates.append((inclusive_value, True))
    if exclusive_value is not None:
        candidates.append((exclusive_value, False))
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], not item[1]))


def _upper_bound(schema: Mapping[str, object]) -> tuple[int | float, bool] | None:
    inclusive_value = _numeric(schema.get("maximum"))
    exclusive_value = _numeric(schema.get("exclusiveMaximum"))
    candidates: list[tuple[int | float, bool]] = []
    if inclusive_value is not None:
        candidates.append((inclusive_value, True))
    if exclusive_value is not None:
        candidates.append((exclusive_value, False))
    if not candidates:
        return None
    return min(candidates, key=lambda item: (item[0], item[1]))


def _lower_is_wider(
    candidate: tuple[int | float, bool] | None,
    baseline: tuple[int | float, bool] | None,
) -> bool:
    if candidate is None:
        return True
    if baseline is None:
        return False
    if candidate[0] < baseline[0]:
        return True
    if candidate[0] > baseline[0]:
        return False
    return candidate[1] or not baseline[1]


def _upper_is_wider(
    candidate: tuple[int | float, bool] | None,
    baseline: tuple[int | float, bool] | None,
) -> bool:
    if candidate is None:
        return True
    if baseline is None:
        return False
    if candidate[0] > baseline[0]:
        return True
    if candidate[0] < baseline[0]:
        return False
    return candidate[1] or not baseline[1]


def _minimum_is_wider(
    candidate: Mapping[str, object],
    baseline: Mapping[str, object],
    key: str,
) -> bool:
    candidate_value = _numeric(candidate.get(key))
    baseline_value = _numeric(baseline.get(key))
    return candidate_value is None or (
        baseline_value is not None and candidate_value <= baseline_value
    )


def _maximum_is_wider(
    candidate: Mapping[str, object],
    baseline: Mapping[str, object],
    key: str,
) -> bool:
    candidate_value = _numeric(candidate.get(key))
    baseline_value = _numeric(baseline.get(key))
    return candidate_value is None or (
        baseline_value is not None and candidate_value >= baseline_value
    )


def _same_unknown_constraints(
    candidate: Mapping[str, object],
    baseline: Mapping[str, object],
) -> bool:
    keys = (set(candidate) | set(baseline)) - _ANNOTATION_KEYS - _KNOWN_KEYS
    return all(candidate.get(key) == baseline.get(key) for key in keys)


def _property_schema(
    schema: Mapping[str, object],
    name: str,
) -> Mapping[str, object] | None:
    properties = schema.get("properties")
    if _is_mapping(properties):
        value = properties.get(name)
        if _is_mapping(value):
            return value
    additional = schema.get("additionalProperties")
    return additional if _is_mapping(additional) else None


def _required_names(value: object) -> set[str] | None:
    if not _is_list(value) or not all(isinstance(name, str) for name in value):
        return None
    names = {name for name in value if isinstance(name, str)}
    return names if len(names) == len(value) else None


def _object_is_superset(
    candidate: Mapping[str, object],
    baseline: Mapping[str, object],
    *,
    candidate_root: Mapping[str, object],
    baseline_root: Mapping[str, object],
    state: _ComparisonState,
) -> bool:
    candidate_required = _required_names(candidate.get("required", []))
    baseline_required = _required_names(baseline.get("required", []))
    if candidate_required is None or baseline_required is None:
        return False
    if not candidate_required <= baseline_required:
        return False

    candidate_properties = candidate.get("properties", {})
    baseline_properties = baseline.get("properties", {})
    if (
        not _is_mapping(candidate_properties)
        or not all(_is_mapping(value) for value in candidate_properties.values())
        or not _is_mapping(baseline_properties)
        or not all(_is_mapping(value) for value in baseline_properties.values())
    ):
        return False
    for name, baseline_property in baseline_properties.items():
        if not _is_mapping(baseline_property):
            return False
        candidate_property = _property_schema(candidate, name)
        if candidate_property is None or not _is_superset(
            candidate_property,
            baseline_property,
            candidate_root=candidate_root,
            baseline_root=baseline_root,
            state=state,
        ):
            return False

    baseline_additional = baseline.get("additionalProperties")
    candidate_additional = candidate.get("additionalProperties")
    if baseline_additional is not False:
        if candidate_additional is False:
            return False
        if _is_mapping(baseline_additional):
            if _is_mapping(candidate_additional):
                if not _is_superset(
                    candidate_additional,
                    baseline_additional,
                    candidate_root=candidate_root,
                    baseline_root=baseline_root,
                    state=state,
                ):
                    return False
            elif candidate_additional is not None:
                return False
        elif candidate_additional is not None and _is_mapping(candidate_additional):
            return False

    return (
        _minimum_is_wider(candidate, baseline, "minProperties")
        and _maximum_is_wider(candidate, baseline, "maxProperties")
        and _property_names_are_wider(candidate, baseline)
    )


def _property_names_are_wider(
    candidate: Mapping[str, object],
    baseline: Mapping[str, object],
) -> bool:
    candidate_names = candidate.get("propertyNames")
    baseline_names = baseline.get("propertyNames")
    if candidate_names is None:
        return True
    if not _is_mapping(candidate_names) or not _is_mapping(baseline_names):
        return False
    return _minimum_is_wider(candidate_names, baseline_names, "minLength") and _maximum_is_wider(
        candidate_names,
        baseline_names,
        "maxLength",
    )


def _is_superset(
    candidate: Mapping[str, object],
    baseline: Mapping[str, object],
    *,
    candidate_root: Mapping[str, object],
    baseline_root: Mapping[str, object],
    state: _ComparisonState,
) -> bool:
    if not state.consume():
        return False
    resolved_candidate = _resolve(candidate, candidate_root)
    resolved_baseline = _resolve(baseline, baseline_root)
    if resolved_candidate is None or resolved_baseline is None:
        return False

    candidate_variants = _variant_list(resolved_candidate)
    baseline_variants = _variant_list(resolved_baseline)
    if candidate_variants is None or baseline_variants is None:
        return False
    if "anyOf" in resolved_candidate or "anyOf" in resolved_baseline:
        return all(
            any(
                _is_superset(
                    candidate_variant,
                    baseline_variant,
                    candidate_root=candidate_root,
                    baseline_root=baseline_root,
                    state=state,
                )
                for candidate_variant in candidate_variants
            )
            for baseline_variant in baseline_variants
        )

    candidate_type = resolved_candidate.get("type")
    baseline_type = resolved_baseline.get("type")
    if candidate_type != baseline_type and not (
        candidate_type == "number" and baseline_type == "integer"
    ):
        return False
    if not isinstance(candidate_type, str) or not _allows_every_value(
        resolved_candidate,
        resolved_baseline,
    ):
        return False
    if not _same_unknown_constraints(resolved_candidate, resolved_baseline):
        return False

    if candidate_type == "string":
        candidate_format = resolved_candidate.get("format")
        baseline_format = resolved_baseline.get("format")
        return (
            _minimum_is_wider(resolved_candidate, resolved_baseline, "minLength")
            and _maximum_is_wider(resolved_candidate, resolved_baseline, "maxLength")
            and (candidate_format is None or candidate_format == baseline_format)
        )
    if candidate_type in {"integer", "number"}:
        candidate_multiple = _numeric(resolved_candidate.get("multipleOf"))
        baseline_multiple = _numeric(resolved_baseline.get("multipleOf"))
        multiple_is_wider = candidate_multiple is None or (
            baseline_multiple is not None and candidate_multiple == baseline_multiple
        )
        return (
            _lower_is_wider(_lower_bound(resolved_candidate), _lower_bound(resolved_baseline))
            and _upper_is_wider(_upper_bound(resolved_candidate), _upper_bound(resolved_baseline))
            and multiple_is_wider
        )
    if candidate_type == "array":
        candidate_items = resolved_candidate.get("items")
        baseline_items = resolved_baseline.get("items")
        return (
            _is_mapping(candidate_items)
            and _is_mapping(baseline_items)
            and _minimum_is_wider(resolved_candidate, resolved_baseline, "minItems")
            and _maximum_is_wider(resolved_candidate, resolved_baseline, "maxItems")
            and not (
                resolved_candidate.get("uniqueItems") is True
                and resolved_baseline.get("uniqueItems") is not True
            )
            and _is_superset(
                candidate_items,
                baseline_items,
                candidate_root=candidate_root,
                baseline_root=baseline_root,
                state=state,
            )
        )
    if candidate_type == "object":
        return _object_is_superset(
            resolved_candidate,
            resolved_baseline,
            candidate_root=candidate_root,
            baseline_root=baseline_root,
            state=state,
        )
    return True


def classify_schema_change(
    previous: Mapping[str, JsonValue],
    current: Mapping[str, JsonValue],
    *,
    direction: SchemaDirection,
) -> SchemaChange:
    """Classify whether current remains compatible with the previous contract."""

    if schema_fingerprint(previous) == schema_fingerprint(current):
        return SchemaChange.IDENTICAL

    previous_root: Mapping[str, object] = previous
    current_root: Mapping[str, object] = current
    state = _ComparisonState()
    compatible = (
        _is_superset(
            current_root,
            previous_root,
            candidate_root=current_root,
            baseline_root=previous_root,
            state=state,
        )
        if direction is SchemaDirection.INPUT
        else _is_superset(
            previous_root,
            current_root,
            candidate_root=previous_root,
            baseline_root=current_root,
            state=state,
        )
    )
    return SchemaChange.NON_BREAKING if compatible else SchemaChange.BREAKING


__all__ = ["SchemaChange", "SchemaDirection", "classify_schema_change"]
