from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from jsonschema import Draft202012Validator
from mcp.server.mcpserver.tools import Tool
from mcp.types import CallToolResult
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    ContractViolation,
    DuplicateToolName,
    IdempotencyRequirement,
    MetadataPolicy,
    SchemaPolicy,
    ToolCatalog,
    ToolDiscoveryMetadata,
    ToolEffect,
    ToolManifest,
    ToolMetadata,
    schema_fingerprint,
)
from tesserix_mcp_runtime.adapters.mcp_authoring import callable_tool

FIXTURES = Path(__file__).parents[1] / "fixtures"


class EchoResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: Annotated[str, Field(max_length=64)]


async def echo(text: Annotated[str, Field(max_length=64)]) -> EchoResult:
    return EchoResult(text=text)


async def missing_return_annotation(value: BoundedText) -> Any:
    return {"text": value}


async def unsafe_identity_input(
    tenant_id: Annotated[str, Field(max_length=64)],
) -> EchoResult:
    return EchoResult(text=tenant_id)


async def unbounded_text(value: str) -> EchoResult:
    return EchoResult(text=value)


async def unbounded_list(values: list[BoundedText]) -> EchoResult:
    return EchoResult(text=values[0] if values else "empty")


async def unbounded_mapping(
    values: dict[Annotated[str, Field(max_length=32)], float],
) -> EchoResult:
    return EchoResult(text=str(len(values)))


BoundedText = Annotated[str, Field(max_length=64)]
BoundedInteger = Annotated[int, Field(ge=0, le=100)]


class MediaKind(StrEnum):
    BOOK = "book"
    VIDEO = "video"


class SearchFilter(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    phrase: BoundedText
    kind: MediaKind | None = None


class SearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    labels: Annotated[list[BoundedText], Field(max_length=4)]
    scores: Annotated[
        dict[Annotated[str, Field(max_length=32)], float],
        Field(max_length=8),
    ]


class RecursiveNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: BoundedText
    children: Annotated[list[RecursiveNode], Field(max_length=4)]


class UnsafeNestedFilter(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: BoundedText


async def discover(
    query: BoundedText,
    tags: Annotated[list[BoundedText], Field(max_length=8)],
    weights: Annotated[
        dict[Annotated[str, Field(max_length=32)], float],
        Field(max_length=8),
    ],
    selector: BoundedInteger | BoundedText,
    criteria: SearchFilter | None = None,
) -> SearchResult:
    del tags, weights, selector, criteria
    return SearchResult(labels=[query], scores={"match": 1.0})


async def walk_recursive(node: RecursiveNode) -> EchoResult:
    return EchoResult(text=node.name)


async def unsafe_nested_identity(criteria: UnsafeNestedFilter) -> EchoResult:
    return EchoResult(text=criteria.role)


def metadata(*, name: str = "examples.echo") -> ToolMetadata:
    return ToolMetadata(
        name=name,
        title="Echo text",
        description="Return bounded text unchanged.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("examples:read",),
    )


def context() -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant="tenant-example",
            subject="subject-example",
            issuer="https://identity.example.invalid",
            scopes=("examples:read",),
        ),
        request_id="request-example",
        run_id="run-example",
    )


def test_typed_callable_uses_the_official_mcp_schema_and_validation_path() -> None:
    definition = callable_tool(echo, metadata=metadata())
    official = Tool.from_function(
        echo,
        name="examples.echo",
        title="Echo text",
        description="Return bounded text unchanged.",
        structured_output=True,
    )
    expected_input = dict(official.parameters)
    expected_input["additionalProperties"] = False

    assert definition.input_schema == expected_input
    assert definition.output_schema == official.output_schema

    returned_input = definition.input_schema
    assert isinstance(returned_input, dict)
    returned_input["title"] = "mutated"
    assert definition.input_schema["title"] == "echoArguments"

    input_model = definition.parse_input({"text": "Grüße 👋"})
    output_model = asyncio.run(definition.handler(input_model, context=context()))
    assert definition.serialize_output(output_model) == {"text": "Grüße 👋"}


def test_callable_boundary_rejects_unknown_arguments_and_unstructured_results() -> None:
    definition = callable_tool(echo, metadata=metadata())

    with pytest.raises(ValueError, match="unknown field"):
        definition.parse_input({"text": "hello", "tenant": "untrusted"})
    with pytest.raises(ValueError, match="invalid structured content"):
        definition.serialize_output(CallToolResult(content=[]))


def test_callable_without_a_structured_return_contract_fails_registration() -> None:
    with pytest.raises(ContractViolation) as captured:
        callable_tool(missing_return_annotation, metadata=metadata())

    assert captured.value.code == "invalid_callable_schema"
    assert captured.value.path == "callable"


def test_discovery_metadata_is_typed_immutable_and_serializable() -> None:
    discovery = ToolDiscoveryMetadata(
        summary="Find catalog entries",
        when_to_use="Use when a caller needs a bounded catalog lookup.",
        capabilities=("cap/catalog-search", "cap/catalog-read"),
        rate_class="interactive",
        lifecycle="stable",
        examples=("Find active payment tools", "Look up a catalog entry by purpose"),
    )
    tool_metadata = ToolMetadata(
        name="catalog.search",
        title="Search the catalog",
        description="Return matching catalog entries without exposing private bodies.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("catalog:read",),
        discovery=discovery,
    )

    assert tool_metadata.to_dict()["discovery"] == {
        "summary": "Find catalog entries",
        "when_to_use": "Use when a caller needs a bounded catalog lookup.",
        "capabilities": ["cap/catalog-search", "cap/catalog-read"],
        "rate_class": "interactive",
        "lifecycle": "stable",
        "examples": ["Find active payment tools", "Look up a catalog entry by purpose"],
    }
    with pytest.raises(FrozenInstanceError):
        discovery.summary = "changed"  # type: ignore[misc]


def test_semantic_capabilities_and_required_scopes_have_cardinality_limits() -> None:
    capabilities = tuple(f"cap/example-{index}" for index in range(32))
    required_scopes = tuple(f"catalog:scope-{index}" for index in range(32))
    discovery = ToolDiscoveryMetadata(
        summary="Find catalog entries",
        when_to_use="Use for a bounded catalog lookup.",
        capabilities=capabilities,
        rate_class="interactive",
        lifecycle="stable",
        examples=(),
    )
    bounded_metadata = ToolMetadata(
        name="catalog.search",
        title="Search catalog",
        description="Return matching catalog entries.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=required_scopes,
        discovery=discovery,
    )

    assert bounded_metadata.discovery is discovery
    assert len(discovery.capabilities) == 32
    assert len(bounded_metadata.required_scopes) == 32

    with pytest.raises(ValueError, match="capabilities must be a bounded immutable tuple"):
        ToolDiscoveryMetadata(
            summary="Find catalog entries",
            when_to_use="Use for a bounded catalog lookup.",
            capabilities=tuple(f"cap/example-{index}" for index in range(33)),
            rate_class="interactive",
            lifecycle="stable",
            examples=(),
        )

    with pytest.raises(ValueError, match="required_scopes must be a bounded immutable tuple"):
        ToolMetadata(
            name="catalog.search",
            title="Search catalog",
            description="Return matching catalog entries.",
            effect=ToolEffect.READ,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.NOT_APPLICABLE,
            required_scopes=tuple(f"catalog:scope-{index}" for index in range(33)),
        )


@pytest.mark.parametrize(
    ("policy", "path"),
    [
        (MetadataPolicy(max_description_bytes=16), "metadata.description"),
        (MetadataPolicy(max_description_tokens=3), "metadata.description"),
        (MetadataPolicy(max_summary_bytes=8), "metadata.discovery.summary"),
        (MetadataPolicy(max_summary_tokens=2), "metadata.discovery.summary"),
        (MetadataPolicy(max_when_to_use_bytes=8), "metadata.discovery.when_to_use"),
        (MetadataPolicy(max_when_to_use_tokens=2), "metadata.discovery.when_to_use"),
        (MetadataPolicy(max_example_bytes=8), "metadata.discovery.examples[0]"),
        (MetadataPolicy(max_example_tokens=2), "metadata.discovery.examples[0]"),
        (MetadataPolicy(max_total_example_bytes=8), "metadata.discovery.examples"),
        (MetadataPolicy(max_total_example_tokens=2), "metadata.discovery.examples"),
    ],
    ids=[
        "description-bytes",
        "description-tokens",
        "summary-bytes",
        "summary-tokens",
        "when-to-use-bytes",
        "when-to-use-tokens",
        "example-bytes",
        "example-tokens",
        "total-example-bytes",
        "total-example-tokens",
    ],
)
def test_callable_registration_enforces_configured_text_budgets(
    policy: MetadataPolicy,
    path: str,
) -> None:
    discovery = ToolDiscoveryMetadata(
        summary="Echo bounded text",
        when_to_use="Use for a deterministic echo example.",
        capabilities=("cap/example-echo",),
        rate_class="interactive",
        lifecycle="stable",
        examples=("Echo a Unicode greeting",),
    )
    bounded_metadata = ToolMetadata(
        name="examples.echo",
        title="Echo text",
        description="Return bounded text unchanged.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("examples:read",),
        discovery=discovery,
    )

    with pytest.raises(ContractViolation) as captured:
        callable_tool(echo, metadata=bounded_metadata, metadata_policy=policy)

    assert captured.value.code == "metadata_limit_exceeded"
    assert captured.value.path == path


def test_callable_registration_enforces_example_count_budget() -> None:
    discovery = ToolDiscoveryMetadata(
        summary="Echo bounded text",
        when_to_use="Use for a deterministic echo example.",
        capabilities=("cap/example-echo",),
        rate_class="interactive",
        lifecycle="stable",
        examples=("Echo a greeting", "Echo a catalog label"),
    )
    bounded_metadata = ToolMetadata(
        name="examples.echo",
        title="Echo text",
        description="Return bounded text unchanged.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("examples:read",),
        discovery=discovery,
    )

    with pytest.raises(ContractViolation) as captured:
        callable_tool(
            echo,
            metadata=bounded_metadata,
            metadata_policy=MetadataPolicy(max_examples=1),
        )

    assert captured.value.code == "metadata_limit_exceeded"
    assert captured.value.path == "metadata.discovery.examples"


def test_optional_union_enum_nested_list_mapping_and_structured_result_match_golden() -> None:
    definition = callable_tool(
        discover,
        metadata=ToolMetadata(
            name="catalog.discover",
            title="Discover catalog entries",
            description="Return a bounded structured discovery result.",
            effect=ToolEffect.READ,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.NOT_APPLICABLE,
            required_scopes=("catalog:read",),
        ),
    )
    catalog = ToolCatalog([definition])
    golden = json.loads((FIXTURES / "typed-callable-schemas.json").read_text(encoding="utf-8"))

    assert len(catalog) == 1
    assert definition.input_schema == golden["input_schema"]
    assert definition.output_schema == golden["output_schema"]

    input_model = definition.parse_input(
        {
            "query": "東京 café",
            "tags": ["vídeo", "本"],
            "weights": {"relevance": 0.8},
            "selector": "book",
            "criteria": {"phrase": "naïve search", "kind": "book"},
        }
    )
    output_model = asyncio.run(definition.handler(input_model, context=context()))
    assert definition.serialize_output(output_model) == {
        "labels": ["東京 café"],
        "scores": {"match": 1.0},
    }


def test_identity_fields_are_rejected_before_callable_registration() -> None:
    with pytest.raises(ContractViolation) as captured:
        callable_tool(unsafe_identity_input, metadata=metadata())

    assert captured.value.code == "forbidden_identity_field"
    assert captured.value.path == "input_schema.properties.tenant_id"

    with pytest.raises(ContractViolation) as nested:
        callable_tool(unsafe_nested_identity, metadata=metadata())

    assert nested.value.code == "forbidden_identity_field"
    assert nested.value.path == "input_schema.$defs.UnsafeNestedFilter.properties.role"


@pytest.mark.parametrize(
    ("function", "code", "path"),
    [
        (unbounded_text, "unbounded_string_schema", "input_schema.properties.value.maxLength"),
        (unbounded_list, "unbounded_array_schema", "input_schema.properties.values.maxItems"),
        (
            unbounded_mapping,
            "unbounded_object_schema",
            "input_schema.properties.values.maxProperties",
        ),
    ],
    ids=["string", "array", "mapping"],
)
def test_unbounded_callable_schemas_fail_registration_with_stable_errors(
    function: Callable[..., object],
    code: str,
    path: str,
) -> None:
    with pytest.raises(ContractViolation) as captured:
        callable_tool(function, metadata=metadata())

    assert captured.value.code == code
    assert captured.value.path == path


def test_callable_schema_byte_budget_fails_before_catalog_construction() -> None:
    with pytest.raises(ContractViolation) as captured:
        callable_tool(
            echo,
            metadata=metadata(),
            schema_policy=SchemaPolicy(max_schema_bytes=64),
        )

    assert captured.value.code == "schema_limit_exceeded"
    assert captured.value.path == "input_schema"


@pytest.mark.parametrize(
    ("function", "policy", "path"),
    [
        (echo, SchemaPolicy(max_schema_nodes=1), "input_schema.properties.text"),
        (discover, SchemaPolicy(max_definitions=1), "input_schema.$defs"),
        (
            discover,
            SchemaPolicy(max_union_variants=1),
            "input_schema.properties.criteria.anyOf",
        ),
    ],
    ids=["nodes", "definitions", "union-variants"],
)
def test_callable_schema_structural_budgets_fail_registration(
    function: Callable[..., object],
    policy: SchemaPolicy,
    path: str,
) -> None:
    with pytest.raises(ContractViolation) as captured:
        callable_tool(function, metadata=metadata(), schema_policy=policy)

    assert captured.value.code == "schema_limit_exceeded"
    assert captured.value.path == path


def test_recursive_callable_schema_fails_with_a_bounded_stable_error() -> None:
    with pytest.raises(ContractViolation) as captured:
        callable_tool(walk_recursive, metadata=metadata())

    assert captured.value.code == "recursive_schema"
    assert captured.value.path == "input_schema.$defs.RecursiveNode.properties.children.items.$ref"


def test_catalog_rejects_case_normalized_collisions_and_names_both_tools() -> None:
    first = callable_tool(echo, metadata=metadata(name="Examples.Echo"))
    second = callable_tool(echo, metadata=metadata(name="examples.echo"))

    with pytest.raises(DuplicateToolName) as captured:
        ToolCatalog([first, second])

    assert captured.value.code == "duplicate_tool_name"
    assert captured.value.first_name == "Examples.Echo"
    assert captured.value.second_name == "examples.echo"
    assert captured.value.normalized_name == "examples.echo"
    assert captured.value.first_path == "tools[0].metadata.name"
    assert captured.value.path == "tools[1].metadata.name"


def test_catalog_exports_immutable_handler_free_manifest_metadata() -> None:
    definition = callable_tool(echo, metadata=metadata())
    catalog = ToolCatalog([definition])

    assert isinstance(catalog.manifests[0], ToolManifest)
    manifest = catalog.manifests[0]
    assert manifest.input_fingerprint == schema_fingerprint(definition.input_schema)
    assert manifest.output_fingerprint == schema_fingerprint(definition.output_schema)
    assert manifest.normalized_name == "examples.echo"

    exported = catalog.export_metadata()
    encoded = json.dumps(exported, ensure_ascii=False, sort_keys=True)
    assert exported[0]["input_schema"] == definition.input_schema
    assert exported[0]["output_schema"] == definition.output_schema
    assert "handler" not in encoded
    assert "function" not in encoded

    returned_schema = manifest.input_schema
    returned_schema["title"] = "mutated"
    assert manifest.input_schema["title"] == "echoArguments"

    returned_output = manifest.output_schema
    returned_output["title"] = "mutated"
    assert manifest.output_schema["title"] == "EchoResult"
    assert exported[0]["fingerprints"] == {
        "input": manifest.input_fingerprint,
        "output": manifest.output_fingerprint,
        "contract": manifest.contract_fingerprint,
    }


def test_schema_fingerprint_rejects_non_finite_json_values() -> None:
    with pytest.raises(ValueError, match="bounded JSON"):
        schema_fingerprint({"value": float("nan")})


@given(
    st.text(
        max_size=64,
    )
)
def test_callable_validation_matches_pydantic_and_the_official_sdk(text: str) -> None:
    definition = callable_tool(echo, metadata=metadata())
    official = Tool.from_function(
        echo,
        name="examples.echo",
        structured_output=True,
    )

    runtime_arguments = definition.parse_input({"text": text})
    official_arguments = official.fn_metadata.validate_arguments({"text": text})
    pydantic_result = EchoResult.model_validate({"text": text})

    assert runtime_arguments == official_arguments == {"text": text}
    assert TypeAdapter(BoundedText).validate_python(text) == text
    assert definition.serialize_output(pydantic_result) == {"text": text}


@given(max_length=st.integers(min_value=1, max_value=256))
@settings(max_examples=25, deadline=None)
def test_callable_schema_generation_matches_the_official_sdk(max_length: int) -> None:
    async def generated(value: str) -> EchoResult:
        return EchoResult(text=value[:64])

    generated.__annotations__ = {
        "value": Annotated[str, Field(max_length=max_length)],
        "return": EchoResult,
    }

    definition = callable_tool(generated, metadata=metadata())
    official = Tool.from_function(
        generated,
        name="examples.echo",
        structured_output=True,
    )
    official_input = dict(official.parameters)
    official_input["additionalProperties"] = False

    assert definition.input_schema == official_input
    assert definition.output_schema == official.output_schema


def test_all_golden_schemas_are_draft_2020_12_conformant() -> None:
    golden = json.loads((FIXTURES / "typed-callable-schemas.json").read_text(encoding="utf-8"))

    for schema in golden.values():
        Draft202012Validator.check_schema(schema)
