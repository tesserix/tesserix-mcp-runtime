# Author typed MCP tools

Define each public tool once as a typed Python callable. The official MCP SDK
derives its input and structured-output schemas; the runtime closes, bounds,
validates, fingerprints, and snapshots those schemas for MCP, Registry, and
compatibility use. Do not maintain a second handwritten schema.

## Define and register one tool

```python
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    IdempotencyRequirement,
    ToolCatalog,
    ToolDiscoveryMetadata,
    ToolEffect,
    ToolMetadata,
)
from tesserix_mcp_runtime.adapters.mcp_authoring import callable_tool

BoundedText = Annotated[str, Field(max_length=128)]


class SearchHit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    identifier: Annotated[str, Field(max_length=64)]
    title: BoundedText


class SearchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hits: Annotated[list[SearchHit], Field(max_length=20)]


async def search_catalog(
    query: BoundedText,
    limit: Annotated[int, Field(ge=1, le=20)] = 10,
) -> SearchResult:
    # Product behavior and backing clients remain owned by the server.
    return SearchResult(hits=[])


definition = callable_tool(
    search_catalog,
    metadata=ToolMetadata(
        name="catalog.search",
        title="Search the catalog",
        description="Return bounded catalog matches for one search query.",
        effect=ToolEffect.READ,
        approval=ApprovalRequirement.NOT_REQUIRED,
        idempotency=IdempotencyRequirement.NOT_APPLICABLE,
        required_scopes=("catalog:read",),
        discovery=ToolDiscoveryMetadata(
            summary="Find catalog entries by intent and text.",
            when_to_use="Use when a caller needs a bounded catalog lookup.",
            capabilities=("cap/catalog-search", "cap/catalog-read"),
            rate_class="interactive",
            lifecycle="stable",
            examples=("Find active payment tools",),
        ),
    ),
)
catalog = ToolCatalog([definition])
```

`definition.input_schema` and `definition.output_schema` are defensive copies.
`ToolCatalog` rejects case-insensitive name collisions before readiness. It
also exposes immutable `manifests` and JSON-safe `export_metadata()` output;
neither form retains or serializes the Python handler.

## Schema rules

The callable must have resolvable parameter annotations and one structured
return annotation. Use frozen Pydantic v2 models with `extra="forbid"` at
model boundaries. The supported public subset includes bounded nested objects,
lists, mappings, enums, optional values, unions, local `$defs`/`$ref`, and
primitive values.

Every variable-size value needs an explicit bound visible in JSON Schema:

- strings: `Annotated[str, Field(max_length=...)]`;
- lists: `Annotated[list[T], Field(max_length=...)]`;
- mappings: bounded key strings plus `Field(max_length=...)` on the mapping;
- models: closed objects; unknown root arguments are rejected;
- recursive models: not supported for public tool contracts.

Registration defaults are deliberately finite:

| Limit | Default |
|---|---:|
| Schema document | 65,536 UTF-8 bytes |
| Traversal depth | 16 |
| Properties or definitions | 128 |
| Schema nodes | 4,096 |
| Union variants | 16 |
| String length | 65,536 |
| Array items | 1,024 |

Pass a stricter `SchemaPolicy` to `callable_tool` when a server needs smaller
limits. Loosening the shared defaults requires an architecture review because
registration happens before the server accepts traffic.

## Semantic metadata is routing data, not authority

Discovery metadata lets a Registry index, filter, and rank tools without
loading handler code. It does not grant a scope, approve a side effect, or
become a trusted instruction. The application authorizer still evaluates the
trusted `CallContext` immediately before every invocation, and Gateway or
Registry selection never replaces that check.

Capability and required-scope tuples contain at most 32 values. Default text
budgets are:

| Field | UTF-8 bytes | Portable tokens |
|---|---:|---:|
| Description | 4,096 | 512 |
| Summary | 512 | 128 |
| When-to-use text | 2,048 | 256 |
| Each example | 1,024 | 128 |
| All examples | 4,096 | 512 |

At most eight examples pass the default `MetadataPolicy`. The portable token
counter is deterministic and model-independent; it is a storage and abuse
budget, not a claim about a model vendor's tokenizer.

Never declare identity, tenant, role, scope, credential, secret, user, or token
fields as callable input. Registration normalizes field spelling and rejects
those concepts at every nested object. Identity comes from the authenticated
transport's `CallContext`, not model-controlled arguments. Only callables
explicitly passed to `callable_tool` are exposed; imports are never scanned.

## Registry snapshots and compatibility

`catalog.export_metadata()` returns, for each tool:

- typed public metadata and normalized name;
- input and output schemas;
- SHA-256 input, output, and combined contract fingerprints.

Canonical UTF-8 JSON makes fingerprints independent of mapping order and
process hash seed. Persist the exact immutable Registry version alongside the
fingerprints; do not identify a deployed contract by mutable tags alone.

Use `classify_schema_change(previous, current, direction=...)` before replacing
an existing contract:

| Direction | Non-breaking condition |
|---|---|
| Input | The current schema accepts every value accepted previously |
| Output | Every value emitted by the current schema was allowed previously |

The result is `identical`, `non_breaking`, or `breaking`. Unknown constraints,
malformed references, recursive comparisons, and unsupported shapes fail
closed as breaking. This classifier is a publication guard; it does not
activate a Gateway route or authorize a caller.

## Registration failures

Invalid callables fail during construction, before catalog or listener startup.
`ContractViolation` carries a stable code and field path, including
`invalid_callable_schema`, `forbidden_identity_field`, `recursive_schema`,
`schema_limit_exceeded`, `metadata_limit_exceeded`, and the relevant unbounded
schema code. `DuplicateToolName` names both colliding definitions. At runtime,
unknown arguments and invalid structured results are normalized before the
application maps them to its payload-safe error contract.

The architecture and rollback decision is recorded in
[ADR-0007](adr/0007-typed-callable-authority-and-manifests.md).
