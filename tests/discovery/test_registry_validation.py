from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import cast

import pytest

from tesserix_mcp_runtime import (
    ErrorCode,
    InMemoryRegistryCache,
    RegistryADKServer,
    RegistryArtifact,
    RegistryArtifactCacheKey,
    RegistryArtifactRaceError,
    RegistryCachePolicy,
    RegistryCandidateDecision,
    RegistryCandidateExplanation,
    RegistryCandidateReason,
    RegistryContractError,
    RegistryResolution,
    RegistryResolutionPolicy,
    RegistryResolutionSource,
    RegistrySearchCacheKey,
    RegistrySearchQuery,
    RegistrySearchStub,
    RegistryToolPin,
    RegistryToolRequirement,
    RegistryUnavailableError,
    registry_artifact_digest,
)


def valid_requirement() -> RegistryToolRequirement:
    return RegistryToolRequirement(
        name="orders_get",
        expected_input_fingerprint="a" * 64,
        expected_output_fingerprint="b" * 64,
    )


def valid_policy() -> RegistryResolutionPolicy:
    return RegistryResolutionPolicy(
        server_name="orders",
        gateway_origin="https://gateway.example.com/",
        supported_protocol_versions=("2025-11-25",),
        required_capabilities=("cap/orders-read",),
        tool_allow=("orders_get",),
        tool_requirements=(valid_requirement(),),
    )


def valid_stub() -> RegistrySearchStub:
    return RegistrySearchStub(
        kind="MCPServer",
        name="orders",
        namespace="tenant-orders",
        tag="1.2.3",
        arn="arn:agentic:registry:tenant-orders:mcpservers/tenant-orders/orders",
        digest=f"sha256:{'a' * 64}",
        ref="mcpservers/tenant-orders/orders@1.2.3",
        fetch_path="/v0/mcpservers/orders/1.2.3?namespace=tenant-orders",
    )


def valid_artifact() -> RegistryArtifact:
    labels = {"domain": "orders"}
    spec: dict[str, object] = {"version": "1.2.3"}
    digest = registry_artifact_digest(
        kind="MCPServer",
        name="orders",
        namespace="tenant-orders",
        tag="1.2.3",
        labels=labels,
        spec=spec,
    )
    return RegistryArtifact(
        api_version="registry.agentic.dev/v1alpha1",
        kind="MCPServer",
        name="orders",
        namespace="tenant-orders",
        tag="1.2.3",
        arn="arn:agentic:registry:tenant-orders:mcpservers/tenant-orders/orders",
        digest=digest,
        ref="mcpservers/tenant-orders/orders@1.2.3",
        labels=labels,
        spec=spec,
    )


def valid_server() -> RegistryADKServer:
    return RegistryADKServer(
        name="orders",
        endpoint="https://gateway.example.com/gateway/orders/mcp",
        allow=("orders_get",),
        deny=(),
        prefix="orders",
        max_tools=8,
        max_schema_bytes=32 * 1024,
        artifact_ref="mcpservers/tenant-orders/orders@1.2.3",
        artifact_digest=f"sha256:{'a' * 64}",
        tool_pins=(
            RegistryToolPin(
                name="orders_get",
                input_fingerprint="a" * 64,
                output_fingerprint="b" * 64,
            ),
        ),
    )


def test_query_and_tool_requirement_validate_every_boundary() -> None:
    with pytest.raises(ValueError, match="intent"):
        RegistrySearchQuery(intent=" ")
    with pytest.raises(ValueError, match="kinds"):
        RegistrySearchQuery(intent="orders", kinds=())
    with pytest.raises(ValueError, match="kinds"):
        RegistrySearchQuery(intent="orders", kinds=("MCPServer", "MCPServer"))
    with pytest.raises(ValueError, match="kinds"):
        RegistrySearchQuery(
            intent="orders",
            kinds=cast(tuple[str, ...], ["MCPServer"]),
        )
    with pytest.raises(ValueError, match="namespace"):
        RegistrySearchQuery(intent="orders", namespace="tenant\nother")
    with pytest.raises(ValueError, match="limit"):
        RegistrySearchQuery(intent="orders", limit=False)

    with pytest.raises(ValueError, match="tool requirement name"):
        RegistryToolRequirement(name="", expected_input_fingerprint="a" * 64)
    with pytest.raises(ValueError, match="fingerprints"):
        RegistryToolRequirement(name="orders_get", expected_input_fingerprint="A" * 64)
    with pytest.raises(ValueError, match="pin a fingerprint or schema"):
        RegistryToolRequirement(name="orders_get")
    with pytest.raises(ValueError, match="JSON object"):
        RegistryToolRequirement(
            name="orders_get",
            compatible_input_schema=cast(Mapping[str, object], ["not-an-object"]),
        )


def test_resolution_policy_validates_default_deny_configuration() -> None:
    assert valid_policy().gateway_origin == "https://gateway.example.com"

    with pytest.raises(ValueError, match="server_name"):
        replace(valid_policy(), server_name="orders!")
    with pytest.raises(ValueError, match="supported_protocol_versions"):
        replace(valid_policy(), supported_protocol_versions=())
    with pytest.raises(ValueError, match="supported_protocol_versions"):
        replace(
            valid_policy(),
            supported_protocol_versions=("2025-11-25", "2025-11-25"),
        )
    with pytest.raises(ValueError, match="controlled capability"):
        replace(valid_policy(), required_capabilities=("orders-read",))
    with pytest.raises(ValueError, match="allowed_lifecycles"):
        replace(valid_policy(), allowed_lifecycles=())
    with pytest.raises(ValueError, match="cannot contain"):
        replace(valid_policy(), tool_deny=("*",))
    with pytest.raises(ValueError, match="tool_prefix"):
        replace(valid_policy(), tool_prefix="orders.")
    with pytest.raises(ValueError, match="immutable typed tuple"):
        replace(
            valid_policy(),
            tool_requirements=cast(
                tuple[RegistryToolRequirement, ...],
                [valid_requirement()],
            ),
        )
    with pytest.raises(ValueError, match="duplicate names"):
        replace(
            valid_policy(),
            tool_requirements=(valid_requirement(), valid_requirement()),
        )


@pytest.mark.parametrize(
    "fetch_path",
    ["", "//registry.example.com/v0/mcpservers/orders", "/v0/orders#fragment", "\\v0\\x"],
    ids=["empty", "network-path", "fragment", "backslash"],
)
def test_search_stub_rejects_unsafe_fetch_paths(fetch_path: str) -> None:
    with pytest.raises(ValueError, match="fetch_path"):
        replace(valid_stub(), fetch_path=fetch_path)


def test_stub_and_artifact_reject_unbounded_or_non_json_values() -> None:
    stub = valid_stub()
    with pytest.raises(ValueError, match="supported Registry kind"):
        replace(stub, kind="Secret")
    with pytest.raises(ValueError, match="digest"):
        replace(stub, digest="sha256:not-a-digest")
    with pytest.raises(ValueError, match="description"):
        replace(stub, description="unsafe\ntext")
    with pytest.raises(ValueError, match="bounded JSON"):
        replace(stub, attributes={"items": list(range(101))})
    with pytest.raises(ValueError, match="bounded JSON"):
        replace(stub, attributes={f"field-{index}": index for index in range(51)})
    with pytest.raises(ValueError, match="bounded JSON"):
        replace(stub, attributes={"value": float("nan")})
    with pytest.raises(ValueError, match="bounded JSON"):
        replace(stub, attributes={"value": b"not-json"})
    with pytest.raises(ValueError, match="labels value"):
        replace(
            stub,
            labels=cast(Mapping[str, str], {"domain": 1}),
        )

    artifact = valid_artifact()
    with pytest.raises(ValueError, match="api_version"):
        replace(artifact, api_version="registry.agentic.dev/v2")
    with pytest.raises(ValueError, match="supported Registry kind"):
        replace(artifact, kind="Secret")
    with pytest.raises(ValueError, match="digest"):
        replace(artifact, digest="bad")
    with pytest.raises(ValueError, match="JSON object"):
        replace(artifact, spec=cast(Mapping[str, object], ["not-an-object"]))
    with pytest.raises(ValueError, match="512 KiB"):
        replace(
            artifact,
            spec={f"field-{index}": "x" * 1000 for index in range(600)},
        )
    with pytest.raises(ValueError, match="string mapping"):
        replace(
            artifact,
            labels={f"label-{index}": "value" for index in range(257)},
        )


def test_registry_digest_rejects_non_json_and_covers_go_float_forms() -> None:
    digest = registry_artifact_digest(
        kind="MCPServer",
        name="orders",
        namespace="tenant-orders",
        tag="1.2.3",
        labels={},
        spec={
            "negativeZero": -0.0,
            "fixedSmall": 1e-6,
            "scientificSmall": 1e-7,
            "scientificLarge": 1e21,
        },
    )
    assert digest.startswith("sha256:")
    with pytest.raises(ValueError, match="finite JSON"):
        registry_artifact_digest(
            kind="MCPServer",
            name="orders",
            namespace="tenant-orders",
            tag="1.2.3",
            labels={},
            spec={"invalid": float("inf")},
        )
    with pytest.raises(ValueError, match="finite JSON"):
        registry_artifact_digest(
            kind="MCPServer",
            name="orders",
            namespace="tenant-orders",
            tag="1.2.3",
            labels={},
            spec={"invalid": b"bytes"},
        )


def test_errors_cache_keys_and_cache_policy_reject_unsafe_values() -> None:
    race = RegistryArtifactRaceError(request_id="request-1", ref="orders@1.2.3")
    assert "orders@1.2.3" in repr(race)
    with pytest.raises(ValueError, match="request_id"):
        RegistryUnavailableError(request_id="")
    with pytest.raises(ValueError, match="failure code"):
        RegistryContractError(request_id="request-1", code=ErrorCode.FORBIDDEN)

    valid_search_key = RegistrySearchCacheKey(
        origin="https://registry.example.com",
        identity_scope_hash="a" * 64,
        contract_version="registry-v0-search-stub-v1",
        query_digest="b" * 64,
    )
    assert valid_search_key.origin == "https://registry.example.com"
    with pytest.raises(ValueError, match="HTTPS origin"):
        replace(valid_search_key, origin="http://registry.example.com")
    with pytest.raises(ValueError, match="cache hashes"):
        replace(valid_search_key, identity_scope_hash="short")
    with pytest.raises(ValueError, match="query contract"):
        replace(valid_search_key, contract_version="future")

    valid_artifact_key = RegistryArtifactCacheKey(
        origin="https://registry.example.com",
        identity_scope_hash="a" * 64,
        contract_version="registry-v0-search-stub-v1",
        artifact_digest=f"sha256:{'b' * 64}",
    )
    with pytest.raises(ValueError, match="identity_scope_hash"):
        replace(valid_artifact_key, identity_scope_hash="short")
    with pytest.raises(ValueError, match="query contract"):
        replace(valid_artifact_key, contract_version="future")
    with pytest.raises(ValueError, match="Registry SHA-256"):
        replace(valid_artifact_key, artifact_digest="bad")

    for policy in (
        RegistryCachePolicy(search_ttl_seconds=30),
        RegistryCachePolicy(artifact_ttl_seconds=60),
        RegistryCachePolicy(offline_max_stale_seconds=3600),
    ):
        assert isinstance(policy, RegistryCachePolicy)
    invalid_policies: tuple[Callable[[], RegistryCachePolicy], ...] = (
        lambda: RegistryCachePolicy(search_ttl_seconds=0),
        lambda: RegistryCachePolicy(artifact_ttl_seconds=61),
        lambda: RegistryCachePolicy(offline_max_stale_seconds=3601),
        lambda: RegistryCachePolicy(search_ttl_seconds=float("nan")),
        lambda: RegistryCachePolicy(artifact_ttl_seconds=False),
    )
    for build in invalid_policies:
        with pytest.raises(ValueError, match="safe bound"):
            build()


def test_in_memory_cache_rejects_invalid_entries_and_times() -> None:
    with pytest.raises(ValueError, match="max_search_entries"):
        InMemoryRegistryCache(max_search_entries=0)
    with pytest.raises(ValueError, match="max_artifact_entries"):
        InMemoryRegistryCache(max_artifact_entries=False)

    cache = InMemoryRegistryCache()
    search_key = RegistrySearchCacheKey(
        origin="https://registry.example.com",
        identity_scope_hash="a" * 64,
        contract_version="registry-v0-search-stub-v1",
        query_digest="b" * 64,
    )
    artifact_key = RegistryArtifactCacheKey(
        origin="https://registry.example.com",
        identity_scope_hash="a" * 64,
        contract_version="registry-v0-search-stub-v1",
        artifact_digest=f"sha256:{'b' * 64}",
    )

    async def exercise() -> None:
        with pytest.raises(ValueError, match="finite monotonic"):
            await cache.get_search(search_key, now=-1)
        with pytest.raises(ValueError, match="safe projection"):
            await cache.put_search(
                search_key,
                cast(tuple[RegistrySearchStub, ...], [valid_stub()]),
                expires_at=1,
            )
        with pytest.raises(ValueError, match="safe projection"):
            await cache.put_search(search_key, (valid_stub(),) * 21, expires_at=1)
        with pytest.raises(ValueError, match="explicit"):
            await cache.get_artifact(
                artifact_key,
                now=0,
                allow_stale=cast(bool, 1),
            )
        with pytest.raises(ValueError, match="ordered expiry"):
            await cache.put_artifact(
                artifact_key,
                valid_artifact(),
                fresh_until=2,
                stale_until=1,
            )
        with pytest.raises(ValueError, match="ordered expiry"):
            await cache.put_artifact(
                artifact_key,
                cast(RegistryArtifact, object()),
                fresh_until=1,
                stale_until=2,
            )

    asyncio.run(exercise())


def test_explanations_server_and_resolution_validate_typed_invariants() -> None:
    selected = RegistryCandidateExplanation(
        ref="orders@1.2.3",
        decision=RegistryCandidateDecision.SELECTED,
    )
    assert selected.reasons == ()
    with pytest.raises(ValueError, match="decision"):
        replace(selected, decision=cast(RegistryCandidateDecision, "selected"))
    with pytest.raises(ValueError, match="bounded typed tuple"):
        replace(
            selected,
            reasons=(RegistryCandidateReason.KIND, RegistryCandidateReason.KIND),
        )
    with pytest.raises(ValueError, match="cannot carry"):
        replace(selected, reasons=(RegistryCandidateReason.KIND,))
    with pytest.raises(ValueError, match="must carry"):
        RegistryCandidateExplanation(
            ref="orders@1.2.3",
            decision=RegistryCandidateDecision.REJECTED,
        )

    pin = RegistryToolPin(
        name="orders_get",
        input_fingerprint="a" * 64,
        output_fingerprint="b" * 64,
    )
    with pytest.raises(ValueError, match="tool pin name"):
        replace(pin, name="")
    with pytest.raises(ValueError, match="fingerprints"):
        replace(pin, output_fingerprint="bad")

    server = valid_server()
    with pytest.raises(ValueError, match="name"):
        replace(server, name="orders!")
    with pytest.raises(ValueError, match="both allow and deny"):
        replace(server, deny=("orders_get",))
    with pytest.raises(ValueError, match="prefix"):
        replace(server, prefix="orders.")
    with pytest.raises(ValueError, match="immutable typed tuple"):
        replace(server, tool_pins=cast(tuple[RegistryToolPin, ...], [pin]))

    resolution = RegistryResolution(
        source=RegistryResolutionSource.NETWORK,
        server=server,
        explanations=(selected,),
    )
    with pytest.raises(ValueError, match="source"):
        replace(resolution, source=cast(RegistryResolutionSource, "network"))
    with pytest.raises(ValueError, match="ADK projection"):
        replace(resolution, server=cast(RegistryADKServer, object()))
    with pytest.raises(ValueError, match="bounded immutable tuple"):
        replace(
            resolution,
            explanations=cast(tuple[RegistryCandidateExplanation, ...], [selected]),
        )
