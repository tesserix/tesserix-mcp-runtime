from __future__ import annotations

import asyncio
from collections.abc import MutableMapping
from dataclasses import FrozenInstanceError
from typing import cast

import pytest

from tesserix_mcp_runtime import (
    AuthenticatedIdentity,
    CallContext,
    InMemoryRegistryCache,
    JsonValue,
    RegistryADKServer,
    RegistryArtifact,
    RegistryArtifactCacheKey,
    RegistryArtifactRaceError,
    RegistryCachePolicy,
    RegistryCacheUnavailableError,
    RegistryCandidateDecision,
    RegistryCandidateReason,
    RegistryDigestMismatchError,
    RegistryDiscovery,
    RegistryResolution,
    RegistryResolutionPolicy,
    RegistryResolutionSource,
    RegistryResolver,
    RegistrySearchCacheKey,
    RegistrySearchQuery,
    RegistrySearchStub,
    RegistryToolPin,
    RegistryToolRequirement,
    RegistryUnavailableError,
    registry_artifact_digest,
    schema_fingerprint,
)


def call_context(
    *,
    tenant: str = "tenant-orders",
    subject: str = "agent-orders",
    scopes: tuple[str, ...] = ("orders:read",),
) -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant=tenant,
            subject=subject,
            issuer="https://identity.example.com",
            scopes=scopes,
        ),
        request_id="request-registry",
        run_id="run-registry",
    )


def order_input_schema(*, max_length: int = 64) -> dict[str, JsonValue]:
    return {
        "type": "object",
        "properties": {"order_id": {"type": "string", "maxLength": max_length}},
        "required": ["order_id"],
        "additionalProperties": False,
    }


def exact_artifact(
    *,
    digest: str | None = None,
    lifecycle: str = "active",
    protocol_versions: tuple[str, ...] = ("2025-11-25",),
    required_scopes: tuple[str, ...] = ("orders:read",),
    gateway_path: str = "/gateway/orders/mcp",
    input_schema: dict[str, JsonValue] | None = None,
    input_fingerprint: str | None = None,
    input_schema_fingerprint: str | None = None,
    include_input_schema_fingerprint: bool = True,
    output_fingerprint: str = "b" * 64,
    tool_status: str = "active",
    tool_scopes: tuple[str, ...] = ("orders:read",),
    tool_capabilities: tuple[str, ...] = ("cap/orders-read",),
) -> RegistryArtifact:
    input_schema = input_schema or order_input_schema()
    labels = {
        "registry.agentic.dev/tenant": "tenant-orders",
        "registry.agentic.dev/visibility": "internal",
    }
    tool: dict[str, JsonValue] = {
        "name": "orders_get",
        "status": tool_status,
        "capabilities": list(tool_capabilities),
        "requiredScopes": list(tool_scopes),
        "inputSchema": input_schema,
        "inputFingerprint": input_fingerprint or schema_fingerprint(input_schema),
        "outputFingerprint": output_fingerprint,
    }
    if include_input_schema_fingerprint:
        tool["inputSchemaFingerprint"] = input_schema_fingerprint or schema_fingerprint(
            input_schema
        )
    spec: dict[str, JsonValue] = {
        "version": "1.2.3",
        "x-tesserix": {
            "lifecycle": lifecycle,
            "protocolVersions": list(protocol_versions),
            "requiredScopes": list(required_scopes),
            "routePolicy": {
                "directAccess": False,
                "gatewayPath": gateway_path,
            },
            "semantic": {"capabilities": ["cap/orders-read"]},
            "tools": [tool],
        },
    }
    computed = registry_artifact_digest(
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
        digest=digest or computed,
        ref="mcpservers/tenant-orders/orders@1.2.3",
        labels=labels,
        spec=spec,
    )


def search_stub(
    *,
    artifact: RegistryArtifact | None = None,
    digest: str | None = None,
) -> RegistrySearchStub:
    artifact = artifact or exact_artifact()
    return RegistrySearchStub(
        kind=artifact.kind,
        name=artifact.name,
        namespace=artifact.namespace,
        tag=artifact.tag,
        arn=artifact.arn,
        digest=digest or artifact.digest,
        ref=artifact.ref,
        title="Orders MCP",
        description="Locate known orders.",
        visibility="internal",
        labels={"domain": "orders"},
        annotations={"discovery.agentic.dev/capabilities": "cap/orders-read"},
        attributes={},
        fetch_path="/v0/mcpservers/orders/1.2.3?namespace=tenant-orders",
    )


def matching_policy(
    *,
    expected_input_fingerprint: str | None = None,
    pin_input: bool = True,
    compatible_input_schema: dict[str, JsonValue] | None = None,
    tool_allow: tuple[str, ...] = ("orders_get",),
) -> RegistryResolutionPolicy:
    return RegistryResolutionPolicy(
        server_name="orders",
        gateway_origin="https://gateway.example.com",
        supported_protocol_versions=("2025-11-25",),
        required_capabilities=("cap/orders-read",),
        tool_allow=tool_allow,
        tool_requirements=(
            RegistryToolRequirement(
                name="orders_get",
                expected_input_fingerprint=(
                    (expected_input_fingerprint or schema_fingerprint(order_input_schema()))
                    if pin_input
                    else None
                ),
                expected_output_fingerprint="b" * 64,
                compatible_input_schema=compatible_input_schema,
            ),
        ),
    )


def test_registry_search_query_is_immutable_and_strictly_bounded() -> None:
    query = RegistrySearchQuery(
        intent="find a known order",
        kinds=("MCPServer",),
        namespace="tenant-orders",
        limit=20,
    )

    assert query.intent == "find a known order"
    assert query.kinds == ("MCPServer",)
    assert query.namespace == "tenant-orders"
    assert query.limit == 20
    field_name = "limit"
    with pytest.raises(FrozenInstanceError):
        setattr(query, field_name, 1)
    with pytest.raises(ValueError, match="intent"):
        RegistrySearchQuery(intent="x" * 513)
    with pytest.raises(ValueError, match="limit"):
        RegistrySearchQuery(intent="orders", limit=21)
    with pytest.raises(ValueError, match="kinds"):
        RegistrySearchQuery(intent="orders", kinds=("Secret",))


def test_registry_stub_copies_and_freezes_only_the_safe_bounded_projection() -> None:
    labels = {"domain": "orders"}
    attributes: dict[str, object] = {
        "capabilities": ["cap/orders-read"],
        "inputSchema": {"type": "object"},
    }

    stub = RegistrySearchStub(
        kind="MCPServer",
        name="io.github.tesserix/orders",
        namespace="tenant-orders",
        tag="1.2.3",
        arn="arn:agentic:registry:tenant-orders:mcpservers/tenant-orders/orders",
        digest="sha256:" + "a" * 64,
        ref="mcpservers/tenant-orders/orders@1.2.3",
        title="Orders MCP",
        description="Locate known customer orders.",
        visibility="internal",
        labels=labels,
        annotations={"discovery.agentic.dev/capabilities": "cap/orders-read"},
        attributes=attributes,
        fetch_path="/v0/mcpservers/orders/1.2.3?namespace=tenant-orders",
    )

    labels["domain"] = "changed"
    attributes["capabilities"] = []
    assert stub.labels == {"domain": "orders"}
    assert stub.attributes["capabilities"] == ("cap/orders-read",)
    mutable_labels = cast(MutableMapping[str, str], stub.labels)
    with pytest.raises(TypeError):
        mutable_labels["other"] = "value"
    with pytest.raises(ValueError, match="fetch_path"):
        RegistrySearchStub(
            kind="MCPServer",
            name="orders",
            namespace="tenant-orders",
            tag="latest",
            arn="arn:agentic:registry:tenant-orders:mcpservers/tenant-orders/orders",
            digest="sha256:" + "a" * 64,
            ref="mcpservers/tenant-orders/orders@latest",
            fetch_path="https://attacker.invalid/v0/mcpservers/orders",
        )


def test_registry_artifact_digest_reproduces_the_go_canonical_hash() -> None:
    digest = registry_artifact_digest(
        kind="MCPServer",
        name="orders<&é",
        namespace="tenant-orders",
        tag="1.2.3",
        labels={"z": "Ω", "a": "<"},
        spec={
            "version": "1.0",
            "threshold": 1.0,
            "nested": {"b": 2.0, "a": "&"},
        },
    )

    assert digest == "sha256:37e14636e1ac6068b1fea08fba14eb1b9461ab258fd8c81c19d5a1559962129e"


def test_exact_registry_artifact_is_deeply_immutable_and_rehashable() -> None:
    labels = {"registry.agentic.dev/tenant": "tenant-orders"}
    spec: dict[str, JsonValue] = {
        "version": "1.2.3",
        "x-tesserix": {
            "lifecycle": "active",
            "protocolVersions": ["2025-11-25"],
        },
    }
    digest = registry_artifact_digest(
        kind="MCPServer",
        name="orders",
        namespace="tenant-orders",
        tag="1.2.3",
        labels=labels,
        spec=spec,
    )

    artifact = RegistryArtifact(
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

    labels["registry.agentic.dev/tenant"] = "tenant-other"
    spec["version"] = "changed"
    assert artifact.computed_digest == digest
    assert artifact.labels["registry.agentic.dev/tenant"] == "tenant-orders"
    assert artifact.spec["version"] == "1.2.3"
    mutable_spec = cast(MutableMapping[str, object], artifact.spec)
    with pytest.raises(TypeError):
        mutable_spec["version"] = "changed"


def test_registry_discovery_is_a_replaceable_runtime_checked_protocol() -> None:
    class Discovery:
        @property
        def origin(self) -> str:
            return "https://registry.example.com"

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: object,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            return ()

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: object,
        ) -> RegistryArtifact:
            del stub, context
            raise AssertionError("not called")

    assert isinstance(Discovery(), RegistryDiscovery)


def test_resolution_policy_is_default_deny_and_matches_adk_surface_bounds() -> None:
    policy = RegistryResolutionPolicy(
        server_name="orders",
        gateway_origin="https://gateway.example.com",
        supported_protocol_versions=("2025-11-25",),
        tool_requirements=(
            RegistryToolRequirement(
                name="orders_get",
                expected_input_fingerprint="a" * 64,
                expected_output_fingerprint="b" * 64,
            ),
        ),
    )

    assert policy.tool_allow == ()
    assert policy.tool_deny == ()
    assert policy.max_tools == 40
    assert policy.max_schema_bytes == 256 * 1024
    with pytest.raises(ValueError, match="both allowed and denied"):
        RegistryResolutionPolicy(
            server_name="orders",
            gateway_origin="https://gateway.example.com",
            supported_protocol_versions=("2025-11-25",),
            tool_allow=("orders_get",),
            tool_deny=("orders_get",),
        )
    with pytest.raises(ValueError, match="gateway_origin"):
        RegistryResolutionPolicy(
            server_name="orders",
            gateway_origin="http://gateway.example.com",
            supported_protocol_versions=("2025-11-25",),
        )


@pytest.mark.parametrize(
    ("max_tools", "max_schema_bytes"),
    [(0, 1), (129, 1), (1, 0), (1, 4 * 1024 * 1024 + 1)],
    ids=["no-tools", "too-many-tools", "no-schema", "schema-too-large"],
)
def test_registry_adk_server_enforces_the_adk_surface_budget_bounds(
    max_tools: int,
    max_schema_bytes: int,
) -> None:
    with pytest.raises(ValueError, match="ADK bound"):
        RegistryADKServer(
            name="orders",
            endpoint="https://gateway.example.com/gateway/orders/mcp",
            allow=("orders_get",),
            deny=(),
            prefix="orders",
            max_tools=max_tools,
            max_schema_bytes=max_schema_bytes,
            artifact_ref="mcpservers/tenant-orders/orders@1.2.3",
            artifact_digest=f"sha256:{'a' * 64}",
            tool_pins=(
                RegistryToolPin(
                    name="orders_get",
                    input_fingerprint="b" * 64,
                    output_fingerprint="c" * 64,
                ),
            ),
        )


@pytest.mark.parametrize(
    ("allow", "pin_names", "max_tools"),
    [
        (("*",), ("orders_get",), 1),
        (("orders_get", "orders_list"), ("orders_get",), 2),
        (("orders_get",), ("orders_get", "orders_list"), 2),
        (("orders_get", "orders_list"), ("orders_get", "orders_list"), 1),
    ],
    ids=["wildcard", "missing-pin", "extra-pin", "over-budget"],
)
def test_registry_adk_server_allows_only_the_exact_reviewed_tool_surface(
    allow: tuple[str, ...],
    pin_names: tuple[str, ...],
    max_tools: int,
) -> None:
    pins = tuple(
        RegistryToolPin(
            name=name,
            input_fingerprint="b" * 64,
            output_fingerprint="c" * 64,
        )
        for name in pin_names
    )

    with pytest.raises(ValueError, match="reviewed tool surface"):
        RegistryADKServer(
            name="orders",
            endpoint="https://gateway.example.com/gateway/orders/mcp",
            allow=allow,
            deny=(),
            prefix="orders",
            max_tools=max_tools,
            max_schema_bytes=32 * 1024,
            artifact_ref="mcpservers/tenant-orders/orders@1.2.3",
            artifact_digest=f"sha256:{'a' * 64}",
            tool_pins=pins,
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://operator@gateway.example.com/gateway/orders/mcp",
        "https://gateway.example.com/gateway/orders/mcp?variant=blue",
    ],
    ids=["userinfo", "query"],
)
def test_registry_adk_server_rejects_ambiguous_gateway_endpoints(endpoint: str) -> None:
    with pytest.raises(ValueError, match="trusted HTTPS gateway URL"):
        RegistryADKServer(
            name="orders",
            endpoint=endpoint,
            allow=("orders_get",),
            deny=(),
            prefix="orders",
            max_tools=1,
            max_schema_bytes=32 * 1024,
            artifact_ref="mcpservers/tenant-orders/orders@1.2.3",
            artifact_digest=f"sha256:{'a' * 64}",
            tool_pins=(
                RegistryToolPin(
                    name="orders_get",
                    input_fingerprint="b" * 64,
                    output_fingerprint="c" * 64,
                ),
            ),
        )


def test_resolver_fetches_one_exact_match_and_projects_only_reviewed_adk_tools() -> None:
    artifact = exact_artifact(include_input_schema_fingerprint=False)
    stub = search_stub(artifact=artifact)

    class Discovery:
        origin = "https://registry.example.com"

        def __init__(self) -> None:
            self.searches: list[RegistrySearchQuery] = []
            self.fetches: list[RegistrySearchStub] = []

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            self.searches.append(query)
            assert context.tenant == "tenant-orders"
            return (stub,)

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            self.fetches.append(stub)
            assert context.subject == "agent-orders"
            return artifact

    discovery = Discovery()
    resolver = RegistryResolver(discovery=discovery)
    query = RegistrySearchQuery(
        intent="find a known order",
        namespace="tenant-orders",
    )
    policy = matching_policy()

    result = asyncio.run(resolver.resolve(query, policy=policy, context=call_context()))

    assert result.source is RegistryResolutionSource.NETWORK
    assert isinstance(result.server, RegistryADKServer)
    assert result.server.endpoint == "https://gateway.example.com/gateway/orders/mcp"
    assert result.server.allow == ("orders_get",)
    assert result.server.deny == ()
    assert result.server.artifact_digest == artifact.digest
    assert tuple(pin.name for pin in result.server.tool_pins) == ("orders_get",)
    assert len(discovery.searches) == 1
    assert discovery.fetches == [stub]


@pytest.mark.parametrize(
    ("stub", "artifact", "expected_error"),
    [
        (
            search_stub(digest="sha256:" + "a" * 64),
            exact_artifact(),
            RegistryArtifactRaceError,
        ),
        (
            search_stub(artifact=exact_artifact(digest="sha256:" + "c" * 64)),
            exact_artifact(digest="sha256:" + "c" * 64),
            RegistryDigestMismatchError,
        ),
    ],
    ids=["moving-search-hit", "corrupt-exact-content"],
)
def test_resolver_raises_typed_failures_for_tag_races_and_digest_corruption(
    stub: RegistrySearchStub,
    artifact: RegistryArtifact,
    expected_error: type[Exception],
) -> None:
    class Discovery:
        origin = "https://registry.example.com"

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            return (stub,)

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub, context
            return artifact

    resolver = RegistryResolver(discovery=Discovery())

    with pytest.raises(expected_error):
        asyncio.run(
            resolver.resolve(
                RegistrySearchQuery(intent="find order", namespace="tenant-orders"),
                policy=matching_policy(),
                context=call_context(),
            )
        )


def test_registry_cache_hits_are_isolated_by_the_full_authenticated_identity() -> None:
    stub = search_stub()
    artifact = exact_artifact()

    class Discovery:
        origin = "https://registry.example.com"

        def __init__(self) -> None:
            self.searches = 0
            self.fetches = 0

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            self.searches += 1
            return (stub,)

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub, context
            self.fetches += 1
            return artifact

    discovery = Discovery()
    resolver = RegistryResolver(
        discovery=discovery,
        cache=InMemoryRegistryCache(),
    )
    query = RegistrySearchQuery(intent="find order", namespace="tenant-orders")

    async def exercise() -> tuple[RegistryResolution, RegistryResolution, RegistryResolution]:
        first = await resolver.resolve(query, policy=matching_policy(), context=call_context())
        same_identity = await resolver.resolve(
            query,
            policy=matching_policy(),
            context=call_context(),
        )
        other_subject = await resolver.resolve(
            query,
            policy=matching_policy(),
            context=call_context(subject="other-agent"),
        )
        return first, same_identity, other_subject

    first, same_identity, other_subject = asyncio.run(exercise())

    assert first.source is RegistryResolutionSource.NETWORK
    assert same_identity.source is RegistryResolutionSource.CACHE
    assert other_subject.source is RegistryResolutionSource.NETWORK
    assert discovery.searches == 2
    assert discovery.fetches == 2


def test_search_cache_keys_partition_every_query_and_identity_dimension() -> None:
    keys: list[RegistrySearchCacheKey] = []

    class Cache:
        async def get_search(
            self,
            key: RegistrySearchCacheKey,
            *,
            now: float,
        ) -> tuple[RegistrySearchStub, ...] | None:
            del now
            keys.append(key)
            return None

        async def put_search(
            self,
            key: RegistrySearchCacheKey,
            stubs: tuple[RegistrySearchStub, ...],
            *,
            expires_at: float,
        ) -> None:
            del key, stubs, expires_at

        async def get_artifact(
            self,
            key: RegistryArtifactCacheKey,
            *,
            now: float,
            allow_stale: bool,
        ) -> RegistryArtifact | None:
            del key, now, allow_stale
            return None

        async def put_artifact(
            self,
            key: RegistryArtifactCacheKey,
            artifact: RegistryArtifact,
            *,
            fresh_until: float,
            stale_until: float,
        ) -> None:
            del key, artifact, fresh_until, stale_until

    class Discovery:
        origin = "https://registry.example.com"

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            return ()

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub, context
            raise AssertionError("an empty search cannot fetch an artifact")

    resolver = RegistryResolver(discovery=Discovery(), cache=Cache())
    base = RegistrySearchQuery(intent="find order", namespace="tenant-orders")
    variants = (
        base,
        RegistrySearchQuery(intent="locate order", namespace="tenant-orders"),
        RegistrySearchQuery(
            intent="find order",
            kinds=("MCPServer", "Tool"),
            namespace="tenant-orders",
        ),
        RegistrySearchQuery(intent="find order", namespace="tenant-support"),
        RegistrySearchQuery(intent="find order", namespace="tenant-orders", limit=5),
    )

    async def exercise() -> None:
        for query in variants:
            await resolver.resolve(
                query,
                policy=matching_policy(),
                context=call_context(scopes=("orders:read", "orders:metadata")),
            )
        await resolver.resolve(
            base,
            policy=matching_policy(),
            context=call_context(scopes=("orders:metadata", "orders:read")),
        )
        await resolver.resolve(
            base,
            policy=matching_policy(),
            context=call_context(tenant="tenant-support"),
        )

    asyncio.run(exercise())

    assert {key.origin for key in keys} == {"https://registry.example.com"}
    assert {key.contract_version for key in keys} == {"registry-v0-search-stub-v1"}
    assert len({key.query_digest for key in keys[:5]}) == 5
    assert keys[0].identity_scope_hash == keys[5].identity_scope_hash
    assert keys[0].identity_scope_hash != keys[6].identity_scope_hash
    assert all(len(key.identity_scope_hash) == 64 for key in keys)
    assert all("tenant-" not in repr(key) for key in keys)


def test_artifact_cache_key_pins_exact_digest_and_identity_scope() -> None:
    stub = search_stub()
    artifact = exact_artifact()
    keys: list[RegistryArtifactCacheKey] = []

    class Cache:
        async def get_search(
            self,
            key: RegistrySearchCacheKey,
            *,
            now: float,
        ) -> tuple[RegistrySearchStub, ...] | None:
            del key, now
            return (stub,)

        async def put_search(
            self,
            key: RegistrySearchCacheKey,
            stubs: tuple[RegistrySearchStub, ...],
            *,
            expires_at: float,
        ) -> None:
            del key, stubs, expires_at

        async def get_artifact(
            self,
            key: RegistryArtifactCacheKey,
            *,
            now: float,
            allow_stale: bool,
        ) -> RegistryArtifact | None:
            del now, allow_stale
            keys.append(key)
            return None

        async def put_artifact(
            self,
            key: RegistryArtifactCacheKey,
            artifact: RegistryArtifact,
            *,
            fresh_until: float,
            stale_until: float,
        ) -> None:
            del artifact, fresh_until, stale_until
            keys.append(key)

    class Discovery:
        origin = "https://registry.example.com"

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            raise AssertionError("search must come from the cache")

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub, context
            return artifact

    resolver = RegistryResolver(discovery=Discovery(), cache=Cache())

    async def exercise() -> None:
        for tenant in ("tenant-orders", "tenant-support"):
            await resolver.resolve(
                RegistrySearchQuery(intent="find order", namespace="tenant-orders"),
                policy=matching_policy(),
                context=call_context(tenant=tenant),
            )

    asyncio.run(exercise())

    assert keys[0] == keys[1]
    assert keys[2] == keys[3]
    assert keys[0].origin == "https://registry.example.com"
    assert keys[0].contract_version == "registry-v0-search-stub-v1"
    assert keys[0].artifact_digest == stub.digest
    assert keys[0].identity_scope_hash != keys[2].identity_scope_hash
    assert "tenant-" not in repr(keys)


def test_in_memory_registry_cache_evicts_least_recently_used_entries_at_bounds() -> None:
    cache = InMemoryRegistryCache(max_search_entries=2, max_artifact_entries=2)
    stub = search_stub()
    artifact = exact_artifact()

    def search_key(digest_character: str) -> RegistrySearchCacheKey:
        return RegistrySearchCacheKey(
            origin="https://registry.example.com",
            identity_scope_hash="a" * 64,
            contract_version="registry-v0-search-stub-v1",
            query_digest=digest_character * 64,
        )

    def artifact_key(digest_character: str) -> RegistryArtifactCacheKey:
        return RegistryArtifactCacheKey(
            origin="https://registry.example.com",
            identity_scope_hash="a" * 64,
            contract_version="registry-v0-search-stub-v1",
            artifact_digest=f"sha256:{digest_character * 64}",
        )

    search_keys = tuple(search_key(character) for character in "bcd")
    artifact_keys = tuple(artifact_key(character) for character in "bcd")

    async def exercise() -> None:
        await cache.put_search(search_keys[0], (stub,), expires_at=10)
        await cache.put_search(search_keys[1], (stub,), expires_at=10)
        assert await cache.get_search(search_keys[0], now=0) == (stub,)
        await cache.put_search(search_keys[2], (stub,), expires_at=10)

        assert await cache.get_search(search_keys[1], now=0) is None
        assert await cache.get_search(search_keys[0], now=0) == (stub,)
        assert await cache.get_search(search_keys[2], now=0) == (stub,)

        await cache.put_artifact(
            artifact_keys[0],
            artifact,
            fresh_until=10,
            stale_until=20,
        )
        await cache.put_artifact(
            artifact_keys[1],
            artifact,
            fresh_until=10,
            stale_until=20,
        )
        assert await cache.get_artifact(artifact_keys[0], now=0, allow_stale=False) == artifact
        await cache.put_artifact(
            artifact_keys[2],
            artifact,
            fresh_until=10,
            stale_until=20,
        )

        assert await cache.get_artifact(artifact_keys[1], now=0, allow_stale=False) is None
        assert await cache.get_artifact(artifact_keys[0], now=0, allow_stale=False) == artifact
        assert await cache.get_artifact(artifact_keys[2], now=0, allow_stale=False) == artifact

    asyncio.run(exercise())


def test_cached_artifact_authorization_lease_is_not_extended_by_cache_hits() -> None:
    stub = search_stub()
    artifact = exact_artifact()

    class ManualClock:
        def __init__(self) -> None:
            self.value = 0.0

        def now(self) -> float:
            return self.value

        async def sleep(self, seconds: float) -> None:
            self.value += seconds

        def advance(self, seconds: float) -> None:
            self.value += seconds

    class Discovery:
        origin = "https://registry.example.com"

        def __init__(self) -> None:
            self.searches = 0
            self.fetches = 0

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            self.searches += 1
            return (stub,)

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub, context
            self.fetches += 1
            return artifact

    clock = ManualClock()
    discovery = Discovery()
    resolver = RegistryResolver(
        discovery=discovery,
        cache=InMemoryRegistryCache(),
        cache_policy=RegistryCachePolicy(
            search_ttl_seconds=30,
            artifact_ttl_seconds=60,
        ),
        clock=clock,
    )
    query = RegistrySearchQuery(intent="find order", namespace="tenant-orders")

    async def exercise() -> None:
        await resolver.resolve(query, policy=matching_policy(), context=call_context())
        clock.advance(31)
        await resolver.resolve(query, policy=matching_policy(), context=call_context())
        clock.advance(30)
        await resolver.resolve(query, policy=matching_policy(), context=call_context())

    asyncio.run(exercise())

    assert discovery.searches == 3
    assert discovery.fetches == 2


def test_explicit_offline_policy_reuses_only_a_digest_verified_exact_artifact() -> None:
    stub = search_stub()
    artifact = exact_artifact()

    class ManualClock:
        def __init__(self) -> None:
            self.value = 0.0

        def now(self) -> float:
            return self.value

        async def sleep(self, seconds: float) -> None:
            self.value += seconds

        def advance(self, seconds: float) -> None:
            self.value += seconds

    class Discovery:
        origin = "https://registry.example.com"

        def __init__(self) -> None:
            self.fetch_unavailable = False

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            return (stub,)

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub
            if self.fetch_unavailable:
                raise RegistryUnavailableError(request_id=context.request_id)
            return artifact

    clock = ManualClock()
    discovery = Discovery()
    resolver = RegistryResolver(
        discovery=discovery,
        cache=InMemoryRegistryCache(),
        cache_policy=RegistryCachePolicy(
            search_ttl_seconds=30,
            artifact_ttl_seconds=60,
            offline_max_stale_seconds=120,
        ),
        clock=clock,
    )
    query = RegistrySearchQuery(intent="find order", namespace="tenant-orders")

    async def exercise() -> RegistryResolution:
        await resolver.resolve(query, policy=matching_policy(), context=call_context())
        clock.advance(61)
        discovery.fetch_unavailable = True
        return await resolver.resolve(
            query,
            policy=matching_policy(),
            context=call_context(),
        )

    result = asyncio.run(exercise())

    assert result.source is RegistryResolutionSource.OFFLINE
    assert result.server is not None
    assert result.server.artifact_digest == artifact.computed_digest


def test_default_policy_never_requests_stale_artifacts_when_registry_is_down() -> None:
    stub = search_stub()

    class Cache:
        def __init__(self) -> None:
            self.allow_stale: list[bool] = []

        async def get_search(
            self,
            key: RegistrySearchCacheKey,
            *,
            now: float,
        ) -> tuple[RegistrySearchStub, ...] | None:
            del key, now
            return (stub,)

        async def put_search(
            self,
            key: RegistrySearchCacheKey,
            stubs: tuple[RegistrySearchStub, ...],
            *,
            expires_at: float,
        ) -> None:
            del key, stubs, expires_at

        async def get_artifact(
            self,
            key: RegistryArtifactCacheKey,
            *,
            now: float,
            allow_stale: bool,
        ) -> RegistryArtifact | None:
            del key, now
            self.allow_stale.append(allow_stale)
            return None

        async def put_artifact(
            self,
            key: RegistryArtifactCacheKey,
            artifact: RegistryArtifact,
            *,
            fresh_until: float,
            stale_until: float,
        ) -> None:
            del key, artifact, fresh_until, stale_until

    class Discovery:
        origin = "https://registry.example.com"

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            raise AssertionError("fresh search must come from the cache")

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub
            raise RegistryUnavailableError(request_id=context.request_id)

    cache = Cache()
    resolver = RegistryResolver(discovery=Discovery(), cache=cache)

    with pytest.raises(RegistryUnavailableError):
        asyncio.run(
            resolver.resolve(
                RegistrySearchQuery(intent="find order", namespace="tenant-orders"),
                policy=matching_policy(),
                context=call_context(),
            )
        )

    assert cache.allow_stale == [False]


def test_offline_mode_reverifies_a_stale_external_cache_artifact() -> None:
    stub = search_stub()
    corrupt = exact_artifact(
        digest=stub.digest,
        input_schema=order_input_schema(max_length=32),
    )

    class Cache:
        async def get_search(
            self,
            key: RegistrySearchCacheKey,
            *,
            now: float,
        ) -> tuple[RegistrySearchStub, ...] | None:
            del key, now
            return (stub,)

        async def put_search(
            self,
            key: RegistrySearchCacheKey,
            stubs: tuple[RegistrySearchStub, ...],
            *,
            expires_at: float,
        ) -> None:
            del key, stubs, expires_at

        async def get_artifact(
            self,
            key: RegistryArtifactCacheKey,
            *,
            now: float,
            allow_stale: bool,
        ) -> RegistryArtifact | None:
            del key, now
            return corrupt if allow_stale else None

        async def put_artifact(
            self,
            key: RegistryArtifactCacheKey,
            artifact: RegistryArtifact,
            *,
            fresh_until: float,
            stale_until: float,
        ) -> None:
            del key, artifact, fresh_until, stale_until

    class Discovery:
        origin = "https://registry.example.com"

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            raise AssertionError("fresh search must come from the cache")

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub
            raise RegistryUnavailableError(request_id=context.request_id)

    resolver = RegistryResolver(
        discovery=Discovery(),
        cache=Cache(),
        cache_policy=RegistryCachePolicy(offline_max_stale_seconds=120),
    )

    with pytest.raises(RegistryDigestMismatchError):
        asyncio.run(
            resolver.resolve(
                RegistrySearchQuery(intent="find order", namespace="tenant-orders"),
                policy=matching_policy(),
                context=call_context(),
            )
        )


def test_cache_failure_degrades_to_registry_without_reducing_availability() -> None:
    stub = search_stub()
    artifact = exact_artifact()

    class FailingCache:
        async def get_search(
            self,
            key: RegistrySearchCacheKey,
            *,
            now: float,
        ) -> tuple[RegistrySearchStub, ...] | None:
            del key, now
            raise RegistryCacheUnavailableError()

        async def put_search(
            self,
            key: RegistrySearchCacheKey,
            stubs: tuple[RegistrySearchStub, ...],
            *,
            expires_at: float,
        ) -> None:
            del key, stubs, expires_at
            raise RegistryCacheUnavailableError()

        async def get_artifact(
            self,
            key: RegistryArtifactCacheKey,
            *,
            now: float,
            allow_stale: bool,
        ) -> RegistryArtifact | None:
            del key, now, allow_stale
            raise RegistryCacheUnavailableError()

        async def put_artifact(
            self,
            key: RegistryArtifactCacheKey,
            artifact: RegistryArtifact,
            *,
            fresh_until: float,
            stale_until: float,
        ) -> None:
            del key, artifact, fresh_until, stale_until
            raise RegistryCacheUnavailableError()

    class Discovery:
        origin = "https://registry.example.com"

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            return (stub,)

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub, context
            return artifact

    result = asyncio.run(
        RegistryResolver(discovery=Discovery(), cache=FailingCache()).resolve(
            RegistrySearchQuery(intent="find order", namespace="tenant-orders"),
            policy=matching_policy(),
            context=call_context(),
        )
    )

    assert result.source is RegistryResolutionSource.NETWORK
    assert result.server is not None


@pytest.mark.parametrize(
    ("artifact", "policy", "expected_reason"),
    [
        (
            exact_artifact(lifecycle="deprecated"),
            matching_policy(),
            RegistryCandidateReason.LIFECYCLE,
        ),
        (
            exact_artifact(protocol_versions=("2024-11-05",)),
            matching_policy(),
            RegistryCandidateReason.PROTOCOL,
        ),
        (
            exact_artifact(required_scopes=("orders:admin",)),
            matching_policy(),
            RegistryCandidateReason.SCOPE,
        ),
        (
            exact_artifact(tool_scopes=("orders:admin",)),
            matching_policy(),
            RegistryCandidateReason.SCOPE,
        ),
        (
            exact_artifact(),
            matching_policy(expected_input_fingerprint="c" * 64),
            RegistryCandidateReason.FINGERPRINT,
        ),
        (
            exact_artifact(input_schema_fingerprint="c" * 64),
            matching_policy(),
            RegistryCandidateReason.FINGERPRINT,
        ),
        (
            exact_artifact(input_schema=order_input_schema(max_length=32)),
            matching_policy(
                pin_input=False,
                compatible_input_schema=order_input_schema(max_length=64),
            ),
            RegistryCandidateReason.SCHEMA,
        ),
        (
            exact_artifact(tool_capabilities=()),
            matching_policy(),
            RegistryCandidateReason.CAPABILITY,
        ),
        (
            exact_artifact(gateway_path="//attacker.invalid/mcp"),
            matching_policy(),
            RegistryCandidateReason.GATEWAY,
        ),
        (
            exact_artifact(),
            matching_policy(tool_allow=()),
            RegistryCandidateReason.TOOL_POLICY,
        ),
    ],
    ids=[
        "lifecycle",
        "protocol",
        "server-scope",
        "tool-scope",
        "fingerprint",
        "projection-fingerprint",
        "schema",
        "tool-capability",
        "gateway",
        "default-deny",
    ],
)
def test_resolver_returns_bounded_no_match_for_every_exact_policy_rejection(
    artifact: RegistryArtifact,
    policy: RegistryResolutionPolicy,
    expected_reason: RegistryCandidateReason,
) -> None:
    stub = search_stub(artifact=artifact)

    class Discovery:
        origin = "https://registry.example.com"

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            return (stub,)

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del stub, context
            return artifact

    result = asyncio.run(
        RegistryResolver(discovery=Discovery()).resolve(
            RegistrySearchQuery(intent="find order", namespace="tenant-orders"),
            policy=policy,
            context=call_context(),
        )
    )

    assert result.server is None
    assert len(result.explanations) == 1
    assert result.explanations[0].decision is RegistryCandidateDecision.REJECTED
    assert result.explanations[0].reasons == (expected_reason,)


def test_resolver_preserves_registry_order_and_fetches_only_the_first_eligible_stub() -> None:
    artifact = exact_artifact()
    wrong_capability = RegistrySearchStub(
        kind="MCPServer",
        name="billing",
        namespace="tenant-orders",
        tag="1.0.0",
        arn="arn:agentic:registry:tenant-orders:mcpservers/tenant-orders/billing",
        digest="sha256:" + "a" * 64,
        ref="mcpservers/tenant-orders/billing@1.0.0",
        annotations={"discovery.agentic.dev/capabilities": "cap/billing-read"},
        fetch_path="/v0/mcpservers/billing/1.0.0?namespace=tenant-orders",
    )
    selected = RegistrySearchStub(
        kind=artifact.kind,
        name=artifact.name,
        namespace=artifact.namespace,
        tag=artifact.tag,
        arn=artifact.arn,
        digest=artifact.digest,
        ref=artifact.ref,
        attributes={"capabilities": ["cap/orders-read"]},
        fetch_path="/v0/mcpservers/orders/1.2.3?namespace=tenant-orders",
    )

    class Discovery:
        origin = "https://registry.example.com"

        def __init__(self) -> None:
            self.fetches: list[RegistrySearchStub] = []

        async def search(
            self,
            query: RegistrySearchQuery,
            *,
            context: CallContext,
        ) -> tuple[RegistrySearchStub, ...]:
            del query, context
            return (wrong_capability, selected)

        async def fetch(
            self,
            stub: RegistrySearchStub,
            *,
            context: CallContext,
        ) -> RegistryArtifact:
            del context
            self.fetches.append(stub)
            return artifact

    discovery = Discovery()
    result = asyncio.run(
        RegistryResolver(discovery=discovery).resolve(
            RegistrySearchQuery(intent="find order", namespace="tenant-orders"),
            policy=matching_policy(),
            context=call_context(),
        )
    )

    assert result.server is not None
    assert discovery.fetches == [selected]
    assert tuple(item.decision for item in result.explanations) == (
        RegistryCandidateDecision.REJECTED,
        RegistryCandidateDecision.SELECTED,
    )
    assert result.explanations[0].reasons == (RegistryCandidateReason.CAPABILITY,)
