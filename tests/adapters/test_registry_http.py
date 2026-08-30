from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from typing import cast

import httpx
import pytest

from tesserix_mcp_runtime import (
    AuthenticatedIdentity,
    CallContext,
    JsonValue,
    RegistryArtifactRaceError,
    RegistryAuthenticationError,
    RegistryAuthorizationError,
    RegistryContractError,
    RegistrySearchQuery,
    RegistrySearchStub,
    RegistryUnavailableError,
    SecretValue,
    registry_artifact_digest,
    schema_fingerprint,
)
from tesserix_mcp_runtime.adapters.outbound_http import OutboundHTTPResponse
from tesserix_mcp_runtime.adapters.registry_http import (
    RegistryHTTPDiscovery,
    RegistryHTTPDiscoveryLimits,
    RegistryHTTPTransport,
)
from tesserix_mcp_runtime.contracts import CredentialProvider
from tesserix_mcp_runtime.redaction import RedactionLimits, RedactionPolicy


def context() -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant="tenant-orders",
            subject="agent-orders",
            issuer="https://identity.example.com",
            scopes=("orders:read",),
        ),
        request_id="request-registry-http",
        run_id="run-registry-http",
    )


def registry_document() -> tuple[dict[str, JsonValue], str, str, str]:
    input_schema: dict[str, JsonValue] = {
        "type": "object",
        "properties": {"order_id": {"type": "string"}},
        "required": ["order_id"],
        "additionalProperties": False,
    }
    labels = {
        "registry.agentic.dev/tenant": "tenant-orders",
        "registry.agentic.dev/visibility": "internal",
    }
    spec: dict[str, JsonValue] = {
        "version": "1.2.3",
        "x-tesserix": {
            "lifecycle": "active",
            "protocolVersions": ["2025-11-25"],
            "requiredScopes": ["orders:read"],
            "routePolicy": {"gatewayPath": "/gateway/orders/mcp"},
            "semantic": {"capabilities": ["cap/orders-read"]},
            "tools": [
                {
                    "name": "orders_get",
                    "status": "active",
                    "capabilities": ["cap/orders-read"],
                    "requiredScopes": ["orders:read"],
                    "inputSchema": input_schema,
                    "inputFingerprint": schema_fingerprint(input_schema),
                    "outputFingerprint": "b" * 64,
                }
            ],
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
    arn = "arn:agentic:registry:tenant-orders:mcpservers/tenant-orders/orders"
    ref = "mcpservers/tenant-orders/orders@1.2.3"
    metadata_labels = dict[str, JsonValue](labels)
    metadata: dict[str, JsonValue] = {
        "name": "orders",
        "namespace": "tenant-orders",
        "tag": "1.2.3",
        "arn": arn,
        "digest": digest,
        "ref": ref,
        "labels": metadata_labels,
    }
    document: dict[str, JsonValue] = {
        "apiVersion": "registry.agentic.dev/v1alpha1",
        "kind": "MCPServer",
        "metadata": metadata,
        "spec": spec,
    }
    return document, digest, arn, ref


def registry_stub_document() -> dict[str, JsonValue]:
    _, digest, arn, ref = registry_document()
    return {
        "kind": "MCPServer",
        "name": "orders",
        "namespace": "tenant-orders",
        "tag": "1.2.3",
        "arn": arn,
        "digest": digest,
        "ref": ref,
        "title": "Orders MCP",
        "description": "Locate known orders.",
        "visibility": "internal",
        "labels": {"domain": "orders"},
        "annotations": {},
        "attributes": {},
        "fetchPath": "/v0/mcpservers/orders/1.2.3?namespace=tenant-orders",
    }


def registry_stub() -> RegistrySearchStub:
    document = registry_stub_document()
    return RegistrySearchStub(
        kind=cast(str, document["kind"]),
        name=cast(str, document["name"]),
        namespace=cast(str, document["namespace"]),
        tag=cast(str, document["tag"]),
        arn=cast(str, document["arn"]),
        digest=cast(str, document["digest"]),
        ref=cast(str, document["ref"]),
        fetch_path=cast(str, document["fetchPath"]),
    )


class NeverTransport:
    async def request(
        self,
        method: str,
        url: str,
        *,
        request_id: str,
        headers: Mapping[str, str | SecretValue] | None = None,
        content: bytes = b"",
    ) -> OutboundHTTPResponse:
        del method, url, request_id, headers, content
        raise AssertionError("transport must not be called")


class InvalidResponseTransport:
    async def request(
        self,
        method: str,
        url: str,
        *,
        request_id: str,
        headers: Mapping[str, str | SecretValue] | None = None,
        content: bytes = b"",
    ) -> OutboundHTTPResponse:
        del method, url, request_id, headers, content
        return cast(OutboundHTTPResponse, object())


class InvalidCredentials:
    async def issue(
        self,
        *,
        audience: str,
        scopes: tuple[str, ...],
        context: CallContext,
    ) -> SecretValue:
        del audience, scopes, context
        return cast(SecretValue, object())


class ExplodingRedactor:
    @property
    def limits(self) -> RedactionLimits:
        return RedactionLimits()

    def redact_text(self, value: str) -> str:
        del value
        raise RuntimeError("redactor internals")

    def redact(self, value: JsonValue) -> JsonValue:
        return value


class MockOutboundTransport:
    def __init__(self, handler: httpx.MockTransport) -> None:
        self._client = httpx.AsyncClient(transport=handler)

    async def request(
        self,
        method: str,
        url: str,
        *,
        request_id: str,
        headers: Mapping[str, str | SecretValue] | None = None,
        content: bytes = b"",
    ) -> OutboundHTTPResponse:
        del request_id
        revealed = {
            name: value.reveal() if isinstance(value, SecretValue) else value
            for name, value in (headers or {}).items()
        }
        response = await self._client.request(
            method,
            url,
            headers=revealed,
            content=content,
        )
        return OutboundHTTPResponse(
            status_code=response.status_code,
            headers=tuple(response.headers.multi_items()),
            body=response.content,
        )

    async def aclose(self) -> None:
        await self._client.aclose()


def test_http_adapter_uses_bounded_get_search_then_the_exact_relative_fetch_path() -> None:
    document, digest, arn, ref = registry_document()
    seen: list[httpx.Request] = []

    def serve(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/v0/search":
            assert request.url.params["q"] == "find a known order"
            assert request.url.params.get_list("kinds") == ["MCPServer"]
            assert request.url.params["namespace"] == "tenant-orders"
            assert request.url.params["limit"] == "10"
            assert request.url.params["view"] == "stub"
            return httpx.Response(
                200,
                json=[
                    {
                        "kind": "MCPServer",
                        "name": "orders",
                        "namespace": "tenant-orders",
                        "tag": "1.2.3",
                        "arn": arn,
                        "digest": digest,
                        "ref": ref,
                        "title": "Orders MCP",
                        "description": "Locate known orders.",
                        "visibility": "internal",
                        "labels": {"domain": "orders"},
                        "annotations": {"discovery.agentic.dev/capabilities": "cap/orders-read"},
                        "attributes": {"capabilities": ["cap/orders-read"]},
                        "fetchPath": ("/v0/mcpservers/orders/1.2.3?namespace=tenant-orders"),
                    }
                ],
            )
        assert request.url.path == "/v0/mcpservers/orders/1.2.3"
        assert request.url.params["namespace"] == "tenant-orders"
        return httpx.Response(
            200,
            content=json.dumps(document, separators=(",", ":")).encode(),
            headers={"content-type": "application/json"},
        )

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )
    assert discovery.origin == "https://registry.example.com"

    async def exercise() -> None:
        query = RegistrySearchQuery(
            intent="find a known order",
            namespace="tenant-orders",
        )
        stubs = await discovery.search(query, context=context())
        assert len(stubs) == 1
        artifact = await discovery.fetch(stubs[0], context=context())
        assert artifact.digest == digest
        assert artifact.computed_digest == digest
        await transport.aclose()

    asyncio.run(exercise())

    assert len(seen) == 2
    assert all(request.method == "GET" for request in seen)


@pytest.mark.parametrize(
    ("status_code", "expected_error"),
    [
        (400, RegistryContractError),
        (404, RegistryUnavailableError),
        (401, RegistryAuthenticationError),
        (403, RegistryAuthorizationError),
        (422, RegistryContractError),
        (429, RegistryUnavailableError),
        (503, RegistryUnavailableError),
    ],
)
def test_http_adapter_maps_statuses_without_exposing_registry_error_payloads(
    status_code: int,
    expected_error: type[Exception],
) -> None:
    def serve(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(status_code, text="Bearer secret registry internals")

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )

    async def exercise() -> None:
        with pytest.raises(expected_error) as caught:
            await discovery.search(RegistrySearchQuery(intent="orders"), context=context())
        assert "secret" not in str(caught.value)
        await transport.aclose()

    asyncio.run(exercise())


def test_http_adapter_rejects_credential_bearing_stub_before_it_can_be_cached() -> None:
    _, digest, arn, ref = registry_document()

    def serve(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            json=[
                {
                    "kind": "MCPServer",
                    "name": "orders",
                    "namespace": "tenant-orders",
                    "tag": "1.2.3",
                    "arn": arn,
                    "digest": digest,
                    "ref": ref,
                    "annotations": {
                        "discovery.agentic.dev/summary": "Authorization: Bearer verysecret"
                    },
                    "fetchPath": "/v0/mcpservers/orders/1.2.3?namespace=tenant-orders",
                }
            ],
        )

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )

    async def exercise() -> None:
        with pytest.raises(RegistryContractError):
            await discovery.search(RegistrySearchQuery(intent="orders"), context=context())
        await transport.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "body",
    [
        b"not-json",
        b'[{"kind":"MCPServer","kind":"Skill"}]',
        b"[" + (b" " * (128 * 1024)) + b"]",
    ],
    ids=["malformed", "duplicate-key", "oversized"],
)
def test_http_adapter_rejects_untrusted_search_response_bodies(body: bytes) -> None:
    def serve(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=body)

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )

    async def exercise() -> None:
        with pytest.raises(RegistryContractError):
            await discovery.search(RegistrySearchQuery(intent="orders"), context=context())
        await transport.aclose()

    asyncio.run(exercise())


def test_http_adapter_maps_missing_exact_tag_to_a_typed_race() -> None:
    _, digest, arn, ref = registry_document()

    def serve(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v0/search":
            return httpx.Response(
                200,
                json=[
                    {
                        "kind": "MCPServer",
                        "name": "orders",
                        "namespace": "tenant-orders",
                        "tag": "1.2.3",
                        "arn": arn,
                        "digest": digest,
                        "ref": ref,
                        "fetchPath": ("/v0/mcpservers/orders/1.2.3?namespace=tenant-orders"),
                    }
                ],
            )
        return httpx.Response(404, text="tag was replaced")

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )

    async def exercise() -> None:
        stubs = await discovery.search(
            RegistrySearchQuery(intent="orders"),
            context=context(),
        )
        with pytest.raises(RegistryArtifactRaceError) as caught:
            await discovery.fetch(stubs[0], context=context())
        assert "replaced" not in str(caught.value)
        await transport.aclose()

    asyncio.run(exercise())


def test_http_adapter_issues_fresh_credentials_only_in_request_headers() -> None:
    document, digest, arn, ref = registry_document()
    issued: list[tuple[str, tuple[str, ...], str]] = []
    seen: list[httpx.Request] = []

    class Credentials:
        async def issue(
            self,
            *,
            audience: str,
            scopes: tuple[str, ...],
            context: CallContext,
        ) -> SecretValue:
            issued.append((audience, scopes, context.request_id))
            return SecretValue(f"credential-{len(issued)}")

    def serve(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/v0/search":
            return httpx.Response(
                200,
                json=[
                    {
                        "kind": "MCPServer",
                        "name": "orders",
                        "namespace": "tenant-orders",
                        "tag": "1.2.3",
                        "arn": arn,
                        "digest": digest,
                        "ref": ref,
                        "fetchPath": ("/v0/mcpservers/orders/1.2.3?namespace=tenant-orders"),
                    }
                ],
            )
        return httpx.Response(200, json=document)

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
        credential_provider=Credentials(),
    )

    async def exercise() -> None:
        stubs = await discovery.search(
            RegistrySearchQuery(intent="orders"),
            context=context(),
        )
        await discovery.fetch(stubs[0], context=context())
        await transport.aclose()

    asyncio.run(exercise())

    assert issued == [
        ("https://registry.example.com", ("registry:read",), context().request_id),
        ("https://registry.example.com", ("registry:read",), context().request_id),
    ]
    assert [request.headers["authorization"] for request in seen] == [
        "Bearer credential-1",
        "Bearer credential-2",
    ]
    assert all("credential-" not in str(request.url) for request in seen)
    assert all(b"credential-" not in request.content for request in seen)


@pytest.mark.parametrize(
    "value",
    [True, "1024", 0, 128 * 1024 + 1],
    ids=["bool", "non-integer", "zero", "above-hard-maximum"],
)
def test_registry_http_search_limits_are_bounded_integers(value: object) -> None:
    with pytest.raises(ValueError, match="body limit"):
        RegistryHTTPDiscoveryLimits(max_search_bytes=cast(int, value))


def test_registry_http_artifact_limit_is_bounded() -> None:
    with pytest.raises(ValueError, match="body limit"):
        RegistryHTTPDiscoveryLimits(max_artifact_bytes=0)


def test_registry_http_constructor_rejects_invalid_dependencies() -> None:
    with pytest.raises(TypeError, match="transport"):
        RegistryHTTPDiscovery(
            origin="https://registry.example.com",
            transport=cast(RegistryHTTPTransport, object()),
        )
    with pytest.raises(TypeError, match="credential_provider"):
        RegistryHTTPDiscovery(
            origin="https://registry.example.com",
            transport=NeverTransport(),
            credential_provider=cast(CredentialProvider[SecretValue], object()),
        )
    with pytest.raises(TypeError, match="limits"):
        RegistryHTTPDiscovery(
            origin="https://registry.example.com",
            transport=NeverTransport(),
            limits=cast(RegistryHTTPDiscoveryLimits, object()),
        )
    with pytest.raises(TypeError, match="redactor"):
        RegistryHTTPDiscovery(
            origin="https://registry.example.com",
            transport=NeverTransport(),
            redactor=cast(RedactionPolicy, object()),
        )


@pytest.mark.parametrize(
    "value",
    [
        ["registry:read"],
        (),
        tuple(f"scope:{index}" for index in range(17)),
        ("registry:read", "registry:read"),
        (1,),
        ("",),
        (" registry:read",),
        ("x" * 257,),
    ],
    ids=[
        "mutable",
        "empty",
        "too-many",
        "duplicate",
        "non-string",
        "blank",
        "untrimmed",
        "too-long",
    ],
)
def test_registry_http_constructor_rejects_invalid_scopes(value: object) -> None:
    with pytest.raises(ValueError, match="credential_scopes"):
        RegistryHTTPDiscovery(
            origin="https://registry.example.com",
            transport=NeverTransport(),
            credential_scopes=cast(tuple[str, ...], value),
        )


def test_registry_http_operations_require_typed_contracts() -> None:
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=NeverTransport(),
    )

    async def exercise() -> None:
        with pytest.raises(TypeError, match="typed query"):
            await discovery.search(
                cast(RegistrySearchQuery, object()),
                context=context(),
            )
        with pytest.raises(TypeError, match="authenticated context"):
            await discovery.search(
                RegistrySearchQuery(intent="orders"),
                context=cast(CallContext, object()),
            )
        with pytest.raises(TypeError, match="typed stub"):
            await discovery.fetch(
                cast(RegistrySearchStub, object()),
                context=context(),
            )
        with pytest.raises(TypeError, match="authenticated context"):
            await discovery.fetch(
                registry_stub(),
                context=cast(CallContext, object()),
            )

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("body", "limit"),
    [(b"{}", 10), (b"[{},{}]", 1)],
    ids=["not-a-list", "more-than-requested"],
)
def test_registry_http_search_rejects_invalid_result_sets(body: bytes, limit: int) -> None:
    def serve(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=body)

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )

    async def exercise() -> None:
        with pytest.raises(RegistryContractError):
            await discovery.search(
                RegistrySearchQuery(intent="orders", limit=limit),
                context=context(),
            )
        await transport.aclose()

    asyncio.run(exercise())


def test_registry_http_rejects_an_invalid_credential_result() -> None:
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=NeverTransport(),
        credential_provider=InvalidCredentials(),
    )

    async def exercise() -> None:
        with pytest.raises(RegistryUnavailableError):
            await discovery.search(RegistrySearchQuery(intent="orders"), context=context())

    asyncio.run(exercise())


def test_registry_http_rejects_a_non_response_transport_result() -> None:
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=InvalidResponseTransport(),
    )

    async def exercise() -> None:
        with pytest.raises(RegistryContractError):
            await discovery.search(RegistrySearchQuery(intent="orders"), context=context())

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", 1),
        ("title", 1),
        ("labels", {"domain": 1}),
        ("attributes", "not-an-object"),
    ],
    ids=["required-text", "optional-text", "text-map", "object"],
)
def test_registry_http_rejects_malformed_stub_fields(
    field: str,
    value: JsonValue,
) -> None:
    stub = registry_stub_document()
    stub[field] = value

    def serve(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json=[stub])

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )

    async def exercise() -> None:
        with pytest.raises(RegistryContractError):
            await discovery.search(RegistrySearchQuery(intent="orders"), context=context())
        await transport.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "malformation",
    ["root", "metadata", "required-text", "labels", "spec"],
)
def test_registry_http_rejects_malformed_artifact_fields(malformation: str) -> None:
    document, _, _, _ = registry_document()
    payload: JsonValue = document
    if malformation == "root":
        payload = []
    elif malformation == "metadata":
        document["metadata"] = "not-an-object"
    elif malformation == "required-text":
        document["apiVersion"] = 1
    elif malformation == "labels":
        metadata = cast(dict[str, JsonValue], document["metadata"])
        metadata["labels"] = {"domain": 1}
    else:
        document["spec"] = []

    def serve(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json=payload)

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )

    async def exercise() -> None:
        with pytest.raises(RegistryContractError):
            await discovery.fetch(registry_stub(), context=context())
        await transport.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("secret", "accepted"),
    [("***", True), ("plaintext-credential", False)],
    ids=["masked", "unmasked"],
)
def test_registry_http_enforces_masking_for_secret_named_fields(
    secret: str,
    accepted: bool,
) -> None:
    stub = registry_stub_document()
    stub["attributes"] = {
        "token": secret,
        "safe-values": [None, True, 1, 1.5],
    }

    def serve(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json=[stub])

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )

    async def exercise() -> None:
        if accepted:
            assert (
                len(
                    await discovery.search(
                        RegistrySearchQuery(intent="orders"),
                        context=context(),
                    )
                )
                == 1
            )
        else:
            with pytest.raises(RegistryContractError):
                await discovery.search(
                    RegistrySearchQuery(intent="orders"),
                    context=context(),
                )
        await transport.aclose()

    asyncio.run(exercise())


def test_registry_http_fails_closed_when_the_redactor_fails() -> None:
    def serve(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json=[registry_stub_document()])

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
        redactor=ExplodingRedactor(),
    )

    async def exercise() -> None:
        with pytest.raises(RegistryContractError) as caught:
            await discovery.search(RegistrySearchQuery(intent="orders"), context=context())
        assert "redactor" not in str(caught.value)
        await transport.aclose()

    asyncio.run(exercise())


@pytest.mark.parametrize("limit", ["depth", "nodes"])
def test_registry_http_rejects_structurally_unbounded_documents(limit: str) -> None:
    stub = registry_stub_document()
    if limit == "depth":
        root: dict[str, JsonValue] = {}
        cursor = root
        for _ in range(34):
            child: dict[str, JsonValue] = {}
            cursor["child"] = child
            cursor = child
        stub["attributes"] = root
    else:
        items: list[JsonValue] = [0] * 32_769
        stub["attributes"] = {"items": items}

    def serve(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, json=[stub])

    transport = MockOutboundTransport(httpx.MockTransport(serve))
    discovery = RegistryHTTPDiscovery(
        origin="https://registry.example.com",
        transport=transport,
    )

    async def exercise() -> None:
        with pytest.raises(RegistryContractError):
            await discovery.search(RegistrySearchQuery(intent="orders"), context=context())
        await transport.aclose()

    asyncio.run(exercise())
