from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import cast

import httpx
import jwt
import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from integration.journey.discovery import journey_read_policy
from integration.journey.identity import (
    ROUTE_SCOPE_CLAIM,
    IdentityAuthority,
    IdentityService,
)
from integration.journey.publication import AgenticRegistryClient, render_authoring
from integration.journey.registry import (
    REGISTRY_ORIGIN,
    JourneyCredentialProvider,
    JourneyRegistryTransport,
)
from tesserix_mcp_publisher import (
    EvidenceReference,
    PreparedPublication,
    PublicationEvidence,
    PublicationStatus,
    PublisherWorkflow,
    prepare_publication,
)

from tesserix_mcp_runtime import (
    AuthenticatedIdentity,
    CallContext,
    JsonValue,
    RegistryArtifactRaceError,
    RegistryResolver,
    RegistrySearchQuery,
    SecretValue,
)
from tesserix_mcp_runtime.adapters.registry_http import RegistryHTTPDiscovery

ROOT = Path(__file__).parents[2]
IMAGE_DIGEST = "sha256:" + "a" * 64


def _evidence() -> PublicationEvidence:
    return PublicationEvidence(
        artifact=EvidenceReference(
            uri="oci://ghcr.io/tesserix/tesserix-mcp-journey@" + IMAGE_DIGEST,
            digest=IMAGE_DIGEST,
            media_type="application/vnd.oci.image.manifest.v1+json",
        ),
        sbom=EvidenceReference(
            uri="https://evidence.journey.invalid/sbom.json",
            digest="sha256:" + "b" * 64,
            media_type="application/spdx+json",
        ),
        provenance=EvidenceReference(
            uri="https://evidence.journey.invalid/provenance.json",
            digest="sha256:" + "c" * 64,
            media_type="application/vnd.in-toto+json",
        ),
    )


def _context(*, tenant: str = "tenant-a") -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant=tenant,
            subject="journey-publisher",
            issuer="https://identity.journey.invalid",
            scopes=("registry:read", "registry:write"),
        ),
        request_id="request-registry-001",
        run_id="journey-run-001",
    )


def _runtime_context(*, tenant: str = "tenant-a") -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant=tenant,
            subject="journey-agent",
            issuer="https://identity.journey.invalid",
            scopes=("journey:approve", "journey:read", "journey:write"),
        ),
        request_id=f"request-discovery-{tenant}",
        run_id="journey-run-001",
    )


def _prepared() -> PreparedPublication:
    return prepare_publication(
        render_authoring(IMAGE_DIGEST),
        runtime_version="1.0.0",
        evidence=_evidence(),
    )


def test_render_authoring_binds_the_built_image_digest_canonically() -> None:
    source = ROOT / "integration" / "journey" / "authoring.json"

    rendered = render_authoring(IMAGE_DIGEST, source=source)
    document = cast(dict[str, JsonValue], json.loads(rendered))
    package = cast(dict[str, JsonValue], document["package"])

    assert package["image_digest"] == IMAGE_DIGEST
    assert b"sha256:" + b"0" * 64 not in rendered
    assert rendered == (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )


def test_render_authoring_binds_candidate_version_to_the_oci_identifier() -> None:
    rendered = render_authoring(IMAGE_DIGEST, version="1.0.1")
    document = cast(dict[str, JsonValue], json.loads(rendered))
    package = cast(dict[str, JsonValue], document["package"])

    assert document["version"] == "1.0.1"
    assert package["identifier"] == "ghcr.io/tesserix/tesserix-mcp-journey:1.0.1"


@pytest.mark.parametrize(
    "digest",
    [
        "sha256:" + "0" * 64,
        "sha256:" + "A" * 64,
        "latest",
    ],
    ids=["placeholder", "uppercase", "floating"],
)
def test_render_authoring_rejects_nonimmutable_image_identity(digest: str) -> None:
    with pytest.raises(ValueError, match="immutable image digest"):
        render_authoring(digest)


def test_rendered_authoring_prepares_with_real_manifest_and_publisher_components() -> None:
    prepared = prepare_publication(
        render_authoring(IMAGE_DIGEST),
        runtime_version="1.0.0",
        evidence=_evidence(),
    )
    registry = cast(dict[str, JsonValue], json.loads(prepared.registry_manifest))
    metadata = cast(dict[str, JsonValue], registry["metadata"])

    assert prepared.name == "io.github.tesserix/journey"
    assert prepared.namespace == "tenant-a"
    assert prepared.version == "1.0.0"
    assert prepared.ref == "mcpservers/tenant-a/io.github.tesserix/journey@1.0.0"
    assert prepared.evidence.artifact.digest == IMAGE_DIGEST
    assert metadata["visibility"] == "private"
    assert prepared.registry_digest.startswith("sha256:")


async def test_credential_provider_issues_only_for_the_exact_registry_audience() -> None:
    authority = IdentityAuthority(
        issuer="https://identity.journey.invalid",
        audience=REGISTRY_ORIGIN,
        now=lambda: 1_800_000_000,
    )
    service = IdentityService(authority)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=service),
        base_url="http://identity.test",
    ) as client:
        provider = JourneyCredentialProvider(
            token_origin="http://identity.test",
            audience=REGISTRY_ORIGIN,
            client=client,
        )
        credential = await provider.issue(
            audience=REGISTRY_ORIGIN,
            scopes=("registry:read", "registry:write"),
            context=_context(),
        )
        with pytest.raises(RuntimeError, match="credential_audience"):
            await provider.issue(
                audience="https://other.journey.invalid",
                scopes=("registry:read",),
                context=_context(),
            )

    public = cast(list[dict[str, object]], authority.jwks_document()["keys"])[0]
    claims = jwt.decode(
        credential.reveal(),
        key=jwt.PyJWK.from_dict(public).key,
        algorithms=["RS256"],
        issuer="https://identity.journey.invalid",
        audience=REGISTRY_ORIGIN,
        options={"verify_exp": False, "verify_iat": False, "verify_nbf": False},
    )
    assert claims["tenant_id"] == "tenant-a"
    assert claims["sub"] == "journey-publisher"
    assert claims["scope"] == "registry:read registry:write"
    assert claims["run_id"] == "journey-run-001"
    assert credential.reveal() not in repr(provider)


async def test_registry_transport_rewrites_only_the_fixed_synthetic_origin() -> None:
    seen: list[httpx.Request] = []

    def serve(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(transport=httpx.MockTransport(serve)) as client:
        transport = JourneyRegistryTransport(
            isolated_origin="http://registry:8080",
            client=client,
        )
        response = await transport.request(
            "GET",
            REGISTRY_ORIGIN + "/v0/search?q=orders",
            request_id="request-registry-001",
            headers={"authorization": SecretValue("Bearer synthetic-token")},
        )
        with pytest.raises(ValueError, match="synthetic Registry origin"):
            await transport.request(
                "GET",
                "https://other.journey.invalid/v0/search",
                request_id="request-registry-002",
            )

    assert response.status_code == 200
    assert len(seen) == 1
    assert str(seen[0].url) == "http://registry:8080/v0/search?q=orders"
    assert seen[0].headers["authorization"] == "Bearer synthetic-token"
    assert seen[0].headers["x-request-id"] == "request-registry-001"
    assert "synthetic-token" not in repr(response)


async def test_publisher_dry_runs_replays_and_verifies_the_exact_signed_artifact() -> None:
    prepared = _prepared()
    signing_key = Ed25519PrivateKey.generate()
    key_id = "journey-ed25519-001"
    signature = base64.b64encode(signing_key.sign(prepared.registry_digest.encode())).decode()
    artifact = cast(dict[str, JsonValue], json.loads(prepared.registry_manifest))
    metadata = cast(dict[str, JsonValue], artifact["metadata"])
    metadata.update(
        {
            "arn": "arn:agentic:tenant-a:MCPServer:io.github.tesserix/journey",
            "digest": prepared.registry_digest,
            "ref": prepared.ref,
            "signature": signature,
            "signedBy": key_id,
        }
    )
    export_body = yaml.safe_dump(
        {
            "apiVersion": "agentgateway.dev/v1alpha1",
            "kind": "AgentgatewayBackend",
            "metadata": {
                "name": "tenant-a-journey",
                "namespace": "agentgateway-system",
            },
            "spec": {},
        },
        sort_keys=True,
    ).encode()
    export_digest = "sha256:" + hashlib.sha256(export_body).hexdigest()
    seen: list[httpx.Request] = []

    def registry(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.headers["authorization"].startswith("Bearer ")
        if request.method == "POST" and request.url.path == "/v0/apply":
            assert request.content == prepared.registry_manifest
            applied = {
                "kind": "MCPServer",
                "name": prepared.name,
                "namespace": prepared.namespace,
                "tag": prepared.version,
                "created": True,
            }
            if request.url.params.get("dryRun") == "true":
                applied["created"] = False
                return httpx.Response(
                    200,
                    json={"applied": [applied], "count": 1, "dry_run": True},
                )
            assert request.headers["idempotency-key"] == "publication-run-001"
            return httpx.Response(200, json={"applied": [applied], "count": 1})
        if request.url.path.endswith("/revisions"):
            return httpx.Response(200, json=[{"revision": 1}])
        if request.url.path == "/v0/export/agentgateway":
            assert request.url.params["namespace"] == prepared.namespace
            assert request.url.params["legacyFlatPath"] == "false"
            require_server_scope = request.url.params["requireServerScope"]
            assert require_server_scope in {"false", "true"}
            if require_server_scope == "true":
                assert request.url.params["scopeClaim"] == ROUTE_SCOPE_CLAIM
            else:
                assert "scopeClaim" not in request.url.params
            return httpx.Response(
                200,
                content=export_body,
                headers={
                    "etag": f'"{export_digest}"',
                    "x-agentgateway-resource-count": "1",
                    "x-agentgateway-resource-digest": export_digest,
                },
            )
        if request.url.path == "/v0/signing-key":
            public = signing_key.public_key().public_bytes_raw()
            return httpx.Response(
                200,
                json={
                    "algorithm": "ed25519",
                    "enabled": True,
                    "encoding": "base64",
                    "keyId": key_id,
                    "publicKey": base64.b64encode(public).decode(),
                    "signs": "digest",
                },
            )
        assert request.url.path.endswith("/1.0.0")
        assert request.url.params["namespace"] == prepared.namespace
        return httpx.Response(200, json=artifact)

    authority = IdentityAuthority(
        issuer="https://identity.journey.invalid",
        audience=REGISTRY_ORIGIN,
        now=lambda: 1_800_000_000,
    )
    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=IdentityService(authority)),
            base_url="http://identity.test",
        ) as identity_client,
        httpx.AsyncClient(transport=httpx.MockTransport(registry)) as registry_client,
    ):
        credential_provider = JourneyCredentialProvider(
            token_origin="http://identity.test",
            audience=REGISTRY_ORIGIN,
            client=identity_client,
        )
        transport = JourneyRegistryTransport(
            isolated_origin="http://registry:8080",
            client=registry_client,
        )
        client = AgenticRegistryClient(
            transport=transport,
            credential_provider=credential_provider,
            context=_context(),
        )
        workflow = PublisherWorkflow(tesserix=client)
        dry_run = await workflow.execute(
            prepared,
            idempotency_key="publication-run-001",
            request_id="request-publish-dry-run",
            dry_run=True,
        )
        first = await workflow.execute(
            prepared,
            idempotency_key="publication-run-001",
            request_id="request-publish-first",
        )
        replay = await workflow.execute(
            prepared,
            idempotency_key="publication-run-001",
            request_id="request-publish-replay",
        )
        revisions = await client.revision_count(
            prepared,
            request_id="request-publish-revisions",
        )
        exported = await client.export_agentgateway(
            namespace=prepared.namespace,
            request_id="request-gateway-export",
            require_server_scope=True,
        )
        unscoped_export = await client.export_agentgateway(
            namespace=prepared.namespace,
            request_id="request-gateway-export-unscoped",
            require_server_scope=False,
        )

    assert dry_run.status is PublicationStatus.DRY_RUN
    assert first.status is replay.status is PublicationStatus.VERIFIED
    assert first.created is replay.created is True
    assert first.digest == replay.digest == prepared.registry_digest
    assert revisions == 1
    assert exported.resource_count == 1
    assert exported.digest == export_digest
    assert unscoped_export.resource_count == 1
    assert unscoped_export.digest == export_digest
    assert sum(request.method == "POST" for request in seen) == 3


async def test_real_registry_resolver_selects_owner_semantics_and_hides_other_tenant() -> None:
    prepared = _prepared()
    artifact = cast(dict[str, JsonValue], json.loads(prepared.registry_manifest))
    metadata = cast(dict[str, JsonValue], artifact["metadata"])
    labels = cast(dict[str, str], metadata["labels"])
    labels.update(
        {
            "registry.agentic.dev/tenant": prepared.namespace,
            "registry.agentic.dev/org": "tesserix",
            "registry.agentic.dev/visibility": "private",
        }
    )
    arn = "arn:agentic:tenant-a:MCPServer:io.github.tesserix/journey"
    metadata.update(
        {
            "arn": arn,
            "digest": prepared.registry_digest,
            "ref": prepared.ref,
        }
    )
    annotations = cast(dict[str, str], metadata["annotations"])
    fetch_path = "/v0/mcpservers/io.github.tesserix%2Fjourney/1.0.0?namespace=tenant-a"
    stub = {
        "annotations": annotations,
        "arn": arn,
        "attributes": {
            "capabilities": [
                "cap/deadline-proof",
                "cap/order-approval",
                "cap/order-read",
                "cap/order-write",
                "cap/redaction-proof",
                "cap/safe-failure",
            ]
        },
        "description": "Exercise the complete tenant-scoped MCP release lifecycle.",
        "digest": prepared.registry_digest,
        "fetchPath": fetch_path,
        "kind": "MCPServer",
        "labels": labels,
        "name": prepared.name,
        "namespace": prepared.namespace,
        "ref": prepared.ref,
        "tag": prepared.version,
        "title": "Tesserix MCP release journey",
        "visibility": "private",
    }
    search_tenants: list[str] = []

    def registry(request: httpx.Request) -> httpx.Response:
        raw_token = request.headers["authorization"].removeprefix("Bearer ")
        claims = jwt.decode(raw_token, options={"verify_signature": False})
        tenant = cast(str, claims["tenant_id"])
        if request.url.path == "/v0/search":
            search_tenants.append(tenant)
            assert request.url.params["q"] == "read a known synthetic order"
            assert request.url.params["view"] == "stub"
            return httpx.Response(200, json=[stub] if tenant == "tenant-a" else [])
        if tenant != "tenant-a":
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json=artifact)

    authority = IdentityAuthority(
        issuer="https://identity.journey.invalid",
        audience=REGISTRY_ORIGIN,
        now=lambda: 1_800_000_000,
    )
    async with (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=IdentityService(authority)),
            base_url="http://identity.test",
        ) as identity_client,
        httpx.AsyncClient(transport=httpx.MockTransport(registry)) as registry_client,
    ):
        provider = JourneyCredentialProvider(
            token_origin="http://identity.test",
            audience=REGISTRY_ORIGIN,
            client=identity_client,
        )
        discovery = RegistryHTTPDiscovery(
            origin=REGISTRY_ORIGIN,
            transport=JourneyRegistryTransport(
                isolated_origin="http://registry:8080",
                client=registry_client,
            ),
            credential_provider=provider,
        )
        query = RegistrySearchQuery(
            intent="read a known synthetic order",
            namespace="tenant-a",
            limit=5,
        )
        owner = await RegistryResolver(discovery=discovery).resolve(
            query,
            policy=journey_read_policy(prepared),
            context=_runtime_context(),
        )
        other = await RegistryResolver(discovery=discovery).resolve(
            query,
            policy=journey_read_policy(prepared),
            context=_runtime_context(tenant="tenant-b"),
        )
        owner_stub = (await discovery.search(query, context=_runtime_context()))[0]
        with pytest.raises(RegistryArtifactRaceError):
            await discovery.fetch(
                owner_stub,
                context=_runtime_context(tenant="tenant-b"),
            )

    assert owner.server is not None
    assert owner.server.endpoint == (
        "https://gateway.journey.invalid/mcp/tenant-a/io-github-tesserix-journey"
    )
    assert owner.server.allow == ("journey.read_order",)
    assert owner.server.artifact_ref == prepared.ref
    assert owner.server.artifact_digest == prepared.registry_digest
    assert other.server is None
    assert search_tenants == ["tenant-a", "tenant-b", "tenant-a"]
