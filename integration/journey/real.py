from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import AsyncIterator, Awaitable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, PaginatedRequestParams
from tesserix_mcp_publisher import (
    PreparedPublication,
    PublicationEvidence,
    PublicationStatus,
    PublisherWorkflow,
    prepare_publication,
)
from tesserix_mcp_testkit import (
    JourneyArtifact,
    JourneyAssertion,
    JourneyComponent,
    JourneyEvidence,
    make_journey_assertion,
)

from integration.journey.backing import JOURNEY_CANARY
from integration.journey.discovery import journey_read_policy
from integration.journey.gateway import render_standalone_gateway_config
from integration.journey.publication import AgenticRegistryClient, render_authoring
from integration.journey.reference_server import JOURNEY_APPROVAL_ID
from integration.journey.registry import (
    REGISTRY_ORIGIN,
    JourneyCredentialProvider,
    JourneyRegistryTransport,
    decode_json_object,
)
from integration.journey.runner import (
    JourneyRunError,
    MCPAuthority,
    create_publication_evidence,
    decode_failure,
    decode_success,
    has_backing_correlation,
)
from integration.journey.stack import ComposeStack
from tesserix_mcp_runtime import (
    AuthenticatedIdentity,
    CallContext,
    JsonValue,
    RegistryArtifact,
    RegistryArtifactRaceError,
    RegistryResolver,
    RegistrySearchQuery,
    RegistrySearchStub,
)
from tesserix_mcp_runtime.adapters.registry_http import RegistryHTTPDiscovery

REGISTRY_COMMIT = "6921474591b6c59e89025370c310c7f85859246f"
GATEWAY_IMAGE = (
    "cr.agentgateway.dev/agentgateway:v1.4.1@"
    "sha256:efd79355b89094a8225a9db465d9a01dc656b377f0bab458761b935a13231d29"
)
GATEWAY_DIGEST = "sha256:efd79355b89094a8225a9db465d9a01dc656b377f0bab458761b935a13231d29"
TRACE_ID = "1" * 32
TRACEPARENT = f"00-{TRACE_ID}-{'2' * 16}-01"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TIMESTAMP = re.compile(
    r"(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
_EXPECTED_TOOLS = frozenset(
    {
        "journey.approve_order",
        "journey.fail",
        "journey.read_order",
        "journey.secret_canary",
        "journey.slow",
        "journey.write_order",
    }
)
_MAX_HTTP_DOCUMENT_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True, kw_only=True)
class RealJourneyConfig:
    output_dir: Path
    runtime_artifact_digest: str
    run_id: str
    created_at: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.output_dir, Path)
            or not self.output_dir.is_absolute()
            or not self.output_dir.is_dir()
            or not isinstance(self.runtime_artifact_digest, str)
            or _DIGEST.fullmatch(self.runtime_artifact_digest) is None
            or not isinstance(self.run_id, str)
            or _RUN_ID.fullmatch(self.run_id) is None
            or not isinstance(self.created_at, str)
            or _TIMESTAMP.fullmatch(self.created_at) is None
        ):
            raise ValueError("real journey configuration is invalid")


def _context(
    *,
    tenant: str,
    subject: str,
    scopes: tuple[str, ...],
    request_id: str,
    run_id: str,
) -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant=tenant,
            subject=subject,
            issuer="https://identity.journey.invalid",
            scopes=scopes,
        ),
        request_id=request_id,
        run_id=run_id,
    )


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )


def _json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_value(item) for item in value]
    raise JourneyRunError("surface_invalid")


def _stub_document(stub: RegistrySearchStub) -> dict[str, JsonValue]:
    return {
        "annotations": _json_value(stub.annotations),
        "arn": stub.arn,
        "attributes": _json_value(stub.attributes),
        "description": stub.description,
        "digest": stub.digest,
        "fetch_path": stub.fetch_path,
        "kind": stub.kind,
        "labels": _json_value(stub.labels),
        "name": stub.name,
        "namespace": stub.namespace,
        "ref": stub.ref,
        "tag": stub.tag,
        "title": stub.title,
        "visibility": stub.visibility,
    }


def _artifact_document(artifact: RegistryArtifact) -> dict[str, JsonValue]:
    return {
        "apiVersion": artifact.api_version,
        "kind": artifact.kind,
        "metadata": {
            "arn": artifact.arn,
            "digest": artifact.digest,
            "labels": _json_value(artifact.labels),
            "name": artifact.name,
            "namespace": artifact.namespace,
            "ref": artifact.ref,
            "tag": artifact.tag,
        },
        "spec": _json_value(artifact.spec),
    }


async def _wait_status(
    origin: str,
    path: str,
    expected: frozenset[int],
    *,
    timeout_seconds: float = 30.0,
) -> httpx.Response:
    deadline = time.monotonic() + timeout_seconds
    async with httpx.AsyncClient(follow_redirects=False, timeout=2.0) as client:
        while True:
            try:
                response = await client.get(origin + path)
                if response.status_code in expected:
                    if len(response.content) > _MAX_HTTP_DOCUMENT_BYTES:
                        raise JourneyRunError("http_response_too_large")
                    return response
            except httpx.HTTPError:
                pass
            if time.monotonic() >= deadline:
                raise JourneyRunError("service_unavailable")
            await asyncio.sleep(0.05)


@asynccontextmanager
async def _mcp_session(
    endpoint: str,
    authority: MCPAuthority,
    *,
    request_id: str,
    timeout_ms: int,
    idempotency_key: str | None = None,
    approval_id: str | None = None,
) -> AsyncIterator[ClientSession]:
    headers = authority.headers(
        request_id=request_id,
        traceparent=TRACEPARENT,
        timeout_ms=timeout_ms,
        idempotency_key=idempotency_key,
        approval_id=approval_id,
    )
    timeout = max(5.0, timeout_ms / 1_000 + 2.0)
    async with (
        httpx2.AsyncClient(headers=headers, follow_redirects=False, timeout=timeout) as http_client,
        streamable_http_client(
            endpoint,
            http_client=http_client,
            terminate_on_close=False,
        ) as streams,
        ClientSession(streams[0], streams[1]) as session,
    ):
        yield session


async def _probe(
    endpoint: str,
    authority: MCPAuthority,
    *,
    request_id: str,
) -> tuple[str, frozenset[str]]:
    async with _mcp_session(
        endpoint,
        authority,
        request_id=request_id,
        timeout_ms=5_000,
    ) as session:
        initialized = await session.initialize()
        names: set[str] = set()
        cursor: str | None = None
        for _ in range(4):
            params = None if cursor is None else PaginatedRequestParams(cursor=cursor)
            listed = await session.list_tools(params=params)
            names.update(tool.name for tool in listed.tools)
            cursor = listed.next_cursor
            if cursor is None:
                return str(initialized.protocol_version), frozenset(names)
        raise JourneyRunError("tool_pagination_unbounded")


async def _wait_probe(
    endpoint: str,
    authority: MCPAuthority,
    *,
    request_id: str,
    timeout_seconds: float = 30.0,
) -> tuple[str, frozenset[str]]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            return await _probe(endpoint, authority, request_id=request_id)
        except Exception:
            if time.monotonic() >= deadline:
                raise JourneyRunError("gateway_probe_unavailable") from None
            await asyncio.sleep(0.05)


async def _wait_reachable(origin: str, path: str, *, timeout_seconds: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    async with httpx.AsyncClient(follow_redirects=False, timeout=2.0) as client:
        while True:
            try:
                response = await client.get(origin + path)
                if 100 <= response.status_code <= 599:
                    return
            except httpx.HTTPError:
                pass
            if time.monotonic() >= deadline:
                raise JourneyRunError("gateway_unavailable")
            await asyncio.sleep(0.05)


async def _invoke(
    endpoint: str,
    authority: MCPAuthority,
    *,
    request_id: str,
    tool_name: str,
    arguments: dict[str, JsonValue],
    timeout_ms: int = 2_000,
    idempotency_key: str | None = None,
    approval_id: str | None = None,
) -> CallToolResult:
    async with _mcp_session(
        endpoint,
        authority,
        request_id=request_id,
        timeout_ms=timeout_ms,
        idempotency_key=idempotency_key,
        approval_id=approval_id,
    ) as session:
        await session.initialize()
        result = await session.call_tool(tool_name, arguments)
    if not isinstance(result, CallToolResult):
        raise JourneyRunError("tool_result_invalid")
    return result


async def _invoke_twice(
    endpoint: str,
    authority: MCPAuthority,
    *,
    request_id: str,
    tool_name: str,
    arguments: dict[str, JsonValue],
    idempotency_key: str,
) -> tuple[CallToolResult, CallToolResult]:
    async with _mcp_session(
        endpoint,
        authority,
        request_id=request_id,
        timeout_ms=2_000,
        idempotency_key=idempotency_key,
    ) as session:
        await session.initialize()
        first = await session.call_tool(tool_name, arguments)
        replay = await session.call_tool(tool_name, arguments)
    if not isinstance(first, CallToolResult) or not isinstance(replay, CallToolResult):
        raise JourneyRunError("tool_result_invalid")
    return first, replay


async def _is_rejected(operation: Awaitable[object]) -> bool:
    try:
        await operation
    except Exception:
        return True
    return False


async def _backing_document(origin: str) -> dict[str, object]:
    response = await _wait_status(origin, "/control/observations", frozenset({200}))
    return dict(decode_json_object(response.content, maximum=_MAX_HTTP_DOCUMENT_BYTES))


async def _set_backing_availability(origin: str, available: bool) -> None:
    async with httpx.AsyncClient(follow_redirects=False, timeout=5.0) as client:
        response = await client.put(origin + "/control/availability", json={"available": available})
    if response.status_code != 200 or len(response.content) > 4_096:
        raise JourneyRunError("backing_control_failed")
    document = decode_json_object(response.content, maximum=4_096)
    if document != {"available": available}:
        raise JourneyRunError("backing_control_failed")


async def _wait_in_flight(origin: str, operation: asyncio.Task[CallToolResult]) -> bytes:
    deadline = time.monotonic() + 5.0
    while True:
        if operation.done():
            raise JourneyRunError("in_flight_call_not_observed")
        response = await _wait_status(origin, "/metrics", frozenset({200}), timeout_seconds=1.0)
        metrics = response.content
        if b'mcp_tool_in_flight{server="journey-mcp",tool="journey.slow"} 1' in metrics:
            return metrics
        if time.monotonic() >= deadline:
            raise JourneyRunError("in_flight_call_not_observed")
        await asyncio.sleep(0.02)


def _record(
    assertions: list[JourneyAssertion],
    *,
    code: str,
    started: float,
    request_id: str,
    known_good: JourneyArtifact,
    trace_id: str = "",
) -> None:
    elapsed_ms = min(600_000, max(0, int((time.monotonic() - started) * 1_000)))
    assertions.append(
        make_journey_assertion(
            code=code,
            passed=True,
            elapsed_ms=elapsed_ms,
            request_id=request_id,
            trace_id=trace_id,
            known_good=known_good,
        )
    )


def _prepare(
    *,
    config: RealJourneyConfig,
    evidence: PublicationEvidence,
    version: str,
) -> PreparedPublication:
    return prepare_publication(
        render_authoring(config.runtime_artifact_digest, version=version),
        runtime_version=version,
        evidence=evidence,
    )


async def run_real_journey(
    config: RealJourneyConfig,
    *,
    stack: ComposeStack,
) -> JourneyEvidence:
    if not isinstance(config, RealJourneyConfig) or not isinstance(stack, ComposeStack):
        raise TypeError("real journey requires validated configuration and stack")
    assertions: list[JourneyAssertion] = []
    surfaces: dict[str, bytes] = {}
    results: dict[str, JsonValue] = {}
    stack.validate()
    stack.up("identity", "backing", "runtime-good", "runtime-bad", "registry")
    identity_origin = stack.origin("identity", 8081)
    backing_origin = stack.origin("backing", 8082)
    registry_origin = stack.origin("registry", 8080)
    runtime_origin = stack.origin("runtime-good", 8080)
    await _wait_status(identity_origin, "/health", frozenset({200}))
    await _wait_status(backing_origin, "/health/ready", frozenset({200}))
    await _wait_status(registry_origin, "/v0/health", frozenset({200}))
    await _wait_status(runtime_origin, "/readyz", frozenset({200}))

    publication_evidence = create_publication_evidence(
        output_dir=config.output_dir,
        artifact_digest=config.runtime_artifact_digest,
        created_at=config.created_at,
    )
    prepared = _prepare(
        config=config,
        evidence=publication_evidence,
        version="1.0.0",
    )
    candidate = _prepare(
        config=config,
        evidence=publication_evidence,
        version="1.0.1",
    )
    known_good = JourneyArtifact(
        ref=prepared.ref,
        registry_digest=prepared.registry_digest,
        artifact_digest=config.runtime_artifact_digest,
        version=prepared.version,
    )
    publisher_context = _context(
        tenant="tenant-a",
        subject="subject-a",
        scopes=("registry:read", "registry:write"),
        request_id="request-publisher-context",
        run_id=config.run_id,
    )
    owner_context = _context(
        tenant="tenant-a",
        subject="subject-a",
        scopes=("journey:approve", "journey:read", "journey:write"),
        request_id="request-discovery-owner",
        run_id=config.run_id,
    )
    other_context = _context(
        tenant="tenant-b",
        subject="subject-b",
        scopes=("journey:approve", "journey:read", "journey:write"),
        request_id="request-discovery-other",
        run_id=config.run_id,
    )

    async with (
        httpx.AsyncClient(
            base_url=identity_origin, follow_redirects=False, timeout=10.0
        ) as identity,
        httpx.AsyncClient(follow_redirects=False, timeout=10.0) as registry_http,
    ):
        credentials = JourneyCredentialProvider(
            token_origin=identity_origin,
            audience=REGISTRY_ORIGIN,
            client=identity,
        )
        transport = JourneyRegistryTransport(
            isolated_origin=registry_origin,
            client=registry_http,
        )
        registry = AgenticRegistryClient(
            transport=transport,
            credential_provider=credentials,
            context=publisher_context,
        )
        workflow = PublisherWorkflow(tesserix=registry)

        started = time.monotonic()
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
        if (
            dry_run.status is not PublicationStatus.DRY_RUN
            or first.status is not PublicationStatus.VERIFIED
            or first.digest != prepared.registry_digest
        ):
            raise JourneyRunError("publication_invalid")
        _record(
            assertions,
            code="publication.immutable",
            started=started,
            request_id="request-publish-first",
            known_good=known_good,
        )

        started = time.monotonic()
        replay = await workflow.execute(
            prepared,
            idempotency_key="publication-run-001",
            request_id="request-publish-replay",
        )
        revisions = await registry.revision_count(
            prepared,
            request_id="request-publish-revisions",
        )
        if (
            replay.status is not PublicationStatus.VERIFIED
            or replay.created != first.created
            or replay.digest != first.digest
            or revisions != 1
        ):
            raise JourneyRunError("publication_replay_invalid")
        _record(
            assertions,
            code="publication.replay",
            started=started,
            request_id="request-publish-replay",
            known_good=known_good,
        )

        discovery = RegistryHTTPDiscovery(
            origin=REGISTRY_ORIGIN,
            transport=transport,
            credential_provider=credentials,
        )
        query = RegistrySearchQuery(
            intent="tenant-scoped MCP release lifecycle",
            namespace="tenant-a",
            limit=5,
        )
        started = time.monotonic()
        stubs = await discovery.search(query, context=owner_context)
        owner = await RegistryResolver(discovery=discovery).resolve(
            query,
            policy=journey_read_policy(prepared),
            context=owner_context,
        )
        if len(stubs) != 1:
            raise JourneyRunError("semantic_search_count_invalid")
        if owner.server is None:
            reasons = sorted(
                reason.value for explanation in owner.explanations for reason in explanation.reasons
            )
            suffix = reasons[0] if reasons else "unknown"
            raise JourneyRunError("semantic_resolution_rejected_" + suffix)
        stub = stubs[0]
        if owner.server.artifact_digest != prepared.registry_digest:
            raise JourneyRunError("semantic_resolution_digest_invalid")
        _record(
            assertions,
            code="discovery.semantic_match",
            started=started,
            request_id="request-discovery-owner",
            known_good=known_good,
        )

        started = time.monotonic()
        artifact = await discovery.fetch(stub, context=owner_context)
        if (
            artifact.digest != prepared.registry_digest
            or artifact.computed_digest != prepared.registry_digest
        ):
            raise JourneyRunError("exact_fetch_invalid")
        _record(
            assertions,
            code="discovery.exact_fetch",
            started=started,
            request_id="request-discovery-exact",
            known_good=known_good,
        )

        started = time.monotonic()
        other = await RegistryResolver(discovery=discovery).resolve(
            query,
            policy=journey_read_policy(prepared),
            context=other_context,
        )
        exact_hidden = False
        try:
            await discovery.fetch(stub, context=other_context)
        except RegistryArtifactRaceError:
            exact_hidden = True
        if other.server is not None or not exact_hidden:
            raise JourneyRunError("tenant_search_disclosed")
        _record(
            assertions,
            code="tenant.search_non_disclosure",
            started=started,
            request_id="request-discovery-other",
            known_good=known_good,
        )

        exported = await registry.export_agentgateway(
            namespace=prepared.namespace,
            request_id="request-gateway-export",
        )
        good_config = render_standalone_gateway_config(
            exported,
            upstream_url="http://runtime-good:8080/mcp",
            issuer="https://identity.journey.invalid",
            audience=REGISTRY_ORIGIN,
            jwks_url="http://identity:8081/jwks.json",
        )
        candidate_config = render_standalone_gateway_config(
            exported,
            upstream_url="http://runtime-bad:8080/mcp",
            issuer="https://identity.journey.invalid",
            audience=REGISTRY_ORIGIN,
            jwks_url="http://identity:8081/jwks.json",
        )
        (config.output_dir / "gateway-good.yaml").write_bytes(good_config)
        (config.output_dir / "gateway-candidate.yaml").write_bytes(candidate_config)
        surfaces.update(
            {
                "agentgateway-export.yaml": exported.body,
                "gateway-candidate.yaml": candidate_config,
                "gateway-good.yaml": good_config,
                "registry-artifact.json": _canonical_json(_artifact_document(artifact)),
                "registry-candidate.json": candidate.registry_manifest,
                "registry-good.json": prepared.registry_manifest,
                "registry-stub.json": _canonical_json(_stub_document(stub)),
            }
        )

        stack.up("gateway-good")
        gateway_origin = stack.origin("gateway-good", 3000)
        gateway_path = urlsplit(owner.server.endpoint).path
        if gateway_path != "/mcp/tenant-a/io-github-tesserix-journey":
            raise JourneyRunError("gateway_path_invalid")
        endpoint = gateway_origin + gateway_path
        runtime_token = await credentials.issue(
            audience=REGISTRY_ORIGIN,
            scopes=("journey:approve", "journey:read", "journey:write"),
            context=_context(
                tenant="tenant-a",
                subject="subject-a",
                scopes=("journey:approve", "journey:read", "journey:write"),
                request_id="request-runtime-token",
                run_id=config.run_id,
            ),
        )
        authority = MCPAuthority(token=runtime_token, run_id=config.run_id)

        started = time.monotonic()
        protocol, tools = await _wait_probe(
            endpoint,
            authority,
            request_id="request-gateway-probe",
        )
        if protocol != "2025-11-25" or tools != _EXPECTED_TOOLS:
            raise JourneyRunError("gateway_probe_invalid")
        _record(
            assertions,
            code="activation.route_accepted",
            started=started,
            request_id="request-gateway-probe",
            known_good=known_good,
        )
        _record(
            assertions,
            code="activation.authenticated_probe",
            started=started,
            request_id="request-gateway-probe",
            known_good=known_good,
        )

        started = time.monotonic()
        read = decode_success(
            await _invoke(
                endpoint,
                authority,
                request_id="request-read-001",
                tool_name="journey.read_order",
                arguments={"order_id": "order-001"},
            )
        )
        if read != {"order_id": "order-001", "status": "missing"}:
            raise JourneyRunError("structured_result_invalid")
        results["read"] = read
        _record(
            assertions,
            code="invocation.structured_result",
            started=started,
            request_id="request-read-001",
            trace_id=TRACE_ID,
            known_good=known_good,
        )

        started = time.monotonic()
        write_first, write_replay = await _invoke_twice(
            endpoint,
            authority,
            request_id="request-write-001",
            tool_name="journey.write_order",
            arguments={"order_id": "order-001", "status": "created"},
            idempotency_key="write-order-001",
        )
        first_value = decode_success(write_first)
        replay_value = decode_success(write_replay)
        backing_after_write = await _backing_document(backing_origin)
        if first_value != replay_value or backing_after_write.get("effect_count") != 1:
            raise JourneyRunError("write_replay_invalid")
        results["write"] = first_value
        results["write_replay"] = replay_value
        _record(
            assertions,
            code="invocation.write_replay",
            started=started,
            request_id="request-write-001",
            trace_id=TRACE_ID,
            known_good=known_good,
        )

        started = time.monotonic()
        approval_denied = decode_failure(
            await _invoke(
                endpoint,
                authority,
                request_id="request-approval-denied",
                tool_name="journey.approve_order",
                arguments={"order_id": "order-001"},
                idempotency_key="approve-order-001",
            )
        )
        approval_allowed = decode_success(
            await _invoke(
                endpoint,
                authority,
                request_id="request-approval-allowed",
                tool_name="journey.approve_order",
                arguments={"order_id": "order-001"},
                idempotency_key="approve-order-001",
                approval_id=JOURNEY_APPROVAL_ID,
            )
        )
        if approval_denied != "approval_required" or approval_allowed.get("status") != "approved":
            raise JourneyRunError("approval_invalid")
        results["approval_denied"] = approval_denied
        results["approval_allowed"] = approval_allowed
        _record(
            assertions,
            code="invocation.approval_required",
            started=started,
            request_id="request-approval-allowed",
            trace_id=TRACE_ID,
            known_good=known_good,
        )

        started = time.monotonic()
        safe_failure = decode_failure(
            await _invoke(
                endpoint,
                authority,
                request_id="request-safe-failure",
                tool_name="journey.fail",
                arguments={},
            )
        )
        if safe_failure != "internal_failure":
            raise JourneyRunError("safe_failure_invalid")
        results["safe_failure"] = safe_failure
        _record(
            assertions,
            code="invocation.safe_failure",
            started=started,
            request_id="request-safe-failure",
            trace_id=TRACE_ID,
            known_good=known_good,
        )

        started = time.monotonic()
        deadline_failure = decode_failure(
            await _invoke(
                endpoint,
                authority,
                request_id="request-deadline",
                tool_name="journey.slow",
                arguments={"delay_ms": 200},
                timeout_ms=20,
            )
        )
        if deadline_failure != "timeout":
            raise JourneyRunError("deadline_invalid")
        results["deadline"] = deadline_failure
        _record(
            assertions,
            code="invocation.deadline",
            started=started,
            request_id="request-deadline",
            trace_id=TRACE_ID,
            known_good=known_good,
        )

        started = time.monotonic()
        canary_result = decode_success(
            await _invoke(
                endpoint,
                authority,
                request_id="request-canary",
                tool_name="journey.secret_canary",
                arguments={},
            )
        )
        if canary_result != {"api_key": "[REDACTED]"}:
            raise JourneyRunError("redaction_invalid")
        results["redaction"] = canary_result
        _record(
            assertions,
            code="redaction.canary_absent",
            started=started,
            request_id="request-canary",
            trace_id=TRACE_ID,
            known_good=known_good,
        )

        started = time.monotonic()
        other_token = await credentials.issue(
            audience=REGISTRY_ORIGIN,
            scopes=("journey:approve", "journey:read", "journey:write"),
            context=_context(
                tenant="tenant-b",
                subject="subject-b",
                scopes=("journey:approve", "journey:read", "journey:write"),
                request_id="request-runtime-token-other",
                run_id=config.run_id,
            ),
        )
        other_authority = MCPAuthority(token=other_token, run_id=config.run_id)
        if not await _is_rejected(
            _probe(endpoint, other_authority, request_id="request-tenant-other")
        ):
            raise JourneyRunError("tenant_invocation_disclosed")
        _record(
            assertions,
            code="tenant.invocation_non_disclosure",
            started=started,
            request_id="request-tenant-other",
            known_good=known_good,
        )

        backing_state = await _backing_document(backing_origin)
        runtime_logs = stack.logs("runtime-good")
        metrics_response = await _wait_status(runtime_origin, "/metrics", frozenset({200}))
        metrics = metrics_response.content
        if b'"event":"audit"' not in runtime_logs or JOURNEY_CANARY.encode() in runtime_logs:
            raise JourneyRunError("audit_invalid")
        started = time.monotonic()
        _record(
            assertions,
            code="observability.audit",
            started=started,
            request_id="request-observability-audit",
            trace_id=TRACE_ID,
            known_good=known_good,
        )
        observations = backing_state.get("observations")
        if (
            not has_backing_correlation(
                observations,
                request_id="request-write-001",
                trace_id=TRACE_ID,
            )
            or b"mcp_server_request_count_total" not in metrics
            or b"request-write-001" in metrics
            or JOURNEY_CANARY.encode() in metrics
        ):
            raise JourneyRunError("correlation_invalid")
        _record(
            assertions,
            code="observability.correlation",
            started=started,
            request_id="request-observability-correlation",
            trace_id=TRACE_ID,
            known_good=known_good,
        )

        await workflow.execute(
            candidate,
            idempotency_key="publication-run-002",
            request_id="request-publish-candidate",
        )
        stack.up("gateway-candidate")
        candidate_origin = stack.origin("gateway-candidate", 3000)
        candidate_endpoint = candidate_origin + gateway_path
        await _wait_reachable(candidate_origin, gateway_path)
        started = time.monotonic()
        in_flight = asyncio.create_task(
            _invoke(
                endpoint,
                authority,
                request_id="request-in-flight",
                tool_name="journey.slow",
                arguments={"delay_ms": 500},
                timeout_ms=1_500,
            )
        )
        try:
            await _wait_in_flight(runtime_origin, in_flight)
            if not await _is_rejected(
                _probe(
                    candidate_endpoint,
                    authority,
                    request_id="request-candidate-probe",
                )
            ):
                raise JourneyRunError("candidate_probe_succeeded")
            completed_in_flight = decode_success(await in_flight)
        finally:
            if not in_flight.done():
                in_flight.cancel()
                await asyncio.gather(in_flight, return_exceptions=True)
        if completed_in_flight != {"slept_ms": 500}:
            raise JourneyRunError("in_flight_call_invalid")
        _record(
            assertions,
            code="activation.bad_probe_rejected",
            started=started,
            request_id="request-candidate-probe",
            known_good=known_good,
        )
        rollback_read = decode_success(
            await _invoke(
                endpoint,
                authority,
                request_id="request-rollback-good",
                tool_name="journey.read_order",
                arguments={"order_id": "order-001"},
            )
        )
        if rollback_read.get("status") != "approved":
            raise JourneyRunError("rollback_invalid")
        _record(
            assertions,
            code="rollback.known_good",
            started=started,
            request_id="request-rollback-good",
            known_good=known_good,
        )

        started = time.monotonic()
        stack.stop("registry")
        registry_outage_read = decode_success(
            await _invoke(
                endpoint,
                authority,
                request_id="request-registry-outage",
                tool_name="journey.read_order",
                arguments={"order_id": "order-001"},
            )
        )
        if registry_outage_read.get("status") != "approved":
            raise JourneyRunError("registry_outage_invalid")
        _record(
            assertions,
            code="outage.registry_last_known_good",
            started=started,
            request_id="request-registry-outage",
            known_good=known_good,
        )
        registry_origin = stack.start_and_resolve_origin("registry", 8080)
        await _wait_status(registry_origin, "/v0/health", frozenset({200}))

        started = time.monotonic()
        stack.stop("gateway-good")
        if not await _is_rejected(_probe(endpoint, authority, request_id="request-gateway-outage")):
            raise JourneyRunError("gateway_outage_invalid")
        _record(
            assertions,
            code="outage.gateway_visible",
            started=started,
            request_id="request-gateway-outage",
            known_good=known_good,
        )
        gateway_origin = stack.start_and_resolve_origin("gateway-good", 3000)
        endpoint = gateway_origin + gateway_path
        protocol, tools = await _wait_probe(
            endpoint,
            authority,
            request_id="request-gateway-restored",
        )
        if protocol != "2025-11-25" or tools != _EXPECTED_TOOLS:
            raise JourneyRunError("gateway_restore_invalid")

        started = time.monotonic()
        effect_count_before_outage = (await _backing_document(backing_origin)).get("effect_count")
        await _set_backing_availability(backing_origin, False)
        backing_failure = decode_failure(
            await _invoke(
                endpoint,
                authority,
                request_id="request-backing-outage",
                tool_name="journey.read_order",
                arguments={"order_id": "order-001"},
            )
        )
        if backing_failure != "unavailable":
            raise JourneyRunError("backing_outage_invalid")
        await _set_backing_availability(backing_origin, True)
        restored = decode_success(
            await _invoke(
                endpoint,
                authority,
                request_id="request-backing-restored",
                tool_name="journey.read_order",
                arguments={"order_id": "order-001"},
            )
        )
        final_backing = await _backing_document(backing_origin)
        if (
            restored.get("status") != "approved"
            or final_backing.get("effect_count") != effect_count_before_outage
        ):
            raise JourneyRunError("backing_restore_invalid")
        _record(
            assertions,
            code="outage.backing_visible",
            started=started,
            request_id="request-backing-outage",
            known_good=known_good,
        )

    surfaces["backing-observations.json"] = _canonical_json(final_backing)
    surfaces["results.json"] = _canonical_json(results)
    surfaces["runtime-metrics.prom"] = metrics
    for service in (
        "backing",
        "gateway-candidate",
        "gateway-good",
        "identity",
        "registry",
        "runtime-bad",
        "runtime-good",
    ):
        surfaces[f"logs/{service}.log"] = stack.logs(service)
    evidence = JourneyEvidence(
        run_id=config.run_id,
        created_at=config.created_at,
        components=(
            JourneyComponent(
                name="agentgateway",
                version="1.4.1",
                revision=GATEWAY_DIGEST,
            ),
            JourneyComponent(
                name="agentic-registry",
                version="6921474",
                revision=REGISTRY_COMMIT,
            ),
            JourneyComponent(
                name="tesserix-mcp-runtime",
                version="1.0.0",
                revision=config.runtime_artifact_digest,
            ),
        ),
        known_good=known_good,
        assertions=tuple(assertions),
    )
    encoded = evidence.to_json(
        surfaces=tuple(surfaces.values()),
        canaries=(JOURNEY_CANARY,),
    )
    for relative, body in surfaces.items():
        target = config.output_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
    (config.output_dir / "journey-evidence.json").write_bytes(encoded)
    return evidence


__all__ = [
    "GATEWAY_DIGEST",
    "GATEWAY_IMAGE",
    "REGISTRY_COMMIT",
    "RealJourneyConfig",
    "run_real_journey",
]
