from __future__ import annotations

import json
from collections.abc import Mapping
from typing import cast

import httpx
import jwt
import pytest
from integration.journey.backing import (
    JOURNEY_CANARY,
    BackingConflict,
    BackingContext,
    BackingService,
    BackingStore,
    BackingUnavailable,
)
from integration.journey.identity import IdentityAuthority, IdentityService, TokenRequest

from tesserix_mcp_runtime import JsonValue, SecretValue

NOW = 1_800_000_000
ISSUER = "https://identity.journey.invalid"
AUDIENCE = "tesserix-mcp-journey"


def _context(
    *,
    tenant: str = "tenant-a",
    idempotency_key: str | None = "write-order-001",
) -> BackingContext:
    return BackingContext(
        tenant=tenant,
        subject="subject-a",
        scopes=("journey:read", "journey:write", "journey:approve"),
        request_id="request-backing-001",
        trace_id="1" * 32,
        idempotency_key=idempotency_key,
    )


def _authority() -> IdentityAuthority:
    return IdentityAuthority(
        issuer=ISSUER,
        audience=AUDIENCE,
        now=lambda: NOW,
        token_ttl_seconds=300,
    )


def test_identity_authority_issues_short_lived_tenant_scoped_rs256_tokens() -> None:
    authority = _authority()
    request = TokenRequest(
        tenant="tenant-a",
        subject="subject-a",
        scopes=("journey:read", "journey:write"),
        run_id="journey-run-001",
    )

    encoded = authority.issue(request)
    jwks = authority.jwks_document()
    keys = jwks["keys"]
    assert isinstance(keys, list)
    assert keys
    first_key = keys[0]
    assert isinstance(first_key, dict)
    public_key = jwt.PyJWK.from_dict(cast(dict[str, object], first_key))
    claims = jwt.decode(
        encoded.reveal(),
        key=public_key.key,
        algorithms=["RS256"],
        issuer=ISSUER,
        audience=AUDIENCE,
        options={"verify_exp": False, "verify_iat": False, "verify_nbf": False},
    )

    assert claims == {
        "aud": AUDIENCE,
        "exp": NOW + 300,
        "groups": ["tenant-a:writer"],
        "iat": NOW,
        "iss": ISSUER,
        "nbf": NOW,
        "run_id": "journey-run-001",
        "scope": "journey:read journey:write",
        "sub": "subject-a",
        "tenant_id": "tenant-a",
    }
    assert isinstance(encoded, SecretValue)
    assert encoded.reveal() not in repr(encoded)
    assert set(first_key) == {
        "alg",
        "e",
        "kid",
        "kty",
        "n",
        "use",
    }


@pytest.mark.parametrize(
    "token_request",
    [
        TokenRequest(tenant="tenant-a", subject="subject-a", scopes=(), run_id="run-a"),
        TokenRequest(
            tenant="Tenant A",
            subject="subject-a",
            scopes=("journey:read",),
            run_id="run-a",
        ),
        TokenRequest(
            tenant="tenant-a",
            subject="subject-a",
            scopes=("journey:read", "journey:read"),
            run_id="run-a",
        ),
    ],
    ids=["no-scopes", "invalid-tenant", "duplicate-scopes"],
)
def test_token_request_rejects_unbounded_or_ambiguous_authority(
    token_request: TokenRequest,
) -> None:
    with pytest.raises(ValueError, match="token request"):
        token_request.validate()


async def test_identity_http_boundary_never_logs_or_returns_private_key_material() -> None:
    authority = _authority()
    service = IdentityService(authority)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=service),
        base_url="http://identity.test",
    ) as client:
        health = await client.get("/health")
        jwks = await client.get("/jwks.json")
        token = await client.post(
            "/token",
            json={
                "tenant": "tenant-a",
                "subject": "subject-a",
                "scopes": ["journey:read"],
                "run_id": "journey-run-001",
            },
        )

    assert health.json() == {"status": "ok"}
    assert jwks.json() == authority.jwks_document()
    token_document = cast(dict[str, object], token.json())
    assert set(token_document) == {"access_token", "expires_in", "token_type"}
    assert token_document["token_type"] == "Bearer"
    assert token_document["expires_in"] == 300
    assert service.events == ("health", "jwks", "token_issued")
    assert cast(str, token_document["access_token"]) not in repr(service)
    assert '"d"' not in jwks.text


async def test_identity_http_boundary_rejects_unknown_and_oversized_inputs() -> None:
    service = IdentityService(_authority())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=service),
        base_url="http://identity.test",
    ) as client:
        unknown = await client.post(
            "/token",
            json={
                "tenant": "tenant-a",
                "subject": "subject-a",
                "scopes": ["journey:read"],
                "run_id": "run-a",
                "role": "admin",
            },
        )
        oversized = await client.post("/token", content=b"x" * 16_385)

    assert unknown.status_code == 400
    assert oversized.status_code == 413
    assert unknown.json() == {"code": "invalid_request"}
    assert oversized.json() == {"code": "request_too_large"}


def test_write_replay_has_one_effect_and_returns_the_original_result() -> None:
    store = BackingStore()

    first = store.write_order(_context(), order_id="order-001", value="created")
    replay = store.write_order(_context(), order_id="order-001", value="created")

    assert (
        first
        == replay
        == {
            "effect_id": "effect-000001",
            "order_id": "order-001",
            "status": "created",
        }
    )
    assert store.effect_count == 1
    assert len(store.observations) == 2
    assert store.observations[1].replayed is True


def test_idempotency_scope_includes_tenant_and_rejects_changed_payload() -> None:
    store = BackingStore()
    store.write_order(_context(), order_id="order-001", value="created")

    tenant_b = store.write_order(
        _context(tenant="tenant-b"),
        order_id="order-001",
        value="created",
    )
    with pytest.raises(BackingConflict):
        store.write_order(_context(), order_id="order-001", value="changed")

    assert tenant_b["effect_id"] == "effect-000002"
    assert store.effect_count == 2


def test_backing_outage_is_visible_without_changing_liveness_or_effects() -> None:
    store = BackingStore()
    store.set_available(False)

    assert store.liveness() is True
    assert store.readiness() is False
    with pytest.raises(BackingUnavailable):
        store.read_order(_context(idempotency_key=None), order_id="order-001")
    with pytest.raises(BackingUnavailable):
        store.write_order(_context(), order_id="order-001", value="created")
    assert store.effect_count == 0


def test_canary_is_confined_to_a_secret_shaped_backing_field() -> None:
    store = BackingStore()

    result = store.secret_canary(_context(idempotency_key=None))
    observations = json.dumps(
        [item.to_document() for item in store.observations],
        sort_keys=True,
    )

    assert result == {"api_key": JOURNEY_CANARY}
    assert JOURNEY_CANARY not in observations
    assert "authorization" not in observations
    assert "idempotency_key" not in observations
    assert "tenant-a" in observations
    assert "subject-a" not in observations


async def test_backing_http_boundary_validates_context_and_exposes_sanitized_state() -> None:
    store = BackingStore()
    service = BackingService(store)
    headers = {
        "x-journey-tenant": "tenant-a",
        "x-journey-subject": "subject-a",
        "x-journey-scopes": "journey:read journey:write journey:approve",
        "x-request-id": "request-backing-001",
        "traceparent": f"00-{'1' * 32}-{'2' * 16}-01",
        "idempotency-key": "write-order-001",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=service),
        base_url="http://backing.test",
    ) as client:
        created = await client.post(
            "/v1/orders/order-001",
            headers=headers,
            json={"status": "created"},
        )
        replayed = await client.post(
            "/v1/orders/order-001",
            headers=headers,
            json={"status": "created"},
        )
        observations = await client.get("/control/observations")
        disabled = await client.put("/control/availability", json={"available": False})
        unavailable = await client.get("/v1/orders/order-001", headers=headers)

    assert created.json() == replayed.json()
    assert observations.json()["effect_count"] == 1
    serialized = json.dumps(observations.json(), sort_keys=True)
    assert "write-order-001" not in serialized
    assert "subject-a" not in serialized
    assert JOURNEY_CANARY not in serialized
    assert disabled.json() == {"available": False}
    assert unavailable.status_code == 503
    assert unavailable.json() == {"code": "backing_unavailable"}


async def test_backing_http_boundary_rejects_cross_tenant_body_authority() -> None:
    service = BackingService(BackingStore())
    headers = {
        "x-journey-tenant": "tenant-a",
        "x-journey-subject": "subject-a",
        "x-journey-scopes": "journey:write",
        "x-request-id": "request-backing-001",
        "traceparent": f"00-{'1' * 32}-{'2' * 16}-01",
        "idempotency-key": "write-order-001",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=service),
        base_url="http://backing.test",
    ) as client:
        response = await client.post(
            "/v1/orders/order-001",
            headers=headers,
            json={"status": "created", "tenant": "tenant-b"},
        )

    assert response.status_code == 400
    assert response.json() == {"code": "invalid_request"}


def test_backing_context_never_renders_subject_or_idempotency_value() -> None:
    context = _context()
    rendered = repr(context)

    assert "subject-a" not in rendered
    assert "write-order-001" not in rendered
    assert "tenant-a" in rendered


def test_json_documents_remain_json_value_compatible() -> None:
    document: Mapping[str, JsonValue] = _context().to_document()

    assert document == {
        "request_id": "request-backing-001",
        "scopes": ["journey:approve", "journey:read", "journey:write"],
        "subject_hash": document["subject_hash"],
        "tenant": "tenant-a",
        "trace_id": "1" * 32,
    }
    assert len(cast(str, document["subject_hash"])) == 64
