from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Callable
from dataclasses import FrozenInstanceError, replace
from typing import cast

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from tesserix_mcp_runtime import Cancellation, JsonValue
from tesserix_mcp_runtime.adapters.gateway_identity import (
    GatewayIdentityConfig,
    GatewayJWTContextProvider,
    HTTPSJWKSFetcher,
    JWKSFetcher,
    JWKSFetchError,
)
from tesserix_mcp_runtime.adapters.streamable_http import (
    HTTPRequestAuthenticationError,
    HTTPRequestMetadata,
)

NOW = 1_800_000_000.0
ISSUER = "https://identity.example.invalid"
AUDIENCE = "tesserix-mcp-runtime"


class _Cancellation:
    @property
    def cancelled(self) -> bool:
        return False

    async def wait(self) -> None:
        await asyncio.Future[None]()


class _JWKS(JWKSFetcher):
    def __init__(self, document: dict[str, JsonValue]) -> None:
        self.document = document
        self.calls = 0

    async def fetch(self) -> dict[str, JsonValue]:
        self.calls += 1
        return self.document


class _RotatingJWKS(JWKSFetcher):
    def __init__(self, responses: list[dict[str, JsonValue] | Exception]) -> None:
        self.responses = responses
        self.calls = 0

    async def fetch(self) -> dict[str, JsonValue]:
        response = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        if isinstance(response, Exception):
            raise response
        return response


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class _OversizedJWKSStream(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"x" * 65_537


def _key_pair(kid: str) -> tuple[rsa.RSAPrivateKey, dict[str, JsonValue]]:
    private = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    raw_public: object = json.loads(RSAAlgorithm.to_jwk(private.public_key()))
    assert isinstance(raw_public, dict)
    public = cast(dict[str, JsonValue], raw_public)
    public.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return private, public


def _token(
    private: rsa.RSAPrivateKey,
    *,
    kid: str,
    claims: dict[str, object] | None = None,
    remove: tuple[str, ...] = (),
) -> str:
    payload: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "subject-a",
        "tenant_id": "tenant-a",
        "scope": "orders:read tools:call",
        "run_id": "run-a",
        "iat": int(NOW - 10),
        "nbf": int(NOW - 10),
        "exp": int(NOW + 300),
    }
    if claims is not None:
        payload.update(claims)
    for name in remove:
        payload.pop(name, None)
    encoded = jwt.encode(payload, private, algorithm="RS256", headers={"kid": kid})
    assert isinstance(encoded, str)
    return encoded


def _config() -> GatewayIdentityConfig:
    return GatewayIdentityConfig(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url="https://identity.example.invalid/.well-known/jwks.json",
        jwks_allowed_hosts=("identity.example.invalid",),
        trusted_proxy_cidrs=("10.0.0.0/8",),
    )


@pytest.mark.parametrize(
    ("url", "allowed_host"),
    [
        ("https://127.0.0.1/keys", "127.0.0.1"),
        ("https://identity.example.invalid:8443/keys", "identity.example.invalid"),
    ],
)
def test_jwks_destination_rejects_ip_literals_and_alternate_ports(
    url: str,
    allowed_host: str,
) -> None:
    with pytest.raises(ValueError, match="jwks_url"):
        GatewayIdentityConfig(
            issuer=ISSUER,
            audience=AUDIENCE,
            jwks_url=url,
            jwks_allowed_hosts=(allowed_host,),
            trusted_proxy_cidrs=("10.0.0.0/8",),
        )


@pytest.mark.parametrize(
    "build",
    [
        lambda: replace(_config(), issuer="http://identity.example.invalid"),
        lambda: replace(_config(), issuer="https://identity.example.invalid:invalid"),
        lambda: replace(_config(), jwks_url="https://unapproved.example.invalid/keys"),
        lambda: replace(
            _config(),
            jwks_url="https://identity.example.invalid:invalid/keys",
        ),
        lambda: replace(_config(), jwks_allowed_hosts=()),
        lambda: replace(
            _config(),
            jwks_allowed_hosts=("identity.example.invalid", "identity.example.invalid"),
        ),
        lambda: replace(_config(), trusted_proxy_cidrs=()),
        lambda: replace(_config(), trusted_proxy_cidrs=("10.0.0.1/8",)),
        lambda: replace(_config(), algorithm="HS256"),
        lambda: replace(_config(), tenant_claim="sub"),
        lambda: replace(_config(), jwks_fresh_seconds=0),
        lambda: replace(_config(), jwks_stale_seconds=899),
        lambda: replace(_config(), jwks_timeout_seconds=float("inf")),
        lambda: replace(_config(), jwks_retry_seconds=True),
        lambda: replace(_config(), max_token_lifetime_seconds=0),
        lambda: replace(
            _config(),
            jwks_fresh_seconds=86_401,
            jwks_stale_seconds=86_401,
        ),
        lambda: replace(_config(), jwks_stale_seconds=604_801),
        lambda: replace(_config(), jwks_timeout_seconds=30.001),
        lambda: replace(_config(), jwks_retry_seconds=300.001),
        lambda: replace(_config(), max_token_lifetime_seconds=86_400.001),
        lambda: replace(_config(), request_timeout_seconds=30.001),
        lambda: replace(_config(), max_jwks_bytes=1_023),
        lambda: replace(_config(), max_jwks_bytes=1_048_577),
        lambda: replace(_config(), max_jwks_keys=0),
        lambda: replace(_config(), max_jwks_keys=129),
        lambda: replace(_config(), clock_skew_seconds=-0.1),
        lambda: replace(_config(), clock_skew_seconds=300.1),
    ],
    ids=[
        "insecure-issuer",
        "invalid-issuer-port",
        "unapproved-jwks-host",
        "invalid-jwks-port",
        "empty-host-allowlist",
        "duplicate-host-allowlist",
        "empty-proxy-allowlist",
        "non-canonical-proxy-network",
        "symmetric-algorithm",
        "reserved-tenant-claim",
        "zero-fresh-window",
        "stale-window-shorter-than-fresh",
        "infinite-timeout",
        "boolean-retry-window",
        "zero-token-lifetime",
        "fresh-window-above-maximum",
        "stale-window-above-maximum",
        "jwks-timeout-above-maximum",
        "retry-window-above-maximum",
        "token-lifetime-above-maximum",
        "request-timeout-above-maximum",
        "jwks-bytes-below-minimum",
        "jwks-bytes-above-maximum",
        "jwks-keys-below-minimum",
        "jwks-keys-above-maximum",
        "negative-clock-skew",
        "clock-skew-above-maximum",
    ],
)
def test_gateway_identity_config_rejects_values_outside_security_boundaries(
    build: Callable[[], GatewayIdentityConfig],
) -> None:
    with pytest.raises(ValueError):
        build()


def test_gateway_identity_config_accepts_inclusive_numeric_boundaries() -> None:
    lower = replace(
        _config(),
        jwks_fresh_seconds=1,
        jwks_stale_seconds=1,
        max_jwks_bytes=1_024,
        max_jwks_keys=1,
        clock_skew_seconds=0,
    )
    upper = replace(
        _config(),
        jwks_fresh_seconds=86_400,
        jwks_stale_seconds=604_800,
        jwks_timeout_seconds=30,
        jwks_retry_seconds=300,
        max_token_lifetime_seconds=86_400,
        request_timeout_seconds=30,
        max_jwks_bytes=1_048_576,
        max_jwks_keys=128,
        clock_skew_seconds=300,
    )

    assert lower.max_jwks_bytes == 1_024
    assert lower.max_jwks_keys == 1
    assert lower.clock_skew_seconds == 0
    assert upper.max_jwks_bytes == 1_048_576
    assert upper.max_jwks_keys == 128
    assert upper.clock_skew_seconds == 300
    assert upper.request_timeout_seconds == 30


def test_identity_adapter_constructors_reject_incompatible_runtime_objects() -> None:
    with pytest.raises(TypeError, match="config"):
        HTTPSJWKSFetcher(cast(GatewayIdentityConfig, object()))
    with pytest.raises(TypeError, match="config"):
        GatewayJWTContextProvider(cast(GatewayIdentityConfig, object()))
    with pytest.raises(TypeError, match="jwks_fetcher"):
        GatewayJWTContextProvider(
            _config(),
            jwks_fetcher=cast(JWKSFetcher, object()),
        )


def _request(
    encoded: str,
    *,
    subject: str = "subject-a",
    tenant: str = "tenant-a",
    run_id: str = "run-a",
) -> HTTPRequestMetadata:
    return HTTPRequestMetadata(
        method="POST",
        path="/mcp",
        headers=(
            ("authorization", f"Bearer {encoded}"),
            ("x-request-id", "request-a"),
            ("x-jwt-claim-sub", subject),
            ("x-jwt-claim-tenant-id", tenant),
            ("x-tesserix-run-id", run_id),
            (
                "traceparent",
                "00-11111111111111111111111111111111-1111111111111111-01",
            ),
            ("tracestate", "vendor=value"),
        ),
        peer_host="10.2.3.4",
    )


def _provider(
    fetcher: JWKSFetcher,
    *,
    cache_clock: Callable[[], float] = lambda: 100.0,
) -> GatewayJWTContextProvider:
    return GatewayJWTContextProvider(
        _config(),
        jwks_fetcher=fetcher,
        wall_clock=lambda: NOW,
        cache_clock=cache_clock,
        request_id_factory=lambda: "generated-request",
    )


def test_valid_gateway_token_builds_exact_immutable_call_context() -> None:
    private, public = _key_pair("key-a")
    fetcher = _JWKS({"keys": [public]})
    cancellation: Cancellation = _Cancellation()

    context = asyncio.run(
        _provider(fetcher).create(
            _request(_token(private, kid="key-a")),
            cancellation=cancellation,
        )
    )

    assert context.tenant == "tenant-a"
    assert context.subject == "subject-a"
    assert context.issuer == ISSUER
    assert context.scopes == ("orders:read", "tools:call")
    assert context.request_id == "request-a"
    assert context.run_id == "run-a"
    assert dict(context.trace) == {
        "traceparent": "00-11111111111111111111111111111111-1111111111111111-01",
        "tracestate": "vendor=value",
    }
    assert context.cancellation is cancellation
    assert fetcher.calls == 1
    with pytest.raises(FrozenInstanceError):
        context.request_id = "changed"  # type: ignore[misc]


def test_trusted_gateway_run_header_supplies_run_when_the_token_has_none() -> None:
    private, public = _key_pair("key-a")

    context = asyncio.run(
        _provider(_JWKS({"keys": [public]})).create(
            _request(_token(private, kid="key-a", remove=("run_id",))),
            cancellation=_Cancellation(),
        )
    )

    assert context.request_id == "request-a"
    assert context.run_id == "run-a"


def test_authenticated_gateway_propagates_bounded_call_control_identifiers() -> None:
    private, public = _key_pair("key-a")
    request = _request(_token(private, kid="key-a"))
    request = HTTPRequestMetadata(
        method=request.method,
        path=request.path,
        headers=(
            *request.headers,
            ("idempotency-key", "idempotency-a"),
            ("x-tesserix-approval-id", "approval-a"),
        ),
        peer_host=request.peer_host,
    )

    context = asyncio.run(
        _provider(_JWKS({"keys": [public]})).create(
            request,
            cancellation=_Cancellation(),
        )
    )

    assert context.idempotency_key == "idempotency-a"
    assert context.approval_id == "approval-a"


@pytest.mark.parametrize(
    ("timeout_ms", "expected_deadline"),
    [("1250", 101.25), ("60000", 130.0)],
    ids=["caller-shortens", "gateway-clamps"],
)
def test_authenticated_gateway_sets_a_bounded_monotonic_deadline(
    timeout_ms: str,
    expected_deadline: float,
) -> None:
    private, public = _key_pair("key-a")
    request = _request(_token(private, kid="key-a"))
    request = HTTPRequestMetadata(
        method=request.method,
        path=request.path,
        headers=(*request.headers, ("x-tesserix-timeout-ms", timeout_ms)),
        peer_host=request.peer_host,
    )

    context = asyncio.run(
        _provider(_JWKS({"keys": [public]}), cache_clock=lambda: 100.0).create(
            request,
            cancellation=_Cancellation(),
        )
    )

    assert context.deadline == expected_deadline


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("idempotency-key", "i" * 513),
        ("x-tesserix-approval-id", "a" * 257),
    ],
)
def test_gateway_rejects_unbounded_call_control_identifiers(
    header: str,
    value: str,
) -> None:
    private, public = _key_pair("key-a")
    request = _request(_token(private, kid="key-a"))
    request = HTTPRequestMetadata(
        method=request.method,
        path=request.path,
        headers=(*request.headers, (header, value)),
        peer_host=request.peer_host,
    )

    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(
            _provider(_JWKS({"keys": [public]})).create(
                request,
                cancellation=_Cancellation(),
            )
        )

    assert raised.value.request_id == "request-a"
    assert value not in repr(raised.value)


@pytest.mark.parametrize(
    "header",
    ["idempotency-key", "x-tesserix-approval-id", "x-tesserix-timeout-ms"],
)
def test_gateway_rejects_ambiguous_call_control_identifiers(header: str) -> None:
    private, public = _key_pair("key-a")
    request = _request(_token(private, kid="key-a"))
    request = HTTPRequestMetadata(
        method=request.method,
        path=request.path,
        headers=(*request.headers, (header, "first"), (header, "second")),
        peer_host=request.peer_host,
    )

    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(
            _provider(_JWKS({"keys": [public]})).create(
                request,
                cancellation=_Cancellation(),
            )
        )

    assert raised.value.request_id == "request-a"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0",
        "01",
        "-1",
        "1.5",
        "\N{FULLWIDTH DIGIT ONE}\N{FULLWIDTH DIGIT TWO}",
        "1000000000",
    ],
    ids=["empty", "zero", "leading-zero", "negative", "decimal", "non-ascii", "too-long"],
)
def test_gateway_rejects_invalid_timeout_header(value: str) -> None:
    private, public = _key_pair("key-a")
    request = _request(_token(private, kid="key-a"))
    request = HTTPRequestMetadata(
        method=request.method,
        path=request.path,
        headers=(*request.headers, ("x-tesserix-timeout-ms", value)),
        peer_host=request.peer_host,
    )

    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(
            _provider(_JWKS({"keys": [public]})).create(
                request,
                cancellation=_Cancellation(),
            )
        )

    assert raised.value.request_id == "request-a"
    if value:
        assert value not in repr(raised.value)


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "expired",
        "not-yet-valid",
        "wrong-issuer",
        "wrong-audience",
        "multiple-audiences",
        "wrong-algorithm",
        "forged-signature",
        "missing-subject",
        "missing-tenant",
        "duplicate-authorization",
        "wrong-scheme",
        "empty-bearer",
        "malformed-bearer",
        "oversized-bearer",
    ],
)
def test_invalid_gateway_authentication_fails_closed_without_private_material(case: str) -> None:
    private, public = _key_pair("key-a")
    fetcher = _JWKS({"keys": [public]})
    encoded = _token(private, kid="key-a")
    request = _request(encoded)

    if case == "missing":
        request = HTTPRequestMetadata(
            method=request.method,
            path=request.path,
            headers=tuple(item for item in request.headers if item[0] != "authorization"),
            peer_host=request.peer_host,
        )
    elif case == "expired":
        encoded = _token(
            private,
            kid="key-a",
            claims={"iat": int(NOW - 400), "nbf": int(NOW - 400), "exp": int(NOW - 60)},
        )
        request = _request(encoded)
    elif case == "not-yet-valid":
        request = _request(
            _token(
                private,
                kid="key-a",
                claims={"iat": int(NOW + 60), "nbf": int(NOW + 60)},
            )
        )
    elif case == "wrong-issuer":
        request = _request(
            _token(private, kid="key-a", claims={"iss": "https://other.example.invalid"})
        )
    elif case == "wrong-audience":
        request = _request(_token(private, kid="key-a", claims={"aud": "another-runtime"}))
    elif case == "multiple-audiences":
        request = _request(
            _token(
                private,
                kid="key-a",
                claims={"aud": [AUDIENCE, "another-runtime"]},
            )
        )
    elif case == "wrong-algorithm":
        payload = jwt.decode(encoded, options={"verify_signature": False})
        encoded = jwt.encode(
            payload,
            b"x" * 32,
            algorithm="HS256",
            headers={"kid": "key-a"},
        )
        request = _request(encoded)
    elif case == "forged-signature":
        forged, _ = _key_pair("unused")
        request = _request(_token(forged, kid="key-a"))
    elif case == "missing-subject":
        request = _request(_token(private, kid="key-a", remove=("sub",)))
    elif case == "missing-tenant":
        request = _request(_token(private, kid="key-a", remove=("tenant_id",)))
    elif case == "duplicate-authorization":
        request = HTTPRequestMetadata(
            method=request.method,
            path=request.path,
            headers=(*request.headers, ("authorization", f"Bearer {encoded}")),
            peer_host=request.peer_host,
        )
    elif case == "wrong-scheme":
        request = HTTPRequestMetadata(
            method=request.method,
            path=request.path,
            headers=tuple(
                (name, "Basic fixture") if name == "authorization" else (name, value)
                for name, value in request.headers
            ),
            peer_host=request.peer_host,
        )
    elif case == "empty-bearer":
        request = HTTPRequestMetadata(
            method=request.method,
            path=request.path,
            headers=tuple(
                (name, "Bearer ") if name == "authorization" else (name, value)
                for name, value in request.headers
            ),
            peer_host=request.peer_host,
        )
    elif case == "malformed-bearer":
        request = HTTPRequestMetadata(
            method=request.method,
            path=request.path,
            headers=tuple(
                (name, "Bearer only.one") if name == "authorization" else (name, value)
                for name, value in request.headers
            ),
            peer_host=request.peer_host,
        )
    elif case == "oversized-bearer":
        request = HTTPRequestMetadata(
            method=request.method,
            path=request.path,
            headers=tuple(
                (name, f"Bearer {'x' * 16_385}.x.x") if name == "authorization" else (name, value)
                for name, value in request.headers
            ),
            peer_host=request.peer_host,
        )

    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(_provider(fetcher).create(request, cancellation=_Cancellation()))

    assert raised.value.request_id == "request-a"
    assert str(raised.value) == "request authentication failed"
    assert encoded not in repr(raised.value)


@pytest.mark.parametrize("peer_host", [None, "not-an-ip", "192.0.2.50"])
def test_untrusted_peer_cannot_promote_forwarded_identity_or_request_id(
    peer_host: str | None,
) -> None:
    private, public = _key_pair("key-a")
    request = _request(_token(private, kid="key-a"))
    request = HTTPRequestMetadata(
        method=request.method,
        path=request.path,
        headers=request.headers,
        peer_host=peer_host,
    )

    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(
            _provider(_JWKS({"keys": [public]})).create(
                request,
                cancellation=_Cancellation(),
            )
        )

    assert raised.value.request_id == "generated-request"


def test_invalid_request_id_factory_falls_back_to_a_safe_generated_value() -> None:
    def fail_request_id() -> str:
        raise RuntimeError("private request id detail")

    provider = GatewayJWTContextProvider(
        _config(),
        jwks_fetcher=_JWKS({"keys": []}),
        request_id_factory=fail_request_id,
    )
    request = HTTPRequestMetadata(method="POST", path="/mcp", headers=(), peer_host=None)

    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(provider.create(request, cancellation=_Cancellation()))

    assert len(raised.value.request_id) == 32
    assert int(raised.value.request_id, 16) >= 0
    assert "private request id detail" not in repr(raised.value)


def test_duplicate_attribution_header_fails_before_it_can_supply_request_id() -> None:
    private, public = _key_pair("key-a")
    request = _request(_token(private, kid="key-a"))
    request = HTTPRequestMetadata(
        method=request.method,
        path=request.path,
        headers=(*request.headers, ("x-request-id", "another-request")),
        peer_host=request.peer_host,
    )

    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(
            _provider(_JWKS({"keys": [public]})).create(
                request,
                cancellation=_Cancellation(),
            )
        )

    assert raised.value.request_id == "generated-request"


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("x-jwt-claim-sub", "another-subject"),
        ("x-jwt-claim-tenant-id", "another-tenant"),
        ("x-tesserix-run-id", "another-run"),
        ("x-jwt-claim-scope", "platform:admin"),
        ("traceparent", "00-invalid"),
    ],
)
def test_forwarded_authority_disagreement_is_rejected_without_disclosure(
    header: str,
    value: str,
) -> None:
    private, public = _key_pair("key-a")
    request = _request(_token(private, kid="key-a"))
    headers = tuple(item for item in request.headers if item[0] != header)
    request = HTTPRequestMetadata(
        method=request.method,
        path=request.path,
        headers=(*headers, (header, value)),
        peer_host=request.peer_host,
    )

    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(
            _provider(_JWKS({"keys": [public]})).create(
                request,
                cancellation=_Cancellation(),
            )
        )

    assert raised.value.request_id == "request-a"
    assert value not in repr(raised.value)


def test_scope_claim_ambiguity_and_excessive_token_lifetime_fail_closed() -> None:
    private, public = _key_pair("key-a")
    provider = _provider(_JWKS({"keys": [public]}))
    ambiguous = _request(
        _token(
            private,
            kid="key-a",
            claims={"scp": ["platform:admin"]},
        )
    )
    long_lived = _request(
        _token(
            private,
            kid="key-a",
            claims={"iat": int(NOW - 10), "exp": int(NOW + 3_700)},
        )
    )

    for request in (ambiguous, long_lived):
        with pytest.raises(HTTPRequestAuthenticationError):
            asyncio.run(provider.create(request, cancellation=_Cancellation()))


@pytest.mark.parametrize(
    "claims",
    [
        {"iat": True},
        {"sub": 7},
        {"scope": ["orders:read", 7]},
        {"scope": {"orders:read": True}},
        {"scope": "orders:read orders:read"},
        {"scope": [f"scope:{index}" for index in range(65)]},
        {"scope": "x" * 257},
    ],
    ids=[
        "boolean-numeric-date",
        "non-string-subject",
        "non-string-scope-item",
        "invalid-scope-container",
        "duplicate-scope",
        "too-many-scopes",
        "oversized-scope",
    ],
)
def test_invalid_numeric_dates_and_scope_shapes_fail_closed(
    claims: dict[str, object],
) -> None:
    private, public = _key_pair("key-a")

    with pytest.raises(HTTPRequestAuthenticationError):
        asyncio.run(
            _provider(_JWKS({"keys": [public]})).create(
                _request(_token(private, kid="key-a", claims=claims)),
                cancellation=_Cancellation(),
            )
        )


def test_non_finite_verifier_clock_fails_closed() -> None:
    private, public = _key_pair("key-a")
    provider = GatewayJWTContextProvider(
        _config(),
        jwks_fetcher=_JWKS({"keys": [public]}),
        wall_clock=lambda: float("nan"),
        request_id_factory=lambda: "generated-request",
    )

    with pytest.raises(HTTPRequestAuthenticationError):
        asyncio.run(
            provider.create(
                _request(_token(private, kid="key-a")),
                cancellation=_Cancellation(),
            )
        )


def test_concurrent_tenants_share_only_public_keys_and_receive_distinct_contexts() -> None:
    private, public = _key_pair("key-a")
    fetcher = _JWKS({"keys": [public]})
    provider = _provider(fetcher)
    first_request = _request(_token(private, kid="key-a"))
    second_request = _request(
        _token(
            private,
            kid="key-a",
            claims={"sub": "subject-b", "tenant_id": "tenant-b", "run_id": "run-b"},
        ),
        subject="subject-b",
        tenant="tenant-b",
        run_id="run-b",
    )

    async def exercise() -> None:
        first, second = await asyncio.gather(
            provider.create(first_request, cancellation=_Cancellation()),
            provider.create(second_request, cancellation=_Cancellation()),
        )
        assert (first.tenant, first.subject, first.run_id) == (
            "tenant-a",
            "subject-a",
            "run-a",
        )
        assert (second.tenant, second.subject, second.run_id) == (
            "tenant-b",
            "subject-b",
            "run-b",
        )
        assert first.identity is not second.identity
        assert first.cancellation is not second.cancellation

    asyncio.run(exercise())
    assert fetcher.calls == 1


def test_unknown_key_forces_one_refresh_and_successful_rotation_removes_the_old_key() -> None:
    private_a, public_a = _key_pair("key-a")
    private_b, public_b = _key_pair("key-b")
    fetcher = _RotatingJWKS(
        [
            {"keys": [public_a]},
            {"keys": [public_b]},
        ]
    )
    provider = _provider(fetcher)

    first = asyncio.run(
        provider.create(
            _request(_token(private_a, kid="key-a")),
            cancellation=_Cancellation(),
        )
    )
    rotated = asyncio.run(
        provider.create(
            _request(_token(private_b, kid="key-b")),
            cancellation=_Cancellation(),
        )
    )

    assert first.tenant == rotated.tenant == "tenant-a"
    assert fetcher.calls == 2
    with pytest.raises(HTTPRequestAuthenticationError):
        asyncio.run(
            provider.create(
                _request(_token(private_a, kid="key-a")),
                cancellation=_Cancellation(),
            )
        )


def test_cached_known_key_survives_bounded_jwks_outage_without_refresh_flooding() -> None:
    private, public = _key_pair("key-a")
    fetcher = _RotatingJWKS(
        [
            {"keys": [public]},
            RuntimeError("private identity dependency detail"),
        ]
    )
    clock = _Clock(100.0)
    provider = _provider(fetcher, cache_clock=clock)
    request = _request(_token(private, kid="key-a"))

    asyncio.run(provider.create(request, cancellation=_Cancellation()))
    clock.now += 901
    stale = asyncio.run(provider.create(request, cancellation=_Cancellation()))
    clock.now += 1
    second_stale = asyncio.run(provider.create(request, cancellation=_Cancellation()))

    assert stale.tenant == second_stale.tenant == "tenant-a"
    assert fetcher.calls == 2

    clock.now = 3_701
    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(provider.create(request, cancellation=_Cancellation()))
    assert "private identity dependency detail" not in repr(raised.value)


def test_jwks_outage_never_admits_an_unknown_key_from_stale_cache() -> None:
    private_a, public_a = _key_pair("key-a")
    private_b, _ = _key_pair("key-b")
    fetcher = _RotatingJWKS(
        [
            {"keys": [public_a]},
            RuntimeError("unavailable"),
        ]
    )
    clock = _Clock(100.0)
    provider = _provider(fetcher, cache_clock=clock)
    asyncio.run(
        provider.create(
            _request(_token(private_a, kid="key-a")),
            cancellation=_Cancellation(),
        )
    )
    clock.now += 901

    with pytest.raises(HTTPRequestAuthenticationError):
        asyncio.run(
            provider.create(
                _request(_token(private_b, kid="key-b")),
                cancellation=_Cancellation(),
            )
        )


def test_concurrent_cache_misses_share_one_jwks_fetch() -> None:
    private, public = _key_pair("key-a")

    async def exercise() -> None:
        class BlockingJWKS(JWKSFetcher):
            def __init__(self) -> None:
                self.calls = 0
                self.started = asyncio.Event()
                self.release = asyncio.Event()

            async def fetch(self) -> dict[str, JsonValue]:
                self.calls += 1
                self.started.set()
                await self.release.wait()
                return {"keys": [public]}

        class ContendedClock:
            def __init__(self) -> None:
                self.calls = 0
                self.second_miss = asyncio.Event()

            def __call__(self) -> float:
                self.calls += 1
                if self.calls == 3:
                    self.second_miss.set()
                return 100.0

        fetcher = BlockingJWKS()
        clock = ContendedClock()
        provider = _provider(fetcher, cache_clock=clock)
        request = _request(_token(private, kid="key-a"))
        first_task = asyncio.create_task(provider.create(request, cancellation=_Cancellation()))
        await fetcher.started.wait()
        second_task = asyncio.create_task(provider.create(request, cancellation=_Cancellation()))
        await clock.second_miss.wait()
        fetcher.release.set()
        first, second = await asyncio.gather(first_task, second_task)

        assert first is not second
        assert first.identity is not second.identity
        assert fetcher.calls == 1

    asyncio.run(exercise())


def test_provider_propagates_jwks_fetch_cancellation() -> None:
    private, _ = _key_pair("key-a")

    class CancellingJWKS(JWKSFetcher):
        async def fetch(self) -> dict[str, JsonValue]:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            _provider(CancellingJWKS()).create(
                _request(_token(private, kid="key-a")),
                cancellation=_Cancellation(),
            )
        )


@pytest.mark.parametrize(
    "case",
    [
        "malformed-key",
        "duplicate-kid",
        "oversized-document",
        "too-many-keys",
        "wrong-algorithm",
        "wrong-use",
        "invalid-key",
        "non-serializable",
    ],
)
def test_malformed_duplicate_and_oversized_jwks_documents_fail_closed(case: str) -> None:
    private, public = _key_pair("key-a")
    if case == "malformed-key":
        document: dict[str, JsonValue] = {"keys": ["not-a-key"]}
    elif case == "duplicate-kid":
        document = {"keys": [public, dict(public)]}
    elif case == "oversized-document":
        document = {"keys": [{**public, "padding": "x" * 65_536}]}
    elif case == "too-many-keys":
        document = {"keys": [{**public, "kid": f"key-{index}"} for index in range(33)]}
    elif case == "wrong-algorithm":
        document = {"keys": [{**public, "alg": "ES256"}]}
    elif case == "wrong-use":
        document = {"keys": [{**public, "use": "enc"}]}
    elif case == "invalid-key":
        document = {"keys": [{"kid": "key-a", "alg": "RS256", "use": "sig", "kty": "RSA"}]}
    else:
        document = cast(
            dict[str, JsonValue],
            {"keys": [public], "invalid": object()},
        )
    fetcher = _JWKS(document)

    with pytest.raises(HTTPRequestAuthenticationError) as raised:
        asyncio.run(
            _provider(fetcher).create(
                _request(_token(private, kid="key-a")),
                cancellation=_Cancellation(),
            )
        )

    assert raised.value.request_id == "request-a"
    assert str(raised.value) == "request authentication failed"
    assert "key-a" not in repr(raised.value)
    assert fetcher.calls == 1


def test_https_jwks_fetcher_reads_one_bounded_json_document_without_redirects() -> None:
    _, public = _key_pair("key-a")
    expected = {"keys": [public]}
    requests: list[httpx.Request] = []

    def serve(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json=expected,
            headers={"content-type": "application/json"},
        )

    document = asyncio.run(
        HTTPSJWKSFetcher(
            _config(),
            transport=httpx.MockTransport(serve),
        ).fetch()
    )

    assert document == expected
    assert len(requests) == 1
    assert str(requests[0].url) == "https://identity.example.invalid/.well-known/jwks.json"
    assert requests[0].headers["accept"] == "application/json"


@pytest.mark.parametrize(
    "case",
    [
        "redirect",
        "failure-status",
        "wrong-media-type",
        "oversized",
        "malformed",
        "invalid-content-length",
        "non-object",
        "streamed-oversized",
    ],
)
def test_https_jwks_fetcher_rejects_unsafe_or_unbounded_responses_generically(case: str) -> None:
    def serve(request: httpx.Request) -> httpx.Response:
        del request
        if case == "redirect":
            return httpx.Response(302, headers={"location": "https://internal.invalid/keys"})
        if case == "failure-status":
            return httpx.Response(503, text="private upstream response")
        if case == "wrong-media-type":
            return httpx.Response(200, content=b"{}", headers={"content-type": "text/plain"})
        if case == "oversized":
            return httpx.Response(
                200,
                content=b"x" * 65_537,
                headers={"content-type": "application/json"},
            )
        if case == "invalid-content-length":
            return httpx.Response(
                200,
                content=b"{}",
                headers={
                    "content-type": "application/json",
                    "content-length": "invalid",
                },
            )
        if case == "non-object":
            return httpx.Response(
                200,
                content=b"[]",
                headers={"content-type": "application/json"},
            )
        if case == "streamed-oversized":
            return httpx.Response(
                200,
                stream=_OversizedJWKSStream(),
                headers={"content-type": "application/json"},
            )
        return httpx.Response(
            200,
            content=b"{",
            headers={"content-type": "application/json"},
        )

    with pytest.raises(JWKSFetchError) as raised:
        asyncio.run(
            HTTPSJWKSFetcher(
                _config(),
                transport=httpx.MockTransport(serve),
            ).fetch()
        )

    assert str(raised.value) == "JWKS fetch failed"
    assert "internal.invalid" not in repr(raised.value)
    assert "private upstream response" not in repr(raised.value)


def test_https_jwks_fetcher_propagates_cancellation() -> None:
    def cancel(request: httpx.Request) -> httpx.Response:
        del request
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            HTTPSJWKSFetcher(
                _config(),
                transport=httpx.MockTransport(cancel),
            ).fetch()
        )
