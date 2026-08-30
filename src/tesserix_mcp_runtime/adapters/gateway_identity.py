"""Verify gateway JWTs and create immutable per-request authority."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

import httpx
import jwt

from tesserix_mcp_runtime.adapters.streamable_http import (
    HTTPRequestAuthenticationError,
    HTTPRequestMetadata,
)
from tesserix_mcp_runtime.contracts import (
    AuthenticatedIdentity,
    CallContext,
    Cancellation,
    JsonValue,
    TraceContext,
)

_SUPPORTED_ALGORITHMS = frozenset({"RS256", "ES256", "EdDSA"})
_RESERVED_TENANT_CLAIMS = frozenset(
    {"act", "aud", "azp", "exp", "iat", "iss", "jti", "nbf", "run_id", "scope", "scp", "sub"}
)


@runtime_checkable
class JWKSFetcher(Protocol):
    """Fetch one decoded JWKS document from an operator-owned endpoint."""

    async def fetch(self) -> Mapping[str, JsonValue]: ...


class GatewayIdentityError(RuntimeError):
    """Base failure raised by the gateway identity adapter."""


class JWKSFetchError(GatewayIdentityError):
    """The bounded JWKS endpoint could not return a usable document."""


@dataclass(frozen=True, slots=True, kw_only=True)
class GatewayIdentityConfig:
    """Fail-closed identity and bounded JWKS policy for one gateway issuer."""

    issuer: str
    audience: str
    jwks_url: str
    jwks_allowed_hosts: tuple[str, ...]
    trusted_proxy_cidrs: tuple[str, ...]
    algorithm: str = "RS256"
    tenant_claim: str = "tenant_id"
    jwks_fresh_seconds: float = 900.0
    jwks_stale_seconds: float = 3_600.0
    jwks_timeout_seconds: float = 2.0
    jwks_retry_seconds: float = 5.0
    max_jwks_bytes: int = 65_536
    max_jwks_keys: int = 32
    clock_skew_seconds: float = 30.0
    max_token_lifetime_seconds: float = 3_600.0

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("issuer", self.issuer, 2_048),
            ("audience", self.audience, 512),
            ("tenant_claim", self.tenant_claim, 128),
        ):
            _require_text(name, value, maximum=maximum)
        if self.tenant_claim in _RESERVED_TENANT_CLAIMS:
            raise ValueError("tenant_claim must be independent from standard authority claims")
        issuer = urlsplit(self.issuer)
        try:
            issuer_port = issuer.port
        except ValueError:
            raise ValueError("issuer must be an absolute HTTPS URL") from None
        if (
            issuer.scheme != "https"
            or issuer.hostname is None
            or issuer.username is not None
            or issuer.password is not None
            or issuer_port not in {None, 443}
            or _is_ip_literal(issuer.hostname)
            or issuer.query
            or issuer.fragment
        ):
            raise ValueError("issuer must be an absolute HTTPS URL")
        jwks = urlsplit(self.jwks_url)
        try:
            jwks_port = jwks.port
        except ValueError:
            raise ValueError("jwks_url must be an absolute HTTPS URL without credentials") from None
        if (
            jwks.scheme != "https"
            or jwks.hostname is None
            or jwks.username is not None
            or jwks.password is not None
            or jwks_port not in {None, 443}
            or _is_ip_literal(jwks.hostname)
            or jwks.query
            or jwks.fragment
        ):
            raise ValueError("jwks_url must be an absolute HTTPS URL without credentials")
        _require_text_tuple("jwks_allowed_hosts", self.jwks_allowed_hosts, maximum=253)
        if jwks.hostname.casefold() not in {host.casefold() for host in self.jwks_allowed_hosts}:
            raise ValueError("jwks_url host must be explicitly allowed")
        _require_text_tuple("trusted_proxy_cidrs", self.trusted_proxy_cidrs, maximum=64)
        for network in self.trusted_proxy_cidrs:
            ipaddress.ip_network(network, strict=True)
        if self.algorithm not in _SUPPORTED_ALGORITHMS:
            raise ValueError("algorithm must be an approved fixed asymmetric algorithm")
        for duration_name, duration_value in (
            ("jwks_fresh_seconds", self.jwks_fresh_seconds),
            ("jwks_stale_seconds", self.jwks_stale_seconds),
            ("jwks_timeout_seconds", self.jwks_timeout_seconds),
            ("jwks_retry_seconds", self.jwks_retry_seconds),
            ("max_token_lifetime_seconds", self.max_token_lifetime_seconds),
        ):
            _require_positive_number(duration_name, duration_value)
        if self.jwks_stale_seconds < self.jwks_fresh_seconds:
            raise ValueError("jwks_stale_seconds must cover the fresh window")
        if isinstance(self.max_jwks_bytes, bool) or not 1_024 <= self.max_jwks_bytes <= 1_048_576:
            raise ValueError("max_jwks_bytes must be between 1024 and 1048576")
        if isinstance(self.max_jwks_keys, bool) or not 1 <= self.max_jwks_keys <= 128:
            raise ValueError("max_jwks_keys must be between 1 and 128")
        _require_bounded_number(
            "clock_skew_seconds",
            self.clock_skew_seconds,
            minimum=0,
            maximum=300,
        )


class HTTPSJWKSFetcher:
    """Fetch one JWKS over an exact, non-redirecting HTTPS boundary."""

    def __init__(
        self,
        config: GatewayIdentityConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not _is_runtime_instance(config, GatewayIdentityConfig):
            raise TypeError("config must be GatewayIdentityConfig")
        self._config = config
        self._transport = transport

    async def fetch(self) -> Mapping[str, JsonValue]:
        try:
            async with (
                httpx.AsyncClient(
                    transport=self._transport,
                    follow_redirects=False,
                    trust_env=False,
                    timeout=self._config.jwks_timeout_seconds,
                ) as client,
                client.stream(
                    "GET",
                    self._config.jwks_url,
                    headers={"accept": "application/json"},
                ) as response,
            ):
                if response.status_code != 200:
                    raise JWKSFetchError
                media_type = response.headers.get("content-type", "").partition(";")[0]
                if media_type.strip().casefold() not in {
                    "application/json",
                    "application/jwk-set+json",
                }:
                    raise JWKSFetchError
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except ValueError:
                        raise JWKSFetchError from None
                    if not 0 <= declared_length <= self._config.max_jwks_bytes:
                        raise JWKSFetchError
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > self._config.max_jwks_bytes:
                        raise JWKSFetchError
                    body.extend(chunk)
            document = json.loads(body)
            if not isinstance(document, dict):
                raise JWKSFetchError
            return cast(dict[str, JsonValue], document)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise JWKSFetchError("JWKS fetch failed") from None


@dataclass(frozen=True, slots=True)
class _JWKSCacheEntry:
    keys: dict[str, jwt.PyJWK]
    fetched_at: float


class _IdentityRejected(Exception):
    pass


class GatewayJWTContextProvider:
    """Authenticate one gateway request without retaining caller authority."""

    def __init__(
        self,
        config: GatewayIdentityConfig,
        *,
        jwks_fetcher: JWKSFetcher | None = None,
        wall_clock: Callable[[], float] = time.time,
        cache_clock: Callable[[], float] = time.monotonic,
        request_id_factory: Callable[[], str] = lambda: secrets.token_hex(16),
    ) -> None:
        if not _is_runtime_instance(config, GatewayIdentityConfig):
            raise TypeError("config must be GatewayIdentityConfig")
        resolved_fetcher = jwks_fetcher or HTTPSJWKSFetcher(config)
        if not _is_runtime_instance(resolved_fetcher, JWKSFetcher):
            raise TypeError("jwks_fetcher must implement JWKSFetcher")
        self._config = config
        self._fetcher = resolved_fetcher
        self._wall_clock = wall_clock
        self._cache_clock = cache_clock
        self._request_id_factory = request_id_factory
        self._trusted_networks = tuple(
            ipaddress.ip_network(item, strict=True) for item in config.trusted_proxy_cidrs
        )
        self._cache: _JWKSCacheEntry | None = None
        self._cache_lock = asyncio.Lock()
        self._retry_after = 0.0

    async def create(
        self,
        request: HTTPRequestMetadata,
        *,
        cancellation: Cancellation,
    ) -> CallContext:
        generated_request_id = self._new_request_id()
        request_id = generated_request_id
        try:
            if not self._trusted_peer(request.peer_host):
                raise _IdentityRejected
            request_id = self._optional_header(request, "x-request-id") or generated_request_id
            encoded = self._bearer_token(request)
            unverified = jwt.get_unverified_header(encoded)
            if unverified.get("alg") != self._config.algorithm:
                raise _IdentityRejected
            kid = _bounded_claim(unverified.get("kid"), maximum=128)
            key = await self._key(kid)
            claims = jwt.decode(
                encoded,
                key=key.key,
                algorithms=[self._config.algorithm],
                issuer=self._config.issuer,
                audience=self._config.audience,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        self._config.tenant_claim,
                        "iat",
                        "nbf",
                        "exp",
                    ],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "strict_aud": True,
                },
            )
            self._validate_times(claims)
            subject = _bounded_claim(claims.get("sub"), maximum=512)
            tenant = _bounded_claim(claims.get(self._config.tenant_claim), maximum=256)
            scopes = _scopes(claims)
            self._agree(request, "x-jwt-claim-sub", subject)
            self._agree(request, "x-jwt-claim-tenant-id", tenant)
            forwarded_scopes = self._optional_header(request, "x-jwt-claim-scope")
            if forwarded_scopes is not None and tuple(sorted(forwarded_scopes.split())) != scopes:
                raise _IdentityRejected
            claimed_run = claims.get("run_id")
            forwarded_run = self._optional_header(request, "x-tesserix-run-id")
            if claimed_run is None:
                run_id = forwarded_run or request_id
            else:
                run_id = _bounded_claim(claimed_run, maximum=256)
                if forwarded_run is not None and forwarded_run != run_id:
                    raise _IdentityRejected
            trace_context = TraceContext(
                traceparent=self._optional_header(request, "traceparent"),
                tracestate=self._optional_header(request, "tracestate"),
            )
            idempotency_key = self._optional_header(request, "idempotency-key")
            approval_id = self._optional_header(request, "x-tesserix-approval-id")
            identity = AuthenticatedIdentity(
                tenant=tenant,
                subject=subject,
                issuer=self._config.issuer,
                scopes=scopes,
            )
            return CallContext(
                identity=identity,
                request_id=request_id,
                run_id=run_id,
                trace_context=trace_context,
                cancellation=cancellation,
                idempotency_key=idempotency_key,
                approval_id=approval_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HTTPRequestAuthenticationError(request_id=request_id) from None

    def _new_request_id(self) -> str:
        try:
            value = self._request_id_factory()
            _require_text("request_id", value, maximum=256)
        except Exception:
            return secrets.token_hex(16)
        return value

    def _trusted_peer(self, peer_host: str | None) -> bool:
        if peer_host is None:
            return False
        try:
            address = ipaddress.ip_address(peer_host)
        except ValueError:
            return False
        return any(address in network for network in self._trusted_networks)

    @staticmethod
    def _optional_header(request: HTTPRequestMetadata, name: str) -> str | None:
        values = request.header_values(name)
        if not values:
            return None
        if len(values) != 1:
            raise _IdentityRejected
        value = values[0]
        _require_text(name, value, maximum=512)
        return value

    def _bearer_token(self, request: HTTPRequestMetadata) -> str:
        values = request.header_values("authorization")
        if len(values) != 1:
            raise _IdentityRejected
        scheme, separator, encoded = values[0].partition(" ")
        if separator != " " or scheme.casefold() != "bearer" or not encoded:
            raise _IdentityRejected
        if len(encoded) > 16_384 or encoded != encoded.strip() or encoded.count(".") != 2:
            raise _IdentityRejected
        return encoded

    @staticmethod
    def _agree(request: HTTPRequestMetadata, name: str, expected: str) -> None:
        supplied = GatewayJWTContextProvider._optional_header(request, name)
        if supplied is not None and supplied != expected:
            raise _IdentityRejected

    async def _key(self, kid: str) -> jwt.PyJWK:
        entry = self._cache
        now = self._cache_clock()
        if entry is not None and now - entry.fetched_at < self._config.jwks_fresh_seconds:
            key = entry.keys.get(kid)
            if key is not None:
                return key
        if now < self._retry_after:
            return self._stale_key(entry, kid, now)
        async with self._cache_lock:
            entry = self._cache
            now = self._cache_clock()
            if entry is not None and now - entry.fetched_at < self._config.jwks_fresh_seconds:
                key = entry.keys.get(kid)
                if key is not None:
                    return key
            if now < self._retry_after:
                return self._stale_key(entry, kid, now)
            try:
                async with asyncio.timeout(self._config.jwks_timeout_seconds):
                    document = await self._fetcher.fetch()
                keys = self._validate_jwks(document)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._retry_after = now + self._config.jwks_retry_seconds
                return self._stale_key(entry, kid, now)
            self._cache = _JWKSCacheEntry(keys=keys, fetched_at=now)
            self._retry_after = 0.0
            try:
                return keys[kid]
            except KeyError:
                self._retry_after = now + self._config.jwks_retry_seconds
                raise _IdentityRejected from None

    def _stale_key(
        self,
        entry: _JWKSCacheEntry | None,
        kid: str,
        now: float,
    ) -> jwt.PyJWK:
        if entry is None or now - entry.fetched_at > self._config.jwks_stale_seconds:
            raise _IdentityRejected
        try:
            return entry.keys[kid]
        except KeyError:
            raise _IdentityRejected from None

    def _validate_jwks(self, document: Mapping[str, JsonValue]) -> dict[str, jwt.PyJWK]:
        try:
            encoded = json.dumps(
                document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise _IdentityRejected from None
        if len(encoded) > self._config.max_jwks_bytes:
            raise _IdentityRejected
        raw_keys = document.get("keys")
        if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= self._config.max_jwks_keys:
            raise _IdentityRejected
        result: dict[str, jwt.PyJWK] = {}
        observed: set[str] = set()
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                raise _IdentityRejected
            kid = _bounded_claim(raw_key.get("kid"), maximum=128)
            if kid in observed:
                raise _IdentityRejected
            observed.add(kid)
            if raw_key.get("alg") != self._config.algorithm:
                continue
            if raw_key.get("use") not in {None, "sig"}:
                raise _IdentityRejected
            try:
                result[kid] = jwt.PyJWK.from_dict(
                    cast(dict[str, Any], raw_key),
                    algorithm=self._config.algorithm,
                )
            except (jwt.PyJWTError, ValueError, TypeError):
                raise _IdentityRejected from None
        if not result:
            raise _IdentityRejected
        return result

    def _validate_times(self, claims: Mapping[str, object]) -> None:
        issued = _numeric_date(claims.get("iat"))
        not_before = _numeric_date(claims.get("nbf"))
        expires = _numeric_date(claims.get("exp"))
        now = self._wall_clock()
        if not math.isfinite(now):
            raise _IdentityRejected
        skew = self._config.clock_skew_seconds
        if issued > now + skew or not_before > now + skew or expires <= now - skew:
            raise _IdentityRejected
        if expires <= issued or expires - issued > self._config.max_token_lifetime_seconds:
            raise _IdentityRejected


def _require_text(name: str, value: object, *, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} must be bounded visible text")


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _require_text_tuple(name: str, value: object, *, maximum: int) -> None:
    if not isinstance(value, tuple) or not value:
        raise ValueError(f"{name} must be a non-empty tuple")
    items = cast(tuple[object, ...], value)
    for item in items:
        _require_text(name, item, maximum=maximum)
    if len(set(items)) != len(items):
        raise ValueError(f"{name} must not contain duplicates")


def _require_positive_number(name: str, value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{name} must be a positive finite number")


def _require_bounded_number(
    name: str,
    value: object,
    *,
    minimum: float,
    maximum: float,
) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or not minimum <= value <= maximum
    ):
        raise ValueError(f"{name} must be between {minimum:g} and {maximum:g}")


def _bounded_claim(value: object, *, maximum: int) -> str:
    try:
        _require_text("claim", value, maximum=maximum)
    except ValueError:
        raise _IdentityRejected from None
    return cast(str, value)


def _numeric_date(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise _IdentityRejected
    return float(value)


def _scopes(claims: Mapping[str, object]) -> tuple[str, ...]:
    scope = claims.get("scope")
    scp = claims.get("scp")
    primary = _scope_values(scope) if scope is not None else ()
    secondary = _scope_values(scp) if scp is not None else ()
    if primary and secondary and set(primary) != set(secondary):
        raise _IdentityRejected
    values = primary or secondary
    if len(values) > 64 or len(set(values)) != len(values):
        raise _IdentityRejected
    return tuple(sorted(values))


def _scope_values(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        values = tuple(value.split())
    elif isinstance(value, list):
        items = cast(list[object], value)
        if not all(isinstance(item, str) for item in items):
            raise _IdentityRejected
        values = tuple(cast(str, item) for item in items)
    else:
        raise _IdentityRejected
    for item in values:
        try:
            _require_text("scope", item, maximum=256)
        except ValueError:
            raise _IdentityRejected from None
    return values


__all__ = [
    "GatewayIdentityConfig",
    "GatewayIdentityError",
    "GatewayJWTContextProvider",
    "HTTPSJWKSFetcher",
    "JWKSFetchError",
    "JWKSFetcher",
]
