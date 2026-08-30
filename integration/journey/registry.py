from __future__ import annotations

import json
from collections.abc import Mapping
from typing import NoReturn
from urllib.parse import SplitResult, urlsplit, urlunsplit

import httpx

from tesserix_mcp_runtime import CallContext, SecretValue
from tesserix_mcp_runtime.adapters.outbound_http import OutboundHTTPResponse

REGISTRY_ORIGIN = "https://registry.journey.invalid"
_MAX_TOKEN_RESPONSE_BYTES = 16 * 1024
_MAX_REGISTRY_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_REQUEST_BYTES = 1024 * 1024


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise _DuplicateKeyError
        output[key] = value
    return output


def _reject_constant(_: str) -> NoReturn:
    raise ValueError


def decode_json_value(body: bytes, *, maximum: int) -> object:
    if not isinstance(body, bytes) or not body or len(body) > maximum:
        raise RuntimeError("journey_boundary_invalid")
    try:
        return json.loads(
            body.decode(),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError, ValueError):
        raise RuntimeError("journey_boundary_invalid") from None


def decode_json_object(body: bytes, *, maximum: int) -> Mapping[str, object]:
    value = decode_json_value(body, maximum=maximum)
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise RuntimeError("journey_boundary_invalid")
    return value


def _origin(value: str, *, allow_http: bool) -> SplitResult:
    parsed = urlsplit(value)
    schemes = {"http", "https"} if allow_http else {"https"}
    if (
        not isinstance(value, str)
        or len(value) > 2_048
        or parsed.scheme not in schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("journey origin must be an exact bounded HTTP origin")
    return parsed


class JourneyCredentialProvider:
    def __init__(
        self,
        *,
        token_origin: str,
        audience: str,
        client: httpx.AsyncClient,
    ) -> None:
        parsed = _origin(token_origin, allow_http=True)
        if not isinstance(audience, str) or len(audience) > 2_048:
            raise ValueError("credential audience must be bounded")
        _origin(audience, allow_http=False)
        if not isinstance(client, httpx.AsyncClient):
            raise TypeError("client must be an AsyncClient")
        self._token_origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        self._audience = audience
        self._client = client

    async def issue(
        self,
        *,
        audience: str,
        scopes: tuple[str, ...],
        context: CallContext,
    ) -> SecretValue:
        if audience != self._audience:
            raise RuntimeError("journey_credential_audience")
        if (
            not isinstance(context, CallContext)
            or not isinstance(scopes, tuple)
            or not 1 <= len(scopes) <= 32
            or len(scopes) != len(set(scopes))
            or any(
                not isinstance(scope, str)
                or not scope
                or scope != scope.strip()
                or len(scope) > 128
                for scope in scopes
            )
        ):
            raise RuntimeError("journey_credential_request")
        try:
            response = await self._client.post(
                self._token_origin + "/token",
                headers={"x-request-id": context.request_id},
                json={
                    "run_id": context.run_id,
                    "scopes": list(scopes),
                    "subject": context.subject,
                    "tenant": context.tenant,
                },
                follow_redirects=False,
                timeout=10.0,
            )
        except httpx.HTTPError:
            raise RuntimeError("journey_credential_unavailable") from None
        if response.status_code != 200:
            raise RuntimeError("journey_credential_unavailable")
        document = decode_json_object(
            response.content,
            maximum=_MAX_TOKEN_RESPONSE_BYTES,
        )
        if set(document) != {"access_token", "expires_in", "token_type"}:
            raise RuntimeError("journey_credential_invalid")
        token = document.get("access_token")
        expires_in = document.get("expires_in")
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= 16_384
            or document.get("token_type") != "Bearer"
            or isinstance(expires_in, bool)
            or not isinstance(expires_in, int)
            or not 30 <= expires_in <= 900
        ):
            raise RuntimeError("journey_credential_invalid")
        return SecretValue(token)


class JourneyRegistryTransport:
    def __init__(self, *, isolated_origin: str, client: httpx.AsyncClient) -> None:
        parsed = _origin(isolated_origin, allow_http=True)
        if not isinstance(client, httpx.AsyncClient):
            raise TypeError("client must be an AsyncClient")
        self._isolated = parsed
        self._client = client

    async def request(
        self,
        method: str,
        url: str,
        *,
        request_id: str,
        headers: Mapping[str, str | SecretValue] | None = None,
        content: bytes = b"",
    ) -> OutboundHTTPResponse:
        parsed = urlsplit(url)
        if (
            method not in {"GET", "POST"}
            or parsed.scheme != "https"
            or parsed.netloc != "registry.journey.invalid"
            or not parsed.path.startswith("/v0/")
            or parsed.fragment
            or not isinstance(request_id, str)
            or not 1 <= len(request_id) <= 256
            or any(ord(character) < 32 for character in request_id)
            or not isinstance(content, bytes)
            or len(content) > _MAX_REQUEST_BYTES
        ):
            raise ValueError("request must use the fixed synthetic Registry origin")
        outbound_headers: dict[str, str] = {"x-request-id": request_id}
        for key, value in (headers or {}).items():
            if (
                not isinstance(key, str)
                or not key
                or len(key) > 256
                or not isinstance(value, str | SecretValue)
            ):
                raise ValueError("Registry headers must be bounded")
            revealed = value.reveal() if isinstance(value, SecretValue) else value
            if len(revealed) > 16_384 or "\r" in revealed or "\n" in revealed:
                raise ValueError("Registry headers must be bounded")
            outbound_headers[key] = revealed
        rewritten = urlunsplit(
            (
                self._isolated.scheme,
                self._isolated.netloc,
                parsed.path,
                parsed.query,
                "",
            )
        )
        try:
            response = await self._client.request(
                method,
                rewritten,
                headers=outbound_headers,
                content=content,
                follow_redirects=False,
                timeout=10.0,
            )
        except httpx.HTTPError:
            raise RuntimeError("journey_registry_unavailable") from None
        if len(response.content) > _MAX_REGISTRY_RESPONSE_BYTES:
            raise RuntimeError("journey_registry_response_too_large")
        response_headers = tuple(response.headers.multi_items())
        if len(response_headers) > 128 or any(
            len(key) > 256 or len(value) > 16_384 for key, value in response_headers
        ):
            raise RuntimeError("journey_registry_response_invalid")
        return OutboundHTTPResponse(
            status_code=response.status_code,
            headers=response_headers,
            body=response.content,
        )


__all__ = [
    "REGISTRY_ORIGIN",
    "JourneyCredentialProvider",
    "JourneyRegistryTransport",
]
