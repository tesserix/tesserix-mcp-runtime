"""Bounded HTTP consumer for the shipped Agentic Registry v0 discovery API."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, TypeGuard, runtime_checkable
from urllib.parse import urlencode

from tesserix_mcp_runtime.contracts import CallContext, CredentialProvider, ErrorCode
from tesserix_mcp_runtime.redaction import (
    RedactionPolicy,
    SecretRedactor,
    SecretValue,
    is_secret_key,
)
from tesserix_mcp_runtime.registry_discovery import (
    RegistryArtifact,
    RegistryArtifactRaceError,
    RegistryAuthenticationError,
    RegistryAuthorizationError,
    RegistryContractError,
    RegistrySearchQuery,
    RegistrySearchStub,
    RegistryUnavailableError,
    canonical_https_origin,
)

from .outbound_http import OutboundHTTPResponse


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def _is_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    return _is_runtime_instance(value, Mapping)


def _is_str(value: object) -> TypeGuard[str]:
    return _is_runtime_instance(value, str)


def _is_text_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    return _is_mapping(value) and all(_is_str(key) for key in value)


def _is_string_mapping(value: object) -> TypeGuard[Mapping[str, str]]:
    return _is_text_mapping(value) and all(
        _is_runtime_instance(item, str) for item in value.values()
    )


def _is_list(value: object) -> TypeGuard[list[object]]:
    return _is_runtime_instance(value, list)


def _is_sequence(value: object) -> TypeGuard[list[object] | tuple[object, ...]]:
    return _is_list(value) or _is_runtime_instance(value, tuple)


class _InvalidRegistryDocument(Exception):
    pass


@runtime_checkable
class RegistryHTTPTransport(Protocol):
    async def request(
        self,
        method: str,
        url: str,
        *,
        request_id: str,
        headers: Mapping[str, str | SecretValue] | None = None,
        content: bytes = b"",
    ) -> OutboundHTTPResponse: ...


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryHTTPDiscoveryLimits:
    max_search_bytes: int = 128 * 1024
    max_artifact_bytes: int = 512 * 1024

    def __post_init__(self) -> None:
        for value, maximum in (
            (self.max_search_bytes, 128 * 1024),
            (self.max_artifact_bytes, 512 * 1024),
        ):
            if (
                _is_runtime_instance(value, bool)
                or not _is_runtime_instance(value, int)
                or not 1 <= value <= maximum
            ):
                raise ValueError("Registry HTTP body limit must be within its hard maximum")


_DEFAULT_LIMITS = RegistryHTTPDiscoveryLimits()
_DEFAULT_REDACTOR = SecretRedactor()


class RegistryHTTPDiscovery:
    """Authorized GET search and same-origin exact fetch over a hardened transport."""

    def __init__(
        self,
        *,
        origin: str,
        transport: RegistryHTTPTransport,
        credential_provider: CredentialProvider[SecretValue] | None = None,
        credential_scopes: tuple[str, ...] = ("registry:read",),
        limits: RegistryHTTPDiscoveryLimits = _DEFAULT_LIMITS,
        redactor: RedactionPolicy = _DEFAULT_REDACTOR,
    ) -> None:
        if not _is_runtime_instance(transport, RegistryHTTPTransport):
            raise TypeError("transport must implement RegistryHTTPTransport")
        if credential_provider is not None and not _is_runtime_instance(
            credential_provider,
            CredentialProvider,
        ):
            raise TypeError("credential_provider must implement CredentialProvider")
        if (
            not _is_runtime_instance(credential_scopes, tuple)
            or not credential_scopes
            or len(credential_scopes) > 16
            or len(credential_scopes) != len(set(credential_scopes))
            or any(
                not _is_runtime_instance(scope, str)
                or not scope
                or scope != scope.strip()
                or len(scope) > 256
                for scope in credential_scopes
            )
        ):
            raise ValueError("credential_scopes must be a bounded immutable tuple")
        if not _is_runtime_instance(limits, RegistryHTTPDiscoveryLimits):
            raise TypeError("limits must be RegistryHTTPDiscoveryLimits")
        if not _is_runtime_instance(redactor, RedactionPolicy):
            raise TypeError("redactor must implement RedactionPolicy")
        self._origin = canonical_https_origin("origin", origin)
        self._transport = transport
        self._credential_provider = credential_provider
        self._credential_scopes = credential_scopes
        self._limits = limits
        self._redactor = redactor

    @property
    def origin(self) -> str:
        return self._origin

    async def search(
        self,
        query: RegistrySearchQuery,
        *,
        context: CallContext,
    ) -> tuple[RegistrySearchStub, ...]:
        if not _is_runtime_instance(query, RegistrySearchQuery) or not _is_runtime_instance(
            context,
            CallContext,
        ):
            raise TypeError("search requires a typed query and authenticated context")
        parameters: list[tuple[str, str]] = [("q", query.intent)]
        parameters.extend(("kinds", kind) for kind in query.kinds)
        if query.namespace is not None:
            parameters.append(("namespace", query.namespace))
        parameters.extend((("limit", str(query.limit)), ("view", "stub")))
        response = await self._transport.request(
            "GET",
            f"{self._origin}/v0/search?{urlencode(parameters)}",
            request_id=context.request_id,
            headers=await self._headers(context),
        )
        self._require_success(response, context=context, ref=None)
        document = self._decode(
            response.body,
            maximum=self._limits.max_search_bytes,
            request_id=context.request_id,
        )
        if not _is_list(document) or len(document) > query.limit:
            raise RegistryContractError(request_id=context.request_id)
        try:
            stubs: list[RegistrySearchStub] = []
            for item in document:
                if not self._secret_safe(item):
                    raise _InvalidRegistryDocument
                stubs.append(self._stub(item))
            return tuple(stubs)
        except (TypeError, ValueError, _InvalidRegistryDocument):
            raise RegistryContractError(request_id=context.request_id) from None

    async def fetch(
        self,
        stub: RegistrySearchStub,
        *,
        context: CallContext,
    ) -> RegistryArtifact:
        if not _is_runtime_instance(stub, RegistrySearchStub) or not _is_runtime_instance(
            context,
            CallContext,
        ):
            raise TypeError("fetch requires a typed stub and authenticated context")
        response = await self._transport.request(
            "GET",
            self._origin + stub.fetch_path,
            request_id=context.request_id,
            headers=await self._headers(context),
        )
        self._require_success(response, context=context, ref=stub.ref)
        document = self._decode(
            response.body,
            maximum=self._limits.max_artifact_bytes,
            request_id=context.request_id,
        )
        try:
            if not self._secret_safe(document):
                raise _InvalidRegistryDocument
            return self._artifact(document)
        except (TypeError, ValueError, _InvalidRegistryDocument):
            raise RegistryContractError(request_id=context.request_id) from None

    async def _headers(self, context: CallContext) -> Mapping[str, str | SecretValue]:
        headers: dict[str, str | SecretValue] = {"accept": "application/json"}
        if self._credential_provider is None:
            return headers
        credential = await self._credential_provider.issue(
            audience=self._origin,
            scopes=self._credential_scopes,
            context=context,
        )
        if not _is_runtime_instance(credential, SecretValue):
            raise RegistryUnavailableError(request_id=context.request_id)
        headers["authorization"] = SecretValue(f"Bearer {credential.reveal()}")
        return headers

    @staticmethod
    def _require_success(
        response: OutboundHTTPResponse,
        *,
        context: CallContext,
        ref: str | None,
    ) -> None:
        if not _is_runtime_instance(response, OutboundHTTPResponse):
            raise RegistryContractError(request_id=context.request_id)
        if response.status_code == 200:
            return
        if response.status_code == 404 and ref is not None:
            raise RegistryArtifactRaceError(request_id=context.request_id, ref=ref)
        if response.status_code in {400, 422}:
            raise RegistryContractError(
                request_id=context.request_id,
                code=ErrorCode.INVALID_INPUT,
            )
        if response.status_code == 401:
            raise RegistryAuthenticationError(request_id=context.request_id)
        if response.status_code == 403:
            raise RegistryAuthorizationError(request_id=context.request_id)
        raise RegistryUnavailableError(request_id=context.request_id)

    @staticmethod
    def _decode(body: bytes, *, maximum: int, request_id: str) -> object:
        if not _is_runtime_instance(body, bytes) or len(body) > maximum:
            raise RegistryContractError(
                request_id=request_id,
                code=ErrorCode.RESULT_TOO_LARGE,
            )

        def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            output: dict[str, object] = {}
            for key, value in pairs:
                if key in output:
                    raise _InvalidRegistryDocument
                output[key] = value
            return output

        try:
            return json.loads(body.decode("utf-8"), object_pairs_hook=object_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, _InvalidRegistryDocument):
            raise RegistryContractError(request_id=request_id) from None

    @classmethod
    def _stub(cls, value: object) -> RegistrySearchStub:
        document = cls._object(value)
        return RegistrySearchStub(
            kind=cls._text(document, "kind"),
            name=cls._text(document, "name"),
            namespace=cls._text(document, "namespace"),
            tag=cls._text(document, "tag"),
            arn=cls._text(document, "arn"),
            digest=cls._text(document, "digest"),
            ref=cls._text(document, "ref"),
            title=cls._optional_text(document, "title"),
            description=cls._optional_text(document, "description"),
            visibility=cls._optional_text(document, "visibility"),
            labels=cls._text_mapping(document.get("labels", {})),
            annotations=cls._text_mapping(document.get("annotations", {})),
            attributes=cls._object(document.get("attributes", {})),
            fetch_path=cls._text(document, "fetchPath"),
        )

    @classmethod
    def _artifact(cls, value: object) -> RegistryArtifact:
        document = cls._object(value)
        metadata = cls._object(document.get("metadata"))
        return RegistryArtifact(
            api_version=cls._text(document, "apiVersion"),
            kind=cls._text(document, "kind"),
            name=cls._text(metadata, "name"),
            namespace=cls._text(metadata, "namespace"),
            tag=cls._text(metadata, "tag"),
            arn=cls._text(metadata, "arn"),
            digest=cls._text(metadata, "digest"),
            ref=cls._text(metadata, "ref"),
            labels=cls._text_mapping(metadata.get("labels", {})),
            spec=cls._object(document.get("spec")),
        )

    @staticmethod
    def _object(value: object) -> Mapping[str, object]:
        if not _is_text_mapping(value):
            raise _InvalidRegistryDocument
        return value

    @staticmethod
    def _text(values: Mapping[str, object], key: str) -> str:
        value = values.get(key)
        if not isinstance(value, str):
            raise _InvalidRegistryDocument
        return value

    @classmethod
    def _optional_text(cls, values: Mapping[str, object], key: str) -> str:
        value = values.get(key, "")
        if not isinstance(value, str):
            raise _InvalidRegistryDocument
        return value

    @classmethod
    def _text_mapping(cls, value: object) -> Mapping[str, str]:
        if not _is_string_mapping(value):
            raise _InvalidRegistryDocument
        return value

    def _secret_safe(
        self,
        value: object,
        *,
        depth: int = 0,
        budget: list[int] | None = None,
    ) -> bool:
        if budget is None:
            budget = [0]
        budget[0] += 1
        if depth > 32 or budget[0] > 32_768:
            return False
        if value is None or isinstance(value, bool | int | float):
            return True
        if isinstance(value, str):
            try:
                return self._redactor.redact_text(value) == value
            except Exception:
                return False
        if _is_mapping(value):
            for key, item in value.items():
                if not _is_str(key):
                    return False
                if is_secret_key(key):
                    if item != "***":
                        return False
                    continue
                if not self._secret_safe(item, depth=depth + 1, budget=budget):
                    return False
            return True
        if _is_sequence(value):
            return all(self._secret_safe(item, depth=depth + 1, budget=budget) for item in value)
        return False


__all__ = [
    "RegistryHTTPDiscovery",
    "RegistryHTTPDiscoveryLimits",
    "RegistryHTTPTransport",
]
