from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast
from urllib.parse import quote, urlencode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tesserix_mcp_publisher import (
    PreparedPublication,
    PublicationError,
    PublicationErrorCode,
    PublishedArtifact,
    PublishReceipt,
)

from integration.journey.gateway import AgentGatewayExport, parse_agentgateway_export
from integration.journey.identity import ROUTE_SCOPE_CLAIM
from integration.journey.registry import (
    REGISTRY_ORIGIN,
    JourneyCredentialProvider,
    decode_json_object,
    decode_json_value,
)
from tesserix_mcp_runtime import CallContext, JsonValue, SecretValue
from tesserix_mcp_runtime.adapters.outbound_http import OutboundHTTPResponse
from tesserix_mcp_runtime.adapters.registry_http import RegistryHTTPTransport

_AUTHORING = Path(__file__).with_name("authoring.json")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_PLACEHOLDER_DIGEST = "sha256:" + "0" * 64
_MAX_AUTHORING_BYTES = 1024 * 1024
_MAX_REGISTRY_DOCUMENT_BYTES = 1024 * 1024
_MAX_SIGNING_KEY_BYTES = 16 * 1024
_MAX_REVISIONS = 128


def _publication_error(
    code: PublicationErrorCode,
    *,
    request_id: str,
    retryable: bool = False,
) -> PublicationError:
    return PublicationError(code, request_id=request_id, retryable=retryable)


def _mapping(value: object, *, request_id: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise _publication_error(
            PublicationErrorCode.COMMAND_OUTPUT_INVALID,
            request_id=request_id,
        )
    return value


def _text(values: Mapping[str, object], key: str, *, request_id: str) -> str:
    value = values.get(key)
    if not isinstance(value, str) or not value:
        raise _publication_error(
            PublicationErrorCode.COMMAND_OUTPUT_INVALID,
            request_id=request_id,
        )
    return value


class AgenticRegistryClient:
    def __init__(
        self,
        *,
        transport: RegistryHTTPTransport,
        credential_provider: JourneyCredentialProvider,
        context: CallContext,
    ) -> None:
        if not isinstance(transport, RegistryHTTPTransport):
            raise TypeError("transport must implement RegistryHTTPTransport")
        if not isinstance(credential_provider, JourneyCredentialProvider):
            raise TypeError("credential_provider must be JourneyCredentialProvider")
        if not isinstance(context, CallContext):
            raise TypeError("context must be an authenticated CallContext")
        self._transport = transport
        self._credential_provider = credential_provider
        self._context = context

    async def remote_validate(
        self,
        prepared: PreparedPublication,
        *,
        idempotency_key: str,
        request_id: str,
    ) -> None:
        response = await self._request(
            "POST",
            "/v0/apply?dryRun=true",
            request_id=request_id,
            idempotency_key=idempotency_key,
            content=prepared.registry_manifest,
            scopes=("registry:read", "registry:write"),
        )
        document = self._document(response, request_id=request_id)
        if document.get("dry_run") is not True:
            raise _publication_error(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            )
        self._applied(document, prepared=prepared, request_id=request_id)

    async def publish(
        self,
        prepared: PreparedPublication,
        *,
        idempotency_key: str,
        request_id: str,
    ) -> PublishReceipt:
        response = await self._request(
            "POST",
            "/v0/apply",
            request_id=request_id,
            idempotency_key=idempotency_key,
            content=prepared.registry_manifest,
            scopes=("registry:read", "registry:write"),
        )
        created = self._applied(
            self._document(response, request_id=request_id),
            prepared=prepared,
            request_id=request_id,
        )
        return PublishReceipt(created=created)

    async def fetch(
        self,
        prepared: PreparedPublication,
        *,
        request_id: str,
    ) -> PublishedArtifact:
        path = (
            "/v0/mcpservers/"
            + quote(prepared.name, safe="")
            + "/"
            + quote(prepared.version, safe="")
            + "?"
            + urlencode({"namespace": prepared.namespace})
        )
        response = await self._request("GET", path, request_id=request_id)
        document = self._document(response, request_id=request_id)
        metadata = _mapping(document.get("metadata"), request_id=request_id)
        return PublishedArtifact(
            name=_text(metadata, "name", request_id=request_id),
            namespace=_text(metadata, "namespace", request_id=request_id),
            version=_text(metadata, "tag", request_id=request_id),
            ref=_text(metadata, "ref", request_id=request_id),
            digest=_text(metadata, "digest", request_id=request_id),
            signature=_text(metadata, "signature", request_id=request_id),
            signed_by=_text(metadata, "signedBy", request_id=request_id),
        )

    async def verify(
        self,
        artifact: PublishedArtifact,
        *,
        request_id: str,
    ) -> None:
        response = await self._request("GET", "/v0/signing-key", request_id=request_id)
        try:
            document = decode_json_object(response.body, maximum=_MAX_SIGNING_KEY_BYTES)
            if (
                set(document) != {"algorithm", "enabled", "encoding", "keyId", "publicKey", "signs"}
                or document.get("enabled") is not True
                or document.get("algorithm") != "ed25519"
                or document.get("encoding") != "base64"
                or document.get("signs") != "digest"
                or document.get("keyId") != artifact.signed_by
            ):
                raise ValueError
            encoded_key = document.get("publicKey")
            if not isinstance(encoded_key, str):
                raise ValueError
            raw_key = base64.b64decode(encoded_key, validate=True)
            raw_signature = base64.b64decode(artifact.signature, validate=True)
            if len(raw_key) != 32 or len(raw_signature) != 64:
                raise ValueError
            Ed25519PublicKey.from_public_bytes(raw_key).verify(
                raw_signature,
                artifact.digest.encode(),
            )
        except (InvalidSignature, RuntimeError, TypeError, ValueError):
            raise _publication_error(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            ) from None

    async def revision_count(
        self,
        prepared: PreparedPublication,
        *,
        request_id: str,
    ) -> int:
        path = (
            "/v0/mcpservers/"
            + quote(prepared.name, safe="")
            + "/revisions?"
            + urlencode({"namespace": prepared.namespace})
        )
        response = await self._request("GET", path, request_id=request_id)
        try:
            document = decode_json_value(
                response.body,
                maximum=_MAX_REGISTRY_DOCUMENT_BYTES,
            )
            if (
                not isinstance(document, list)
                or len(document) > _MAX_REVISIONS
                or any(
                    not isinstance(item, dict)
                    or isinstance(item.get("revision"), bool)
                    or not isinstance(item.get("revision"), int)
                    or item["revision"] < 1
                    for item in document
                )
            ):
                raise ValueError
            return len(document)
        except (RuntimeError, TypeError, ValueError):
            raise _publication_error(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            ) from None

    async def export_agentgateway(
        self,
        *,
        namespace: str,
        request_id: str,
        require_server_scope: bool,
    ) -> AgentGatewayExport:
        if namespace != self._context.tenant or not isinstance(require_server_scope, bool):
            raise _publication_error(
                PublicationErrorCode.INVALID_ARGUMENT,
                request_id=request_id,
            )
        query = {
            "legacyFlatPath": "false",
            "namespace": namespace,
            "requireServerScope": str(require_server_scope).lower(),
            "targetNamespace": "agentgateway-system",
        }
        if require_server_scope:
            query["scopeClaim"] = ROUTE_SCOPE_CLAIM
        path = "/v0/export/agentgateway?" + urlencode(query)
        response = await self._request("GET", path, request_id=request_id)
        try:
            return parse_agentgateway_export(response)
        except ValueError:
            raise _publication_error(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            ) from None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        request_id: str,
        idempotency_key: str | None = None,
        content: bytes = b"",
        scopes: tuple[str, ...] = ("registry:read",),
    ) -> OutboundHTTPResponse:
        context = replace(self._context, request_id=request_id)
        credential = await self._credential_provider.issue(
            audience=REGISTRY_ORIGIN,
            scopes=scopes,
            context=context,
        )
        headers: dict[str, str | SecretValue] = {
            "accept": "application/json",
            "authorization": SecretValue(f"Bearer {credential.reveal()}"),
        }
        if content:
            headers["content-type"] = "application/yaml"
        if idempotency_key is not None:
            headers["idempotency-key"] = idempotency_key
        response = await self._transport.request(
            method,
            REGISTRY_ORIGIN + path,
            request_id=request_id,
            headers=headers,
            content=content,
        )
        if response.status_code == 200:
            return response
        if response.status_code == 409:
            raise _publication_error(PublicationErrorCode.CONFLICT, request_id=request_id)
        if response.status_code in {429, 500, 502, 503, 504}:
            raise _publication_error(
                PublicationErrorCode.UNAVAILABLE,
                request_id=request_id,
                retryable=True,
            )
        raise _publication_error(PublicationErrorCode.COMMAND_FAILED, request_id=request_id)

    @staticmethod
    def _document(
        response: OutboundHTTPResponse,
        *,
        request_id: str,
    ) -> Mapping[str, object]:
        try:
            return decode_json_object(
                response.body,
                maximum=_MAX_REGISTRY_DOCUMENT_BYTES,
            )
        except RuntimeError:
            raise _publication_error(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            ) from None

    @staticmethod
    def _applied(
        document: Mapping[str, object],
        *,
        prepared: PreparedPublication,
        request_id: str,
    ) -> bool:
        applied = document.get("applied")
        if document.get("count") != 1 or not isinstance(applied, list) or len(applied) != 1:
            raise _publication_error(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            )
        item = _mapping(applied[0], request_id=request_id)
        created = item.get("created")
        if (
            item.get("kind") != "MCPServer"
            or item.get("name") != prepared.name
            or item.get("namespace") != prepared.namespace
            or item.get("tag") != prepared.version
            or not isinstance(created, bool)
        ):
            raise _publication_error(
                PublicationErrorCode.COMMAND_OUTPUT_INVALID,
                request_id=request_id,
            )
        return created


def render_authoring(
    image_digest: str,
    *,
    version: str = "1.0.0",
    source: Path = _AUTHORING,
) -> bytes:
    if (
        not isinstance(image_digest, str)
        or _DIGEST.fullmatch(image_digest) is None
        or image_digest == _PLACEHOLDER_DIGEST
        or not isinstance(version, str)
        or _VERSION.fullmatch(version) is None
        or not isinstance(source, Path)
    ):
        raise ValueError("authoring render requires an immutable image digest")
    raw = source.read_bytes()
    if not raw or len(raw) > _MAX_AUTHORING_BYTES:
        raise ValueError("authoring source must be a bounded JSON document")
    try:
        document = cast(dict[str, JsonValue], json.loads(raw))
        package = document["package"]
        source_version = document.get("version")
        identifier = package.get("identifier") if isinstance(package, dict) else None
        if (
            not isinstance(package, dict)
            or package.get("image_digest") != _PLACEHOLDER_DIGEST
            or not isinstance(source_version, str)
            or not isinstance(identifier, str)
            or not identifier.endswith(":" + source_version)
        ):
            raise ValueError
        package["image_digest"] = image_digest
        package["identifier"] = identifier.removesuffix(source_version) + version
        document["version"] = version
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("authoring source must contain the digest placeholder") from None
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )


__all__ = ["AgenticRegistryClient", "render_authoring"]
