from __future__ import annotations

import argparse
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import cast
from urllib.parse import urlsplit

import jwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.types import Receive, Scope, Send

from integration.journey.http import (
    InvalidRequest,
    RequestTooLarge,
    request_json,
    request_method,
    request_path,
    send_json,
)
from tesserix_mcp_runtime import JsonValue, SecretValue

_TENANT = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_SUBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}\Z")
_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TOKEN_REQUEST_BYTES = 16_384
ROUTE_SCOPE_CLAIM = "urn:zitadel:iam:org:project:roles"


class AdversarialTokenCase(StrEnum):
    MALFORMED = "malformed"
    EXPIRED = "expired"
    FORGED_SIGNATURE = "forged_signature"
    WRONG_AUDIENCE = "wrong_audience"
    WRONG_ISSUER = "wrong_issuer"
    WRONG_ALGORITHM = "wrong_algorithm"
    REVOKED_KEY = "revoked_key"
    CLAIM_DISAGREEMENT = "claim_disagreement"


@dataclass(frozen=True, slots=True, kw_only=True)
class TokenRequest:
    tenant: str
    subject: str
    scopes: tuple[str, ...]
    run_id: str

    def validate(self) -> None:
        if (
            not isinstance(self.tenant, str)
            or _TENANT.fullmatch(self.tenant) is None
            or not isinstance(self.subject, str)
            or _SUBJECT.fullmatch(self.subject) is None
            or not isinstance(self.scopes, tuple)
            or not 1 <= len(self.scopes) <= 32
            or any(
                not isinstance(scope, str) or _SCOPE.fullmatch(scope) is None
                for scope in self.scopes
            )
            or len(set(self.scopes)) != len(self.scopes)
            or not isinstance(self.run_id, str)
            or _RUN_ID.fullmatch(self.run_id) is None
        ):
            raise ValueError("token request must contain bounded tenant authority")


class IdentityAuthority:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        now: Callable[[], int] = lambda: int(time.time()),
        token_ttl_seconds: int = 300,
    ) -> None:
        parsed = urlsplit(issuer)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not isinstance(audience, str)
            or _SCOPE.fullmatch(audience) is None
            or isinstance(token_ttl_seconds, bool)
            or not isinstance(token_ttl_seconds, int)
            or not 30 <= token_ttl_seconds <= 900
        ):
            raise ValueError("identity authority requires bounded exact configuration")
        self._issuer = issuer
        self._audience = audience
        self._now = now
        self._ttl = token_ttl_seconds
        self._kid = "journey-rs256-001"
        self._private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
        self._attacker_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
        self._retired_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
        raw_public: object = json.loads(RSAAlgorithm.to_jwk(self._private_key.public_key()))
        if not isinstance(raw_public, dict):
            raise RuntimeError("public key conversion failed")
        public = {
            key: value
            for key, value in cast(dict[str, JsonValue], raw_public).items()
            if key in {"e", "kty", "n"}
        }
        public.update({"alg": "RS256", "kid": self._kid, "use": "sig"})
        self._public = public

    @property
    def token_ttl_seconds(self) -> int:
        return self._ttl

    def jwks_document(self) -> dict[str, JsonValue]:
        return {"keys": [dict(self._public)]}

    def issue(self, request: TokenRequest) -> SecretValue:
        if not isinstance(request, TokenRequest):
            raise ValueError("request must use TokenRequest")
        request.validate()
        now = self._now()
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise RuntimeError("identity clock failed")
        encoded = jwt.encode(
            self._claims(request, now=now),
            self._private_key,
            algorithm="RS256",
            headers={"kid": self._kid},
        )
        if not isinstance(encoded, str):
            raise RuntimeError("token encoder failed")
        return SecretValue(encoded)

    def issue_adversarial(
        self,
        request: TokenRequest,
        case: AdversarialTokenCase,
    ) -> SecretValue:
        if not isinstance(request, TokenRequest) or not isinstance(case, AdversarialTokenCase):
            raise ValueError("adversarial token request is invalid")
        request.validate()
        now = self._now()
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise RuntimeError("identity clock failed")
        if case is AdversarialTokenCase.MALFORMED:
            return SecretValue("malformed.token.value")
        claims = self._claims(request, now=now)
        key = self._private_key
        kid = self._kid
        algorithm = "RS256"
        if case is AdversarialTokenCase.EXPIRED:
            claims.update(
                {
                    "iat": now - self._ttl - 1,
                    "nbf": now - self._ttl - 1,
                    "exp": now - self._ttl,
                }
            )
        elif case is AdversarialTokenCase.FORGED_SIGNATURE:
            key = self._attacker_key
        elif case is AdversarialTokenCase.WRONG_AUDIENCE:
            claims["aud"] = "https://other-audience.journey.invalid"
        elif case is AdversarialTokenCase.WRONG_ISSUER:
            claims["iss"] = "https://other-identity.journey.invalid"
        elif case is AdversarialTokenCase.WRONG_ALGORITHM:
            algorithm = "none"
        elif case is AdversarialTokenCase.REVOKED_KEY:
            key = self._retired_key
            kid = "journey-retired-001"
        elif case is AdversarialTokenCase.CLAIM_DISAGREEMENT:
            claims["scp"] = ["journey:admin"]
        if algorithm == "none":
            encoded = jwt.encode(claims, key="", algorithm=algorithm, headers={"kid": kid})
        else:
            encoded = jwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid})
        if not isinstance(encoded, str):
            raise RuntimeError("token encoder failed")
        return SecretValue(encoded)

    def _claims(self, request: TokenRequest, *, now: int) -> dict[str, object]:
        route_roles = {
            scope: {request.tenant: f"{request.tenant}.journey.invalid"}
            for scope in request.scopes
            if scope.startswith("mcp:")
        }
        return {
            "aud": self._audience,
            "exp": now + self._ttl,
            "groups": [f"{request.tenant}:writer"],
            "iat": now,
            "iss": self._issuer,
            "nbf": now,
            "run_id": request.run_id,
            "scope": " ".join(request.scopes),
            "sub": request.subject,
            "tenant_id": request.tenant,
            ROUTE_SCOPE_CLAIM: route_roles,
        }


class IdentityService:
    def __init__(self, authority: IdentityAuthority) -> None:
        if not isinstance(authority, IdentityAuthority):
            raise TypeError("authority must be IdentityAuthority")
        self._authority = authority
        self._available = True
        self._events: list[str] = []

    @property
    def events(self) -> tuple[str, ...]:
        return tuple(self._events)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("identity service supports HTTP only")
        method = request_method(scope)
        path = request_path(scope)
        if method == "GET" and path == "/health":
            self._events.append("health")
            await send_json(send, 200, {"status": "ok"})
            return
        if method == "PUT" and path == "/control/availability":
            await self._availability(receive, send)
            return
        if not self._available and path in {
            "/adversarial-token",
            "/jwks.json",
            "/token",
        }:
            await send_json(send, 503, {"code": "unavailable"})
            return
        if method == "GET" and path == "/jwks.json":
            self._events.append("jwks")
            await send_json(send, 200, self._authority.jwks_document())
            return
        if method == "POST" and path == "/token":
            await self._token(receive, send)
            return
        if method == "POST" and path == "/adversarial-token":
            await self._adversarial_token(receive, send)
            return
        await send_json(send, 404, {"code": "not_found"})

    async def _availability(self, receive: Receive, send: Send) -> None:
        try:
            document = await request_json(receive, maximum_bytes=_TOKEN_REQUEST_BYTES)
            if set(document) != {"available"} or not isinstance(document["available"], bool):
                raise InvalidRequest
        except RequestTooLarge:
            await send_json(send, 413, {"code": "request_too_large"})
            return
        except (InvalidRequest, KeyError):
            await send_json(send, 400, {"code": "invalid_request"})
            return
        available = document["available"]
        self._available = available
        await send_json(send, 200, {"available": available})

    async def _token(self, receive: Receive, send: Send) -> None:
        try:
            document = await request_json(receive, maximum_bytes=_TOKEN_REQUEST_BYTES)
        except RequestTooLarge:
            await send_json(send, 413, {"code": "request_too_large"})
            return
        except InvalidRequest:
            await send_json(send, 400, {"code": "invalid_request"})
            return
        try:
            if set(document) != {"run_id", "scopes", "subject", "tenant"}:
                raise ValueError
            scopes = document["scopes"]
            if not isinstance(scopes, list) or any(not isinstance(item, str) for item in scopes):
                raise ValueError
            request = TokenRequest(
                tenant=cast(str, document["tenant"]),
                subject=cast(str, document["subject"]),
                scopes=tuple(cast(list[str], scopes)),
                run_id=cast(str, document["run_id"]),
            )
            token = self._authority.issue(request)
        except (KeyError, TypeError, ValueError):
            await send_json(send, 400, {"code": "invalid_request"})
            return
        self._events.append("token_issued")
        await send_json(
            send,
            200,
            {
                "access_token": token.reveal(),
                "expires_in": self._authority.token_ttl_seconds,
                "token_type": "Bearer",
            },
        )

    async def _adversarial_token(self, receive: Receive, send: Send) -> None:
        try:
            document = await request_json(receive, maximum_bytes=_TOKEN_REQUEST_BYTES)
        except RequestTooLarge:
            await send_json(send, 413, {"code": "request_too_large"})
            return
        except InvalidRequest:
            await send_json(send, 400, {"code": "invalid_request"})
            return
        try:
            if set(document) != {"case", "run_id", "scopes", "subject", "tenant"}:
                raise ValueError
            scopes = document["scopes"]
            if not isinstance(scopes, list) or any(not isinstance(item, str) for item in scopes):
                raise ValueError
            case = AdversarialTokenCase(cast(str, document["case"]))
            request = TokenRequest(
                tenant=cast(str, document["tenant"]),
                subject=cast(str, document["subject"]),
                scopes=tuple(cast(list[str], scopes)),
                run_id=cast(str, document["run_id"]),
            )
            token = self._authority.issue_adversarial(request, case)
        except (KeyError, TypeError, ValueError):
            await send_json(send, 400, {"code": "invalid_request"})
            return
        self._events.append("adversarial_token_issued")
        await send_json(
            send,
            200,
            {
                "access_token": token.reveal(),
                "case": case.value,
                "token_type": "Bearer",
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--issuer", default="https://identity.journey.invalid")
    parser.add_argument("--audience", default="tesserix-mcp-journey")
    arguments = parser.parse_args()
    service = IdentityService(
        IdentityAuthority(issuer=arguments.issuer, audience=arguments.audience)
    )
    uvicorn.run(service, host=arguments.host, port=arguments.port, access_log=False)


if __name__ == "__main__":
    main()


__all__ = [
    "ROUTE_SCOPE_CLAIM",
    "AdversarialTokenCase",
    "IdentityAuthority",
    "IdentityService",
    "TokenRequest",
]
