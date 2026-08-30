from __future__ import annotations

import argparse
import hashlib
import re
import threading
from dataclasses import dataclass

import uvicorn
from starlette.types import Receive, Scope, Send

from integration.journey.http import (
    InvalidRequest,
    RequestTooLarge,
    request_headers,
    request_json,
    request_method,
    request_path,
    send_json,
)
from tesserix_mcp_runtime import JsonValue

JOURNEY_CANARY = "SyntheticJourneyCanary8Kq3"

_TENANT = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_SUBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}\Z")
_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TRACEPARENT = re.compile(r"00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}\Z")
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{7,199}\Z")
_ORDER_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_STATUS = re.compile(r"[a-z][a-z_]{0,31}\Z")
_MAX_REQUEST_BYTES = 16_384


class BackingUnavailable(RuntimeError):
    pass


class BackingConflict(RuntimeError):
    pass


class BackingForbidden(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class BackingContext:
    tenant: str
    subject: str
    scopes: tuple[str, ...]
    request_id: str
    trace_id: str
    idempotency_key: str | None

    def __post_init__(self) -> None:
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
            or not isinstance(self.request_id, str)
            or _REQUEST_ID.fullmatch(self.request_id) is None
            or not isinstance(self.trace_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", self.trace_id) is None
            or (
                self.idempotency_key is not None
                and (
                    not isinstance(self.idempotency_key, str)
                    or _IDEMPOTENCY_KEY.fullmatch(self.idempotency_key) is None
                )
            )
        ):
            raise ValueError("backing context must contain bounded verified authority")

    def __repr__(self) -> str:
        return (
            "BackingContext("
            f"tenant={self.tenant!r}, scope_count={len(self.scopes)}, "
            f"request_id={self.request_id!r}, trace_id={self.trace_id!r}, "
            f"has_idempotency_key={self.idempotency_key is not None})"
        )

    def to_document(self) -> dict[str, JsonValue]:
        scopes: list[JsonValue] = list(self.scopes)
        return {
            "request_id": self.request_id,
            "scopes": sorted(scopes, key=str),
            "subject_hash": hashlib.sha256(self.subject.encode()).hexdigest(),
            "tenant": self.tenant,
            "trace_id": self.trace_id,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class BackingObservation:
    operation: str
    context: BackingContext
    replayed: bool

    def to_document(self) -> dict[str, JsonValue]:
        return {
            "context": self.context.to_document(),
            "operation": self.operation,
            "replayed": self.replayed,
        }


@dataclass(frozen=True, slots=True)
class _StoredEffect:
    fingerprint: str
    result: dict[str, JsonValue]


class BackingStore:
    def __init__(self) -> None:
        self._available = True
        self._effects: dict[tuple[str, str], _StoredEffect] = {}
        self._orders: dict[tuple[str, str], dict[str, JsonValue]] = {}
        self._observations: list[BackingObservation] = []
        self._effect_count = 0
        self._lock = threading.Lock()

    @property
    def effect_count(self) -> int:
        with self._lock:
            return self._effect_count

    @property
    def observations(self) -> tuple[BackingObservation, ...]:
        with self._lock:
            return tuple(self._observations)

    def set_available(self, available: bool) -> None:
        if not isinstance(available, bool):
            raise ValueError("availability must be boolean")
        with self._lock:
            self._available = available

    def liveness(self) -> bool:
        return True

    def readiness(self) -> bool:
        with self._lock:
            return self._available

    def read_order(self, context: BackingContext, *, order_id: str) -> dict[str, JsonValue]:
        self._validate_order(order_id)
        with self._lock:
            self._require_available()
            self._require_scope(context, "journey:read")
            result = self._orders.get(
                (context.tenant, order_id),
                {"order_id": order_id, "status": "missing"},
            )
            self._record("read_order", context, replayed=False)
            return dict(result)

    def write_order(
        self,
        context: BackingContext,
        *,
        order_id: str,
        value: str,
    ) -> dict[str, JsonValue]:
        self._validate_order(order_id)
        if not isinstance(value, str) or _STATUS.fullmatch(value) is None:
            raise ValueError("order status must be bounded text")
        with self._lock:
            self._require_available()
            self._require_scope(context, "journey:write")
            if context.idempotency_key is None:
                raise BackingConflict
            key = (context.tenant, context.idempotency_key)
            fingerprint = hashlib.sha256(f"{order_id}\0{value}".encode()).hexdigest()
            existing = self._effects.get(key)
            if existing is not None:
                if existing.fingerprint != fingerprint:
                    raise BackingConflict
                self._record("write_order", context, replayed=True)
                return dict(existing.result)
            self._effect_count += 1
            result: dict[str, JsonValue] = {
                "effect_id": f"effect-{self._effect_count:06d}",
                "order_id": order_id,
                "status": value,
            }
            self._effects[key] = _StoredEffect(fingerprint=fingerprint, result=result)
            self._orders[(context.tenant, order_id)] = dict(result)
            self._record("write_order", context, replayed=False)
            return dict(result)

    def secret_canary(self, context: BackingContext) -> dict[str, JsonValue]:
        with self._lock:
            self._require_available()
            self._require_scope(context, "journey:read")
            self._record("secret_canary", context, replayed=False)
            return {"api_key": JOURNEY_CANARY}

    def _record(self, operation: str, context: BackingContext, *, replayed: bool) -> None:
        self._observations.append(
            BackingObservation(operation=operation, context=context, replayed=replayed)
        )

    def _require_available(self) -> None:
        if not self._available:
            raise BackingUnavailable

    @staticmethod
    def _require_scope(context: BackingContext, scope: str) -> None:
        if scope not in context.scopes:
            raise BackingForbidden

    @staticmethod
    def _validate_order(order_id: str) -> None:
        if not isinstance(order_id, str) or _ORDER_ID.fullmatch(order_id) is None:
            raise ValueError("order id must be bounded text")


class BackingService:
    def __init__(self, store: BackingStore) -> None:
        if not isinstance(store, BackingStore):
            raise TypeError("store must be BackingStore")
        self._store = store

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("backing service supports HTTP only")
        method = request_method(scope)
        path = request_path(scope)
        if method == "GET" and path == "/health/live":
            await send_json(send, 200, {"status": "ok"})
            return
        if method == "GET" and path == "/health/ready":
            status = 200 if self._store.readiness() else 503
            await send_json(send, status, {"ready": self._store.readiness()})
            return
        if method == "GET" and path == "/control/observations":
            await send_json(
                send,
                200,
                {
                    "available": self._store.readiness(),
                    "effect_count": self._store.effect_count,
                    "observations": [item.to_document() for item in self._store.observations],
                },
            )
            return
        if method == "PUT" and path == "/control/availability":
            await self._availability(receive, send)
            return
        await self._tool_request(method, path, scope, receive, send)

    async def _availability(self, receive: Receive, send: Send) -> None:
        try:
            document = await request_json(receive, maximum_bytes=_MAX_REQUEST_BYTES)
            if set(document) != {"available"} or not isinstance(document["available"], bool):
                raise InvalidRequest
        except RequestTooLarge:
            await send_json(send, 413, {"code": "request_too_large"})
            return
        except (InvalidRequest, KeyError):
            await send_json(send, 400, {"code": "invalid_request"})
            return
        available = document["available"]
        self._store.set_available(available)
        await send_json(send, 200, {"available": available})

    async def _tool_request(
        self,
        method: str,
        path: str,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        try:
            context = self._context(scope)
            if method == "GET" and path == "/v1/canary":
                result = self._store.secret_canary(context)
            elif path.startswith("/v1/orders/"):
                order_id = path.removeprefix("/v1/orders/")
                if method == "GET":
                    result = self._store.read_order(context, order_id=order_id)
                elif method == "POST":
                    document = await request_json(receive, maximum_bytes=_MAX_REQUEST_BYTES)
                    if set(document) != {"status"} or not isinstance(document["status"], str):
                        raise InvalidRequest
                    result = self._store.write_order(
                        context,
                        order_id=order_id,
                        value=document["status"],
                    )
                else:
                    await send_json(send, 405, {"code": "method_not_allowed"})
                    return
            else:
                await send_json(send, 404, {"code": "not_found"})
                return
        except RequestTooLarge:
            await send_json(send, 413, {"code": "request_too_large"})
            return
        except (InvalidRequest, ValueError):
            await send_json(send, 400, {"code": "invalid_request"})
            return
        except BackingForbidden:
            await send_json(send, 404, {"code": "not_found"})
            return
        except BackingConflict:
            await send_json(send, 409, {"code": "idempotency_conflict"})
            return
        except BackingUnavailable:
            await send_json(send, 503, {"code": "backing_unavailable"})
            return
        await send_json(send, 200, result)

    @staticmethod
    def _context(scope: Scope) -> BackingContext:
        headers = request_headers(scope)
        traceparent = headers.get("traceparent", "")
        matched = _TRACEPARENT.fullmatch(traceparent)
        if matched is None:
            raise InvalidRequest
        scopes = tuple(sorted(headers.get("x-journey-scopes", "").split()))
        return BackingContext(
            tenant=headers.get("x-journey-tenant", ""),
            subject=headers.get("x-journey-subject", ""),
            scopes=scopes,
            request_id=headers.get("x-request-id", ""),
            trace_id=matched.group(1),
            idempotency_key=headers.get("idempotency-key"),
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8082)
    arguments = parser.parse_args()
    uvicorn.run(
        BackingService(BackingStore()),
        host=arguments.host,
        port=arguments.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()


__all__ = [
    "JOURNEY_CANARY",
    "BackingConflict",
    "BackingContext",
    "BackingService",
    "BackingStore",
    "BackingUnavailable",
]
