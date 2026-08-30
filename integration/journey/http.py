from __future__ import annotations

import json
from collections.abc import Mapping

from starlette.types import Message, Receive, Scope, Send

from tesserix_mcp_runtime import JsonValue


class RequestTooLarge(ValueError):
    pass


class InvalidRequest(ValueError):
    pass


def request_method(scope: Scope) -> str:
    value = scope.get("method")
    return value if isinstance(value, str) else ""


def request_path(scope: Scope) -> str:
    value = scope.get("path")
    return value if isinstance(value, str) else ""


def request_headers(scope: Scope) -> Mapping[str, str]:
    raw = scope.get("headers")
    if not isinstance(raw, list):
        raise InvalidRequest
    headers: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, tuple) or len(item) != 2:
            raise InvalidRequest
        name, value = item
        if not isinstance(name, bytes) or not isinstance(value, bytes):
            raise InvalidRequest
        try:
            decoded_name = name.decode("ascii").casefold()
            decoded_value = value.decode("ascii")
        except UnicodeDecodeError as error:
            raise InvalidRequest from error
        if decoded_name in headers:
            raise InvalidRequest
        headers[decoded_name] = decoded_value
    return headers


async def request_body(receive: Receive, *, maximum_bytes: int) -> bytes:
    body = bytearray()
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            raise InvalidRequest
        chunk = message.get("body", b"")
        if not isinstance(chunk, bytes):
            raise InvalidRequest
        body.extend(chunk)
        if len(body) > maximum_bytes:
            raise RequestTooLarge
        if not message.get("more_body", False):
            return bytes(body)


async def request_json(
    receive: Receive,
    *,
    maximum_bytes: int,
) -> Mapping[str, object]:
    raw = await request_body(receive, maximum_bytes=maximum_bytes)
    try:
        value: object = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InvalidRequest from error
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InvalidRequest
    return value


async def send_json(send: Send, status: int, document: JsonValue) -> None:
    body = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    start: Message = {
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ],
    }
    await send(start)
    await send({"type": "http.response.body", "body": body})


__all__ = [
    "InvalidRequest",
    "RequestTooLarge",
    "request_headers",
    "request_json",
    "request_method",
    "request_path",
    "send_json",
]
