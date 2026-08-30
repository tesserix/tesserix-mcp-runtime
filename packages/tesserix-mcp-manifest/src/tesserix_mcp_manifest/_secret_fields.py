from __future__ import annotations

import re

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_KEY_SEPARATOR = re.compile(r"[^A-Za-z0-9]+")
_SECRET_WORDS = frozenset(
    {
        "authorization",
        "credential",
        "credentials",
        "passwd",
        "password",
        "secret",
        "secrets",
        "token",
        "tokens",
    }
)
_SECRET_COMPOUNDS = frozenset({"accesskey", "apikey", "privatekey"})


def is_secret_key(key: str) -> bool:
    expanded = _CAMEL_BOUNDARY.sub("_", key)
    parts = tuple(part.lower() for part in _KEY_SEPARATOR.split(expanded) if part)
    return bool(_SECRET_WORDS.intersection(parts)) or "".join(parts) in _SECRET_COMPOUNDS


__all__ = ["is_secret_key"]
