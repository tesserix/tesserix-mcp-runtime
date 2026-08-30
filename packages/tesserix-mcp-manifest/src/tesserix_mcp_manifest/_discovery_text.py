from __future__ import annotations

import re

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|token|secret|password|authorization|credential)"
    r"\s*[:=]\s*[^\s,;]+"
)
_BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_JWT_VALUE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_RUNTIME_URI = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,15}://")
_ENVIRONMENT_ASSIGNMENT = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\s*=\s*[^\s,;]+")
_UNSAFE_PATTERNS = (
    _SECRET_ASSIGNMENT,
    _BEARER_VALUE,
    _PRIVATE_KEY,
    _JWT_VALUE,
    _RUNTIME_URI,
    _ENVIRONMENT_ASSIGNMENT,
)


def validated_discovery_text(value: str) -> str:
    if (
        value != value.strip()
        or not value.isprintable()
        or any(character.isspace() and character != " " for character in value)
        or "  " in value
        or "```" in value
        or value.startswith("#!")
        or any(pattern.search(value) is not None for pattern in _UNSAFE_PATTERNS)
    ):
        raise ValueError("discovery text must be one-line secret-safe prose")
    return value


__all__ = ["validated_discovery_text"]
