from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MAX_URL_BYTES = 2_048


def _is_visible(value: str) -> bool:
    return all(character.isprintable() and not character.isspace() for character in value)


def _fully_unquote(value: str) -> str:
    decoded = value
    while True:
        next_value = unquote(decoded)
        if next_value == decoded:
            return decoded
        decoded = next_value


def validated_url(value: str, *, https_only: bool) -> str:
    if (
        not _is_visible(value)
        or len(value.encode("utf-8")) > _MAX_URL_BYTES
        or "?" in value
        or "#" in value
        or _INVALID_PERCENT_ESCAPE.search(value) is not None
    ):
        raise ValueError("URL must be bounded visible text")
    parsed = urlsplit(value)
    allowed_schemes = {"https"} if https_only else {"http", "https"}
    try:
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        raise ValueError("URL must be absolute and credential-free") from None
    decoded_authority = _fully_unquote(parsed.netloc)
    if (
        parsed.scheme not in allowed_schemes
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or "%" in parsed.netloc
        or "@" in decoded_authority
        or "\\" in decoded_authority
        or not _is_visible(decoded_authority)
    ):
        raise ValueError("URL must be absolute and credential-free")
    decoded_path = _fully_unquote(parsed.path)
    if (
        not _is_visible(decoded_path)
        or "\\" in decoded_path
        or any(part in {".", ".."} for part in decoded_path.split("/"))
    ):
        raise ValueError("URL path must not contain traversal")
    return value


__all__ = ["validated_url"]
