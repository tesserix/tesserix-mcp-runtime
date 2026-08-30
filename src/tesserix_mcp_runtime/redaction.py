"""Bounded, replaceable redaction at runtime trust boundaries."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol, cast, runtime_checkable

from tesserix_mcp_runtime.contracts import JsonValue

REDACTED_TEXT = "[REDACTED]"
_MAX_DEPTH = 64
_MAX_NODES = 65_536
_MAX_TEXT_BYTES = 1_048_576
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>\b(?:authorization|proxy[-_ ]?authorization|token|"
    r"(?:access|refresh|auth|id)[-_ ]?token|api[-_ ]?key|credential|password|"
    r"client[-_ ]?secret|private[-_ ]?key|(?:secret[-_ ]?access|access|signing|"
    r"encryption)[-_ ]?key(?:[-_ ]?id)?)\b[\"']?\s*[:=]\s*)"
    r"(?P<value>(?:Bearer|Basic)\s+[^\s,;}\]]+|\"[^\"\r\n]*\"|"
    r"'[^'\r\n]*'|[^\s,;}\]]+)"
)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----[\s\S]*?"
    r"-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----"
)
_KEY_PARTS = re.compile(r"[^a-z0-9]")
_SENSITIVE_EXACT = frozenset(
    {
        "authorization",
        "proxyauthorization",
        "token",
        "password",
        "passwd",
        "credential",
        "credentials",
        "secret",
        "clientsecret",
        "privatekey",
        "apikey",
        "accesskey",
        "accesskeyid",
        "secretaccesskey",
        "signingkey",
        "encryptionkey",
        "accesstoken",
        "refreshtoken",
        "authtoken",
        "idtoken",
    }
)
_SENSITIVE_SUFFIXES = (
    "token",
    "password",
    "credential",
    "credentials",
    "secret",
    "privatekey",
    "apikey",
    "accesskeyid",
    "secretaccesskey",
    "signingkey",
    "encryptionkey",
    "accesstoken",
    "refreshtoken",
    "authtoken",
    "idtoken",
)


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


class RedactionError(Exception):
    """A payload-free failure raised when safe redaction cannot be completed."""

    def __init__(self, *, limit: bool = False) -> None:
        super().__init__("redaction limit exceeded" if limit else "redaction failed")


@dataclass(frozen=True, slots=True, kw_only=True)
class RedactionLimits:
    max_depth: int = _MAX_DEPTH
    max_nodes: int = _MAX_NODES
    max_text_bytes: int = _MAX_TEXT_BYTES

    def __post_init__(self) -> None:
        for value, maximum in (
            (self.max_depth, _MAX_DEPTH),
            (self.max_nodes, _MAX_NODES),
            (self.max_text_bytes, _MAX_TEXT_BYTES),
        ):
            if (
                _is_runtime_instance(value, bool)
                or not _is_runtime_instance(value, int)
                or not 1 <= value <= maximum
            ):
                raise ValueError(
                    "redaction limit must be a positive integer within its hard maximum"
                )


_DEFAULT_REDACTION_LIMITS = RedactionLimits()


class SecretValue:
    """Hold a credential while making ordinary rendering safe by construction."""

    __slots__ = ("__value",)

    def __init__(self, value: str) -> None:
        if (
            not _is_runtime_instance(value, str)
            or not 4 <= len(value) <= 4096
            or value != value.strip()
            or value == REDACTED_TEXT
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("secret value must be bounded non-empty visible text")
        self.__value = value

    def __str__(self) -> str:
        return REDACTED_TEXT

    def __repr__(self) -> str:
        return f"SecretValue({REDACTED_TEXT!r})"

    def __format__(self, format_spec: str) -> str:
        return format(REDACTED_TEXT, format_spec)

    def reveal(self) -> str:
        """Return the credential only at an explicit outbound boundary."""

        return self.__value


@runtime_checkable
class RedactionPolicy(Protocol):
    @property
    def limits(self) -> RedactionLimits: ...

    def redact_text(self, value: str) -> str: ...

    def redact(self, value: JsonValue) -> JsonValue: ...


@dataclass(slots=True)
class _InputBudget:
    nodes: int = 0
    text_bytes: int = 0


def is_secret_key(value: str) -> bool:
    normalized = _KEY_PARTS.sub("", value.casefold())
    return normalized in _SENSITIVE_EXACT or normalized.endswith(_SENSITIVE_SUFFIXES)


class SecretRedactor:
    """Redact exact configured values and supported credential shapes."""

    __slots__ = ("_known_secrets", "_limits")

    def __init__(
        self,
        *,
        known_secrets: Iterable[SecretValue] = (),
        limits: RedactionLimits = _DEFAULT_REDACTION_LIMITS,
    ) -> None:
        if not _is_runtime_instance(limits, RedactionLimits):
            raise ValueError("limits must satisfy the redaction limits contract")
        values: list[str] = []
        for secret in known_secrets:
            if not _is_runtime_instance(secret, SecretValue):
                raise ValueError("known secrets must use SecretValue")
            value = secret.reveal()
            if value not in values:
                values.append(value)
        self._known_secrets = tuple(sorted(values, key=len, reverse=True))
        self._limits = limits

    @property
    def limits(self) -> RedactionLimits:
        return self._limits

    def redact_text(self, value: str) -> str:
        if not _is_runtime_instance(value, str):
            raise RedactionError()
        self._check_text(value)
        redacted = self._redact_text(value)
        self._check_text(redacted)
        return redacted

    def redact(self, value: JsonValue) -> JsonValue:
        self._validate(value, depth=0, budget=_InputBudget())
        output = self._transform(value)
        self._validate(output, depth=0, budget=_InputBudget())
        return output

    def _check_text(self, value: str) -> None:
        if len(value.encode("utf-8")) > self._limits.max_text_bytes:
            raise RedactionError(limit=True)

    def _redact_text(self, value: str) -> str:
        for secret in self._known_secrets:
            value = value.replace(secret, REDACTED_TEXT)
        value = _PRIVATE_KEY.sub(REDACTED_TEXT, value)
        value = _JWT.sub(REDACTED_TEXT, value)

        def replace_assignment(match: re.Match[str]) -> str:
            assigned = match.group("value")
            if assigned[:1] in {'"', "'"} and assigned[-1:] == assigned[:1]:
                replacement = f"{assigned[0]}{REDACTED_TEXT}{assigned[0]}"
            else:
                replacement = REDACTED_TEXT
            return f"{match.group('prefix')}{replacement}"

        return _SECRET_ASSIGNMENT.sub(replace_assignment, value)

    def _validate(self, value: object, *, depth: int, budget: _InputBudget) -> None:
        if depth > self._limits.max_depth:
            raise RedactionError(limit=True)
        budget.nodes += 1
        if budget.nodes > self._limits.max_nodes:
            raise RedactionError(limit=True)
        if value is None or isinstance(value, bool | int):
            return
        if isinstance(value, float):
            if not math.isfinite(value):
                raise RedactionError()
            return
        if isinstance(value, str):
            self._consume_text(value, budget)
            return
        if isinstance(value, list):
            for item in cast(list[object], value):
                self._validate(item, depth=depth + 1, budget=budget)
            return
        if isinstance(value, dict):
            for key, item in cast(dict[object, object], value).items():
                if not isinstance(key, str):
                    raise RedactionError()
                self._consume_text(key, budget)
                self._validate(item, depth=depth + 1, budget=budget)
            return
        raise RedactionError()

    def _consume_text(self, value: str, budget: _InputBudget) -> None:
        budget.text_bytes += len(value.encode("utf-8"))
        if budget.text_bytes > self._limits.max_text_bytes:
            raise RedactionError(limit=True)

    def _transform(self, value: JsonValue) -> JsonValue:
        if isinstance(value, str):
            return self._redact_text(value)
        if isinstance(value, list):
            return [self._transform(item) for item in value]
        if isinstance(value, dict):
            output: dict[str, JsonValue] = {}
            for key, item in value.items():
                redacted_key = self._redact_text(key)
                candidate = redacted_key
                suffix = 2
                while candidate in output:
                    candidate = f"{redacted_key}#{suffix}"
                    suffix += 1
                output[candidate] = REDACTED_TEXT if is_secret_key(key) else self._transform(item)
            return output
        return value


DEFAULT_REDACTION_POLICY: RedactionPolicy = SecretRedactor()


__all__ = [
    "DEFAULT_REDACTION_POLICY",
    "REDACTED_TEXT",
    "RedactionError",
    "RedactionLimits",
    "RedactionPolicy",
    "SecretRedactor",
    "SecretValue",
]
