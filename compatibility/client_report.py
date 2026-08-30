from __future__ import annotations

import re
from dataclasses import dataclass, field

_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_PROTOCOL = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")


@dataclass(slots=True, kw_only=True)
class ClientEvidence:
    client: str
    lane: str
    expected_sdk: str
    supported_features: tuple[str, ...]
    negotiated_out: tuple[str, ...]
    feature_gaps: tuple[str, ...] = ()
    _current_operation: str | None = field(default=None, init=False)
    _operations: list[str] = field(default_factory=list, init=False)
    _protocols: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        names = (
            self.client,
            self.lane,
            *self.supported_features,
            *self.negotiated_out,
            *self.feature_gaps,
        )
        if any(_NAME.fullmatch(name) is None for name in names):
            raise ValueError("client evidence names are invalid")
        if not self.expected_sdk or len(self.expected_sdk) > 32:
            raise ValueError("client evidence SDK is invalid")

    def begin(self, operation: str) -> None:
        if self._current_operation is not None or _NAME.fullmatch(operation) is None:
            raise RuntimeError("client evidence operation is invalid")
        self._current_operation = operation

    def complete(self) -> None:
        if self._current_operation is None:
            raise RuntimeError("client evidence has no active operation")
        if self._current_operation not in self._operations:
            self._operations.append(self._current_operation)
        self._current_operation = None

    def negotiated(self, protocol: str) -> None:
        if _PROTOCOL.fullmatch(protocol) is None:
            raise RuntimeError("client evidence protocol is invalid")
        if protocol not in self._protocols:
            self._protocols.append(protocol)

    def succeeded(self, *, actual_sdk: str) -> dict[str, object]:
        if self._current_operation is not None or actual_sdk != self.expected_sdk:
            raise RuntimeError("client evidence cannot report success")
        return self._document(actual_sdk=actual_sdk, passed=True, failure=None)

    def failed(self, *, actual_sdk: str, error: BaseException) -> dict[str, object]:
        operation = self._current_operation or "client_process"
        failure = {
            "code": "client_operation_failed",
            "error_type": type(error).__name__[:64],
            "operation": operation,
            "protocol": self._protocols[-1] if self._protocols else "not-negotiated",
        }
        return self._document(actual_sdk=actual_sdk, passed=False, failure=failure)

    def _document(
        self,
        *,
        actual_sdk: str,
        passed: bool,
        failure: dict[str, str] | None,
    ) -> dict[str, object]:
        return {
            "client": self.client,
            "failure": failure,
            "feature_gaps": list(self.feature_gaps),
            "lane": self.lane,
            "negotiated_out": list(self.negotiated_out),
            "operations": list(self._operations),
            "passed": passed,
            "protocols": list(self._protocols),
            "schema_version": 1,
            "sdk": actual_sdk,
            "supported_features": list(self.supported_features),
        }


__all__ = ["ClientEvidence"]
