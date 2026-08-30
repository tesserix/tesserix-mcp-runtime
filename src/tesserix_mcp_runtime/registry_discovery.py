"""Bounded, identity-scoped discovery of exact Agentic Registry artifacts."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import math
import re
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, TypeGuard, runtime_checkable
from urllib.parse import urlsplit, urlunsplit

from tesserix_mcp_runtime.clock import SystemClock
from tesserix_mcp_runtime.contracts import CallContext, Clock, ErrorCode, JsonValue
from tesserix_mcp_runtime.errors import RuntimeFailure
from tesserix_mcp_runtime.schema_compatibility import (
    SchemaChange,
    SchemaDirection,
    classify_schema_change,
)
from tesserix_mcp_runtime.tool_manifest import schema_fingerprint

_MAX_SEARCH_RESULTS = 20
_REGISTRY_KINDS = frozenset(
    {
        "Agent",
        "Blueprint",
        "Dataset",
        "EvalSuite",
        "GatewayResource",
        "MCPServer",
        "Prompt",
        "Skill",
        "Tool",
        "Workflow",
    }
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
_ADK_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_CAPABILITY = re.compile(r"cap/[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_CACHE_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_QUERY_CONTRACT_VERSION = "registry-v0-search-stub-v1"


def _is_runtime_instance(value: object, expected: type[Any]) -> bool:
    return isinstance(value, expected)


def _is_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    return _is_runtime_instance(value, Mapping)


def _is_sequence(value: object) -> TypeGuard[list[object] | tuple[object, ...]]:
    return _is_runtime_instance(value, list) or _is_runtime_instance(value, tuple)


def _is_tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    return _is_runtime_instance(value, tuple)


def _is_int(value: object) -> TypeGuard[int]:
    return not _is_runtime_instance(value, bool) and _is_runtime_instance(value, int)


def _is_number(value: object) -> TypeGuard[int | float]:
    return not _is_runtime_instance(value, bool) and (
        _is_runtime_instance(value, int) or _is_runtime_instance(value, float)
    )


def _is_str(value: object) -> TypeGuard[str]:
    return _is_runtime_instance(value, str)


def _is_text_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    return _is_mapping(value) and all(_is_str(key) for key in value)


def _empty_text_mapping() -> Mapping[str, str]:
    return {}


def _empty_object_mapping() -> Mapping[str, object]:
    return {}


def _require_text(name: str, value: object, *, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} must be bounded visible text")


def canonical_https_origin(name: str, value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{name} must be an HTTPS origin without credentials or path")
    return urlunsplit(("https", parsed.netloc, "", "", ""))


def _freeze_json(
    value: object,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
    max_depth: int = 8,
    max_nodes: int = 512,
    max_mapping_entries: int = 50,
    max_sequence_items: int = 100,
    max_text: int = 512,
) -> object:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > max_depth or budget[0] > max_nodes:
        raise ValueError("attributes must be bounded JSON")
    if value is None or isinstance(value, str | bool | int):
        if isinstance(value, str) and len(value) > max_text:
            raise ValueError("attributes must be bounded JSON")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("attributes must be bounded JSON")
        return value
    if _is_mapping(value):
        if len(value) > max_mapping_entries:
            raise ValueError("attributes must be bounded JSON")
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not _is_str(key):
                raise ValueError("attributes must be bounded JSON")
            _require_text("attribute key", key, maximum=128)
            frozen[key] = _freeze_json(
                item,
                depth=depth + 1,
                budget=budget,
                max_depth=max_depth,
                max_nodes=max_nodes,
                max_mapping_entries=max_mapping_entries,
                max_sequence_items=max_sequence_items,
                max_text=max_text,
            )
        return MappingProxyType(frozen)
    if _is_sequence(value):
        if len(value) > max_sequence_items:
            raise ValueError("attributes must be bounded JSON")
        return tuple(
            _freeze_json(
                item,
                depth=depth + 1,
                budget=budget,
                max_depth=max_depth,
                max_nodes=max_nodes,
                max_mapping_entries=max_mapping_entries,
                max_sequence_items=max_sequence_items,
                max_text=max_text,
            )
            for item in value
        )
    raise ValueError("attributes must be bounded JSON")


def _freeze_text_mapping(
    name: str,
    values: Mapping[str, str],
    *,
    maximum_entries: int = 50,
) -> Mapping[str, str]:
    if not _is_runtime_instance(values, Mapping) or len(values) > maximum_entries:
        raise ValueError(f"{name} must be a bounded string mapping")
    copied: dict[str, str] = {}
    for key, value in values.items():
        _require_text(f"{name} key", key, maximum=256)
        _require_text(f"{name} value", value, maximum=512)
        copied[key] = value
    return MappingProxyType(copied)


def _go_json_string(value: str) -> str:
    encoded = json.dumps(value, ensure_ascii=False)
    return (
        encoded.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _go_json_float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("artifact content must be finite JSON")
    if value == 0 and math.copysign(1, value) < 0:
        return "-0"
    rendered = repr(value).lower()
    if "e" not in rendered:
        return rendered.removesuffix(".0")
    mantissa, raw_exponent = rendered.split("e", 1)
    exponent = int(raw_exponent)
    if -6 <= exponent < 21:
        fixed = format(Decimal(rendered), "f")
        return fixed.rstrip("0").rstrip(".") if "." in fixed else fixed
    mantissa = mantissa.removesuffix(".0")
    sign = "+" if exponent >= 0 else "-"
    return f"{mantissa}e{sign}{abs(exponent)}"


def _go_json(value: object) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _go_json_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _go_json_float(value)
    if _is_mapping(value):
        items: list[str] = []
        keys: list[str] = []
        for key in value:
            if not _is_str(key):
                raise ValueError("artifact content must be a JSON object")
            keys.append(key)
        for key in sorted(keys):
            items.append(f"{_go_json_string(key)}:{_go_json(value[key])}")
        return "{" + ",".join(items) + "}"
    if _is_sequence(value):
        return "[" + ",".join(_go_json(item) for item in value) + "]"
    raise ValueError("artifact content must be finite JSON")


def _thaw_json(value: object) -> JsonValue:
    if value is None or isinstance(value, str | bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON number must be finite")
        return value
    if _is_mapping(value):
        output: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not _is_str(key):
                raise ValueError("JSON object keys must be strings")
            output[key] = _thaw_json(item)
        return output
    if _is_sequence(value):
        return [_thaw_json(item) for item in value]
    raise ValueError("value must be JSON")


def _mapping(value: object) -> Mapping[str, object] | None:
    return value if _is_text_mapping(value) else None


def _text_tuple(value: object, *, maximum: int = 128) -> tuple[str, ...] | None:
    if not _is_sequence(value) or len(value) > maximum:
        return None
    output: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or item != item.strip():
            return None
        output.append(item)
    if len(output) != len(set(output)):
        return None
    return tuple(output)


def _schema(value: object) -> dict[str, JsonValue] | None:
    mapping = _mapping(value)
    if mapping is None:
        return None
    thawed = _thaw_json(mapping)
    return thawed if isinstance(thawed, dict) else None


def _cache_hash(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def registry_artifact_digest(
    *,
    kind: str,
    name: str,
    namespace: str,
    tag: str,
    labels: Mapping[str, str],
    spec: Mapping[str, object],
) -> str:
    """Reproduce Agentic Registry's canonical `Object.ContentHash`."""

    canonical = (
        "{"
        + ",".join(
            (
                f'"kind":{_go_json(kind)}',
                f'"name":{_go_json(name)}',
                f'"namespace":{_go_json(namespace)}',
                f'"tag":{_go_json(tag)}',
                f'"labels":{_go_json(labels)}',
                f'"spec":{_go_json(spec)}',
            )
        )
        + "}"
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistrySearchQuery:
    """One finite semantic search against the Registry safe-stub view."""

    intent: str
    kinds: tuple[str, ...] = ("MCPServer",)
    namespace: str | None = None
    limit: int = 10

    def __post_init__(self) -> None:
        _require_text("intent", self.intent, maximum=512)
        if (
            not _is_runtime_instance(self.kinds, tuple)
            or not self.kinds
            or len(self.kinds) > len(_REGISTRY_KINDS)
            or len(set(self.kinds)) != len(self.kinds)
            or any(kind not in _REGISTRY_KINDS for kind in self.kinds)
        ):
            raise ValueError("kinds must be unique supported Registry kinds")
        if self.namespace is not None:
            _require_text("namespace", self.namespace, maximum=256)
        if not _is_int(self.limit) or not 1 <= self.limit <= 20:
            raise ValueError(f"limit must be between 1 and {_MAX_SEARCH_RESULTS}")


def _require_unique_text_tuple(
    name: str,
    values: object,
    *,
    maximum_items: int,
    maximum_text: int = 256,
) -> None:
    if not _is_tuple(values) or len(values) > maximum_items or len(values) != len(set(values)):
        raise ValueError(f"{name} must be a bounded unique tuple")
    for value in values:
        _require_text(name, value, maximum=maximum_text)


def _require_adk_surface_bounds(*, max_tools: object, max_schema_bytes: object) -> None:
    if not _is_int(max_tools) or not 1 <= max_tools <= 128:
        raise ValueError("max_tools must match the ADK bound")
    if not _is_int(max_schema_bytes) or not 1 <= max_schema_bytes <= 4 * 1024 * 1024:
        raise ValueError("max_schema_bytes must match the ADK bound")


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryToolRequirement:
    """A reviewed schema contract one Registry-advertised tool must satisfy."""

    name: str
    expected_input_fingerprint: str | None = None
    expected_output_fingerprint: str | None = None
    compatible_input_schema: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        _require_text("tool requirement name", self.name, maximum=128)
        for fingerprint in (
            self.expected_input_fingerprint,
            self.expected_output_fingerprint,
        ):
            if fingerprint is not None and _FINGERPRINT.fullmatch(fingerprint) is None:
                raise ValueError("expected fingerprints must be lowercase SHA-256 digests")
        if (
            self.expected_input_fingerprint is None
            and self.expected_output_fingerprint is None
            and self.compatible_input_schema is None
        ):
            raise ValueError("tool requirement must pin a fingerprint or schema")
        if self.compatible_input_schema is not None:
            frozen = _freeze_json(
                self.compatible_input_schema,
                max_depth=32,
                max_nodes=4096,
                max_mapping_entries=256,
                max_sequence_items=512,
                max_text=4096,
            )
            if not _is_text_mapping(frozen):
                raise ValueError("compatible_input_schema must be a JSON object")
            object.__setattr__(self, "compatible_input_schema", frozen)


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryResolutionPolicy:
    """Explicit compatibility and ADK surface policy for one resolution."""

    server_name: str
    gateway_origin: str
    supported_protocol_versions: tuple[str, ...]
    required_capabilities: tuple[str, ...] = ()
    allowed_lifecycles: tuple[str, ...] = ("active",)
    tool_allow: tuple[str, ...] = ()
    tool_deny: tuple[str, ...] = ()
    tool_prefix: str = ""
    tool_requirements: tuple[RegistryToolRequirement, ...] = ()
    max_tools: int = 40
    max_schema_bytes: int = 256 * 1024

    def __post_init__(self) -> None:
        if _ADK_NAME.fullmatch(self.server_name) is None:
            raise ValueError("server_name must use the portable ADK name grammar")
        object.__setattr__(
            self,
            "gateway_origin",
            canonical_https_origin("gateway_origin", self.gateway_origin),
        )
        _require_unique_text_tuple(
            "supported_protocol_versions",
            self.supported_protocol_versions,
            maximum_items=16,
            maximum_text=64,
        )
        if not self.supported_protocol_versions:
            raise ValueError("supported_protocol_versions must not be empty")
        _require_unique_text_tuple(
            "required_capabilities",
            self.required_capabilities,
            maximum_items=32,
            maximum_text=132,
        )
        if any(_CAPABILITY.fullmatch(value) is None for value in self.required_capabilities):
            raise ValueError("required_capabilities must use the controlled capability grammar")
        _require_unique_text_tuple(
            "allowed_lifecycles",
            self.allowed_lifecycles,
            maximum_items=8,
            maximum_text=64,
        )
        if not self.allowed_lifecycles:
            raise ValueError("allowed_lifecycles must not be empty")
        for name, values in (("tool_allow", self.tool_allow), ("tool_deny", self.tool_deny)):
            _require_unique_text_tuple(name, values, maximum_items=128, maximum_text=128)
        overlap = sorted(set(self.tool_allow) & set(self.tool_deny))
        if overlap:
            raise ValueError(f"{', '.join(overlap)} is both allowed and denied")
        if "*" in self.tool_deny:
            raise ValueError("tool_deny cannot contain '*'")
        if self.tool_prefix and _ADK_NAME.fullmatch(self.tool_prefix) is None:
            raise ValueError("tool_prefix must use the portable ADK name grammar")
        if not _is_runtime_instance(self.tool_requirements, tuple) or any(
            not _is_runtime_instance(requirement, RegistryToolRequirement)
            for requirement in self.tool_requirements
        ):
            raise ValueError("tool_requirements must be an immutable typed tuple")
        requirement_names = tuple(requirement.name for requirement in self.tool_requirements)
        if len(requirement_names) != len(set(requirement_names)):
            raise ValueError("tool_requirements must not contain duplicate names")
        _require_adk_surface_bounds(
            max_tools=self.max_tools,
            max_schema_bytes=self.max_schema_bytes,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistrySearchStub:
    """One authorized, secret-safe Registry search projection."""

    kind: str
    name: str
    namespace: str
    tag: str
    arn: str
    digest: str
    ref: str
    fetch_path: str
    title: str = ""
    description: str = ""
    visibility: str = ""
    labels: Mapping[str, str] = field(default_factory=_empty_text_mapping)
    annotations: Mapping[str, str] = field(default_factory=_empty_text_mapping)
    attributes: Mapping[str, object] = field(default_factory=_empty_object_mapping)

    def __post_init__(self) -> None:
        if self.kind not in _REGISTRY_KINDS:
            raise ValueError("kind must be a supported Registry kind")
        for name, value, maximum in (
            ("name", self.name, 512),
            ("namespace", self.namespace, 256),
            ("tag", self.tag, 256),
            ("arn", self.arn, 2048),
            ("ref", self.ref, 2048),
        ):
            _require_text(name, value, maximum=maximum)
        if _DIGEST.fullmatch(self.digest) is None:
            raise ValueError("digest must be a Registry SHA-256 digest")
        for name, value, maximum in (
            ("title", self.title, 512),
            ("description", self.description, 512),
            ("visibility", self.visibility, 64),
        ):
            if value:
                _require_text(name, value, maximum=maximum)
        parsed_path = urlsplit(self.fetch_path)
        if (
            not self.fetch_path
            or len(self.fetch_path) > 2048
            or parsed_path.scheme
            or parsed_path.netloc
            or parsed_path.fragment
            or not parsed_path.path.startswith("/v0/")
            or parsed_path.path.startswith("//")
            or "\\" in self.fetch_path
        ):
            raise ValueError("fetch_path must be a bounded same-origin Registry v0 path")
        frozen_attributes = _freeze_json(self.attributes)
        if not _is_text_mapping(frozen_attributes):
            raise ValueError("attributes must be a bounded JSON object")
        object.__setattr__(self, "labels", _freeze_text_mapping("labels", self.labels))
        object.__setattr__(
            self,
            "annotations",
            _freeze_text_mapping("annotations", self.annotations),
        )
        object.__setattr__(self, "attributes", frozen_attributes)


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryArtifact:
    """One exact Registry artifact retained under an identity-scoped digest key."""

    api_version: str
    kind: str
    name: str
    namespace: str
    tag: str
    arn: str
    digest: str
    ref: str
    labels: Mapping[str, str]
    spec: Mapping[str, object]

    def __post_init__(self) -> None:
        if self.api_version != "registry.agentic.dev/v1alpha1":
            raise ValueError("api_version must be the supported Registry contract")
        if self.kind not in _REGISTRY_KINDS:
            raise ValueError("kind must be a supported Registry kind")
        for name, value, maximum in (
            ("name", self.name, 512),
            ("namespace", self.namespace, 256),
            ("tag", self.tag, 256),
            ("arn", self.arn, 2048),
            ("ref", self.ref, 2048),
        ):
            _require_text(name, value, maximum=maximum)
        if _DIGEST.fullmatch(self.digest) is None:
            raise ValueError("digest must be a Registry SHA-256 digest")
        frozen_spec = _freeze_json(
            self.spec,
            max_depth=32,
            max_nodes=32_768,
            max_mapping_entries=1024,
            max_sequence_items=1024,
            max_text=16_384,
        )
        if not _is_text_mapping(frozen_spec):
            raise ValueError("spec must be a bounded JSON object")
        if len(_go_json(frozen_spec).encode("utf-8")) > 524_288:
            raise ValueError("spec must be at most 512 KiB")
        object.__setattr__(
            self,
            "labels",
            _freeze_text_mapping("labels", self.labels, maximum_entries=256),
        )
        object.__setattr__(self, "spec", frozen_spec)

    @property
    def computed_digest(self) -> str:
        return registry_artifact_digest(
            kind=self.kind,
            name=self.name,
            namespace=self.namespace,
            tag=self.tag,
            labels=self.labels,
            spec=self.spec,
        )


@runtime_checkable
class RegistryDiscovery(Protocol):
    """Transport-neutral authorized Registry search and exact fetch."""

    @property
    def origin(self) -> str: ...

    async def search(
        self,
        query: RegistrySearchQuery,
        *,
        context: CallContext,
    ) -> tuple[RegistrySearchStub, ...]: ...

    async def fetch(
        self,
        stub: RegistrySearchStub,
        *,
        context: CallContext,
    ) -> RegistryArtifact: ...


class RegistryCandidateDecision(StrEnum):
    SELECTED = "selected"
    REJECTED = "rejected"


class RegistryCandidateReason(StrEnum):
    KIND = "kind"
    NAMESPACE = "namespace"
    CAPABILITY = "capability"
    LIFECYCLE = "lifecycle"
    PROTOCOL = "protocol"
    SCOPE = "scope"
    TOOL_POLICY = "tool_policy"
    SCHEMA = "schema"
    FINGERPRINT = "fingerprint"
    GATEWAY = "gateway"
    CONTRACT = "contract"


class RegistryResolutionSource(StrEnum):
    NETWORK = "network"
    CACHE = "cache"
    OFFLINE = "offline"


class RegistryDiscoveryError(RuntimeFailure):
    """Base for payload-free Registry resolution failures."""

    def __init__(
        self,
        code: ErrorCode,
        *,
        request_id: str,
        ref: str | None = None,
    ) -> None:
        _require_text("request_id", request_id, maximum=256)
        if ref is not None:
            _require_text("ref", ref, maximum=2048)
        self.request_id = request_id
        self.ref = ref
        super().__init__(code)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(code={self.code.value!r}, "
            f"request_id={self.request_id!r}, ref={self.ref!r})"
        )


class RegistryArtifactRaceError(RegistryDiscoveryError):
    """Search and exact fetch no longer identify the same artifact content."""

    def __init__(self, *, request_id: str, ref: str) -> None:
        super().__init__(ErrorCode.CONFLICT, request_id=request_id, ref=ref)


class RegistryDigestMismatchError(RegistryDiscoveryError):
    """Exact Registry bytes do not reproduce the advertised content digest."""

    def __init__(self, *, request_id: str, ref: str) -> None:
        super().__init__(ErrorCode.CONFLICT, request_id=request_id, ref=ref)


class RegistryUnavailableError(RegistryDiscoveryError):
    """Registry could not safely answer the requested discovery operation."""

    def __init__(self, *, request_id: str) -> None:
        super().__init__(ErrorCode.UNAVAILABLE, request_id=request_id)


class RegistryAuthenticationError(RegistryDiscoveryError):
    def __init__(self, *, request_id: str) -> None:
        super().__init__(ErrorCode.UNAUTHENTICATED, request_id=request_id)


class RegistryAuthorizationError(RegistryDiscoveryError):
    def __init__(self, *, request_id: str) -> None:
        super().__init__(ErrorCode.FORBIDDEN, request_id=request_id)


class RegistryContractError(RegistryDiscoveryError):
    def __init__(
        self,
        *,
        request_id: str,
        code: ErrorCode = ErrorCode.UNAVAILABLE,
    ) -> None:
        if code not in {ErrorCode.INVALID_INPUT, ErrorCode.RESULT_TOO_LARGE, ErrorCode.UNAVAILABLE}:
            raise ValueError("Registry contract failure code must remain payload-free")
        super().__init__(code, request_id=request_id)


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistrySearchCacheKey:
    """Secret-free identity and query partition for cached authorized stubs."""

    origin: str
    identity_scope_hash: str
    contract_version: str
    query_digest: str

    def __post_init__(self) -> None:
        if self.origin != canonical_https_origin("origin", self.origin):
            raise ValueError("origin must be canonical")
        if (
            _CACHE_DIGEST.fullmatch(self.identity_scope_hash) is None
            or _CACHE_DIGEST.fullmatch(self.query_digest) is None
        ):
            raise ValueError("cache hashes must be lowercase SHA-256 digests")
        if self.contract_version != _QUERY_CONTRACT_VERSION:
            raise ValueError("contract_version must identify the shipped query contract")


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryArtifactCacheKey:
    """Identity-scoped key for one immutable exact Registry artifact."""

    origin: str
    identity_scope_hash: str
    contract_version: str
    artifact_digest: str

    def __post_init__(self) -> None:
        if self.origin != canonical_https_origin("origin", self.origin):
            raise ValueError("origin must be canonical")
        if _CACHE_DIGEST.fullmatch(self.identity_scope_hash) is None:
            raise ValueError("identity_scope_hash must be a lowercase SHA-256 digest")
        if self.contract_version != _QUERY_CONTRACT_VERSION:
            raise ValueError("contract_version must identify the shipped query contract")
        if _DIGEST.fullmatch(self.artifact_digest) is None:
            raise ValueError("artifact_digest must be a Registry SHA-256 digest")


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryCachePolicy:
    """Fresh authorization leases and explicit bounded offline retention."""

    search_ttl_seconds: float = 30.0
    artifact_ttl_seconds: float = 60.0
    offline_max_stale_seconds: float = 0.0

    def __post_init__(self) -> None:
        for name, value, lower, upper in (
            ("search_ttl_seconds", self.search_ttl_seconds, 0.001, 30.0),
            ("artifact_ttl_seconds", self.artifact_ttl_seconds, 0.001, 60.0),
            ("offline_max_stale_seconds", self.offline_max_stale_seconds, 0.0, 3600.0),
        ):
            if not _is_number(value) or not math.isfinite(value) or not lower <= value <= upper:
                raise ValueError(f"{name} must be within its safe bound")


_DEFAULT_CACHE_POLICY = RegistryCachePolicy()


class RegistryCacheUnavailableError(RuntimeFailure):
    """A replaceable cache adapter could not safely answer an operation."""

    def __init__(self) -> None:
        super().__init__(ErrorCode.UNAVAILABLE)


@runtime_checkable
class RegistryDiscoveryCache(Protocol):
    async def get_search(
        self,
        key: RegistrySearchCacheKey,
        *,
        now: float,
    ) -> tuple[RegistrySearchStub, ...] | None: ...

    async def put_search(
        self,
        key: RegistrySearchCacheKey,
        stubs: tuple[RegistrySearchStub, ...],
        *,
        expires_at: float,
    ) -> None: ...

    async def get_artifact(
        self,
        key: RegistryArtifactCacheKey,
        *,
        now: float,
        allow_stale: bool,
    ) -> RegistryArtifact | None: ...

    async def put_artifact(
        self,
        key: RegistryArtifactCacheKey,
        artifact: RegistryArtifact,
        *,
        fresh_until: float,
        stale_until: float,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class _SearchCacheEntry:
    stubs: tuple[RegistrySearchStub, ...]
    expires_at: float


@dataclass(frozen=True, slots=True)
class _ArtifactCacheEntry:
    artifact: RegistryArtifact
    fresh_until: float
    stale_until: float


class InMemoryRegistryCache:
    """Finite process-local cache; never a catalog or authorization source."""

    def __init__(
        self,
        *,
        max_search_entries: int = 128,
        max_artifact_entries: int = 64,
    ) -> None:
        for name, value, maximum in (
            ("max_search_entries", max_search_entries, 1024),
            ("max_artifact_entries", max_artifact_entries, 256),
        ):
            if not _is_int(value) or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be within its hard bound")
        self._max_search_entries = max_search_entries
        self._max_artifact_entries = max_artifact_entries
        self._search: OrderedDict[RegistrySearchCacheKey, _SearchCacheEntry] = OrderedDict()
        self._artifacts: OrderedDict[RegistryArtifactCacheKey, _ArtifactCacheEntry] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get_search(
        self,
        key: RegistrySearchCacheKey,
        *,
        now: float,
    ) -> tuple[RegistrySearchStub, ...] | None:
        self._validate_time(now)
        async with self._lock:
            entry = self._search.get(key)
            if entry is None:
                return None
            if now >= entry.expires_at:
                del self._search[key]
                return None
            self._search.move_to_end(key)
            return entry.stubs

    async def put_search(
        self,
        key: RegistrySearchCacheKey,
        stubs: tuple[RegistrySearchStub, ...],
        *,
        expires_at: float,
    ) -> None:
        self._validate_time(expires_at)
        if (
            not _is_runtime_instance(stubs, tuple)
            or len(stubs) > _MAX_SEARCH_RESULTS
            or any(not _is_runtime_instance(stub, RegistrySearchStub) for stub in stubs)
        ):
            raise ValueError("stubs must satisfy the bounded safe projection")
        async with self._lock:
            self._search[key] = _SearchCacheEntry(stubs=stubs, expires_at=expires_at)
            self._search.move_to_end(key)
            while len(self._search) > self._max_search_entries:
                self._search.popitem(last=False)

    async def get_artifact(
        self,
        key: RegistryArtifactCacheKey,
        *,
        now: float,
        allow_stale: bool,
    ) -> RegistryArtifact | None:
        self._validate_time(now)
        if not _is_runtime_instance(allow_stale, bool):
            raise ValueError("allow_stale must be explicit")
        async with self._lock:
            entry = self._artifacts.get(key)
            if entry is None:
                return None
            if now >= entry.stale_until:
                del self._artifacts[key]
                return None
            if now >= entry.fresh_until and not allow_stale:
                return None
            self._artifacts.move_to_end(key)
            return entry.artifact

    async def put_artifact(
        self,
        key: RegistryArtifactCacheKey,
        artifact: RegistryArtifact,
        *,
        fresh_until: float,
        stale_until: float,
    ) -> None:
        self._validate_time(fresh_until)
        self._validate_time(stale_until)
        if not _is_runtime_instance(artifact, RegistryArtifact) or stale_until < fresh_until:
            raise ValueError("artifact cache entry must be typed with ordered expiry")
        async with self._lock:
            self._artifacts[key] = _ArtifactCacheEntry(
                artifact=artifact,
                fresh_until=fresh_until,
                stale_until=stale_until,
            )
            self._artifacts.move_to_end(key)
            while len(self._artifacts) > self._max_artifact_entries:
                self._artifacts.popitem(last=False)

    @staticmethod
    def _validate_time(value: float) -> None:
        if not _is_number(value) or not math.isfinite(value) or value < 0:
            raise ValueError("cache time must be a finite monotonic value")


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryCandidateExplanation:
    """Bounded reason data for one already-authorized search stub."""

    ref: str
    decision: RegistryCandidateDecision
    reasons: tuple[RegistryCandidateReason, ...] = ()

    def __post_init__(self) -> None:
        _require_text("ref", self.ref, maximum=2048)
        if not _is_runtime_instance(self.decision, RegistryCandidateDecision):
            raise ValueError("decision must be typed")
        if (
            not _is_runtime_instance(self.reasons, tuple)
            or len(self.reasons) > len(RegistryCandidateReason)
            or len(self.reasons) != len(set(self.reasons))
            or any(
                not _is_runtime_instance(reason, RegistryCandidateReason) for reason in self.reasons
            )
        ):
            raise ValueError("reasons must be a bounded typed tuple")
        if self.decision is RegistryCandidateDecision.SELECTED and self.reasons:
            raise ValueError("a selected candidate cannot carry rejection reasons")
        if self.decision is RegistryCandidateDecision.REJECTED and not self.reasons:
            raise ValueError("a rejected candidate must carry a reason")


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryToolPin:
    """Registry-reviewed schema fingerprints retained beside an ADK declaration."""

    name: str
    input_fingerprint: str
    output_fingerprint: str

    def __post_init__(self) -> None:
        _require_text("tool pin name", self.name, maximum=128)
        if (
            _FINGERPRINT.fullmatch(self.input_fingerprint) is None
            or _FINGERPRINT.fullmatch(self.output_fingerprint) is None
        ):
            raise ValueError("tool pins must contain lowercase SHA-256 fingerprints")


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryADKServer:
    """Exact Registry result consumable by ADK's existing MCP surface machinery."""

    name: str
    endpoint: str
    allow: tuple[str, ...]
    deny: tuple[str, ...]
    prefix: str
    max_tools: int
    max_schema_bytes: int
    artifact_ref: str
    artifact_digest: str
    tool_pins: tuple[RegistryToolPin, ...]

    def __post_init__(self) -> None:
        if _ADK_NAME.fullmatch(self.name) is None:
            raise ValueError("name must use the portable ADK grammar")
        endpoint = urlsplit(self.endpoint)
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError("endpoint must be a trusted HTTPS gateway URL")
        for name, values in (("allow", self.allow), ("deny", self.deny)):
            _require_unique_text_tuple(name, values, maximum_items=128, maximum_text=128)
        if set(self.allow) & set(self.deny):
            raise ValueError("ADK projection cannot both allow and deny a tool")
        if self.prefix and _ADK_NAME.fullmatch(self.prefix) is None:
            raise ValueError("prefix must use the portable ADK grammar")
        _require_adk_surface_bounds(
            max_tools=self.max_tools,
            max_schema_bytes=self.max_schema_bytes,
        )
        _require_text("artifact_ref", self.artifact_ref, maximum=2048)
        if _DIGEST.fullmatch(self.artifact_digest) is None:
            raise ValueError("artifact_digest must be a Registry digest")
        if not _is_runtime_instance(self.tool_pins, tuple) or any(
            not _is_runtime_instance(pin, RegistryToolPin) for pin in self.tool_pins
        ):
            raise ValueError("tool_pins must be an immutable typed tuple")
        pin_names = tuple(pin.name for pin in self.tool_pins)
        if "*" in self.allow or pin_names != self.allow or len(self.allow) > self.max_tools:
            raise ValueError("allow and tool_pins must describe the exact reviewed tool surface")


@dataclass(frozen=True, slots=True, kw_only=True)
class RegistryResolution:
    """One match or an explicit bounded no-match decision."""

    source: RegistryResolutionSource
    server: RegistryADKServer | None
    explanations: tuple[RegistryCandidateExplanation, ...]

    def __post_init__(self) -> None:
        if not _is_runtime_instance(self.source, RegistryResolutionSource):
            raise ValueError("source must be typed")
        if self.server is not None and not _is_runtime_instance(self.server, RegistryADKServer):
            raise ValueError("server must be an ADK projection")
        if not _is_runtime_instance(self.explanations, tuple) or len(self.explanations) > 20:
            raise ValueError("explanations must be a bounded immutable tuple")


@dataclass(frozen=True, slots=True)
class _ResolvedTool:
    name: str
    input_fingerprint: str
    output_fingerprint: str
    schema_bytes: int


class RegistryResolver:
    """Resolve one Registry-ranked stub into an exact policy-safe ADK declaration."""

    def __init__(
        self,
        *,
        discovery: RegistryDiscovery,
        cache: RegistryDiscoveryCache | None = None,
        cache_policy: RegistryCachePolicy = _DEFAULT_CACHE_POLICY,
        clock: Clock | None = None,
    ) -> None:
        if not _is_runtime_instance(discovery, RegistryDiscovery):
            raise TypeError("discovery must implement RegistryDiscovery")
        if cache is not None and not _is_runtime_instance(cache, RegistryDiscoveryCache):
            raise TypeError("cache must implement RegistryDiscoveryCache")
        if not _is_runtime_instance(cache_policy, RegistryCachePolicy):
            raise TypeError("cache_policy must be a RegistryCachePolicy")
        resolved_clock = clock or SystemClock()
        if not _is_runtime_instance(resolved_clock, Clock):
            raise TypeError("clock must implement Clock")
        self._discovery = discovery
        self._origin = canonical_https_origin("Registry origin", discovery.origin)
        self._cache = cache
        self._cache_policy = cache_policy
        self._clock = resolved_clock

    async def resolve(
        self,
        query: RegistrySearchQuery,
        *,
        policy: RegistryResolutionPolicy,
        context: CallContext,
    ) -> RegistryResolution:
        if not _is_runtime_instance(query, RegistrySearchQuery):
            raise TypeError("query must be a RegistrySearchQuery")
        if not _is_runtime_instance(policy, RegistryResolutionPolicy):
            raise TypeError("policy must be a RegistryResolutionPolicy")
        if not _is_runtime_instance(context, CallContext):
            raise TypeError("context must be an authenticated CallContext")
        search_key = self._search_key(query, context=context)
        network_used = False
        stubs = None
        if self._cache is not None:
            try:
                stubs = await self._cache.get_search(search_key, now=self._clock.now())
            except RegistryCacheUnavailableError:
                stubs = None
        if stubs is None:
            stubs = await self._discovery.search(query, context=context)
            network_used = True
            if not _is_runtime_instance(stubs, tuple) or len(stubs) > query.limit:
                raise ValueError("Registry search violated the bounded stub contract")
            if self._cache is not None:
                with contextlib.suppress(RegistryCacheUnavailableError):
                    await self._cache.put_search(
                        search_key,
                        stubs,
                        expires_at=self._clock.now() + self._cache_policy.search_ttl_seconds,
                    )
        if not _is_runtime_instance(stubs, tuple) or len(stubs) > query.limit:
            raise ValueError("Registry search violated the bounded stub contract")
        explanations: list[RegistryCandidateExplanation] = []
        selected: RegistrySearchStub | None = None
        for stub in stubs:
            reasons = self._stub_reasons(stub, query=query, policy=policy)
            if reasons:
                explanations.append(
                    RegistryCandidateExplanation(
                        ref=stub.ref,
                        decision=RegistryCandidateDecision.REJECTED,
                        reasons=reasons,
                    )
                )
                continue
            selected = stub
            break
        if selected is None:
            return RegistryResolution(
                source=(
                    RegistryResolutionSource.NETWORK
                    if network_used
                    else RegistryResolutionSource.CACHE
                ),
                server=None,
                explanations=tuple(explanations),
            )
        artifact_key = self._artifact_key(selected, context=context)
        artifact = None
        artifact_from_network = False
        offline_used = False
        if self._cache is not None:
            try:
                artifact = await self._cache.get_artifact(
                    artifact_key,
                    now=self._clock.now(),
                    allow_stale=False,
                )
            except RegistryCacheUnavailableError:
                artifact = None
        if artifact is None:
            network_used = True
            try:
                artifact = await self._discovery.fetch(selected, context=context)
                artifact_from_network = True
            except RegistryUnavailableError as registry_error:
                if self._cache is None or self._cache_policy.offline_max_stale_seconds == 0:
                    raise
                try:
                    artifact = await self._cache.get_artifact(
                        artifact_key,
                        now=self._clock.now(),
                        allow_stale=True,
                    )
                except RegistryCacheUnavailableError:
                    raise registry_error from None
                if artifact is None:
                    raise
                offline_used = True
        self._verify_exact_identity(selected, artifact, request_id=context.request_id)
        if self._cache is not None and artifact_from_network:
            fresh_until = self._clock.now() + self._cache_policy.artifact_ttl_seconds
            with contextlib.suppress(RegistryCacheUnavailableError):
                await self._cache.put_artifact(
                    artifact_key,
                    artifact,
                    fresh_until=fresh_until,
                    stale_until=fresh_until + self._cache_policy.offline_max_stale_seconds,
                )
        server, reasons = self._project(artifact, policy=policy, context=context)
        explanations.append(
            RegistryCandidateExplanation(
                ref=selected.ref,
                decision=(
                    RegistryCandidateDecision.SELECTED
                    if server is not None
                    else RegistryCandidateDecision.REJECTED
                ),
                reasons=() if server is not None else reasons,
            )
        )
        return RegistryResolution(
            source=(
                RegistryResolutionSource.OFFLINE
                if offline_used
                else (
                    RegistryResolutionSource.NETWORK
                    if network_used
                    else RegistryResolutionSource.CACHE
                )
            ),
            server=server,
            explanations=tuple(explanations),
        )

    def _search_key(
        self,
        query: RegistrySearchQuery,
        *,
        context: CallContext,
    ) -> RegistrySearchCacheKey:
        return RegistrySearchCacheKey(
            origin=self._origin,
            identity_scope_hash=self._identity_scope_hash(context),
            contract_version=_QUERY_CONTRACT_VERSION,
            query_digest=_cache_hash(
                {
                    "intent": query.intent,
                    "kinds": query.kinds,
                    "namespace": query.namespace,
                    "limit": query.limit,
                    "view": "stub",
                }
            ),
        )

    def _artifact_key(
        self,
        stub: RegistrySearchStub,
        *,
        context: CallContext,
    ) -> RegistryArtifactCacheKey:
        return RegistryArtifactCacheKey(
            origin=self._origin,
            identity_scope_hash=self._identity_scope_hash(context),
            contract_version=_QUERY_CONTRACT_VERSION,
            artifact_digest=stub.digest,
        )

    @staticmethod
    def _identity_scope_hash(context: CallContext) -> str:
        return _cache_hash(
            {
                "issuer": context.issuer,
                "tenant": context.tenant,
                "subject": context.subject,
                "scopes": tuple(sorted(context.scopes)),
            }
        )

    @staticmethod
    def _stub_reasons(
        stub: RegistrySearchStub,
        *,
        query: RegistrySearchQuery,
        policy: RegistryResolutionPolicy,
    ) -> tuple[RegistryCandidateReason, ...]:
        reasons: list[RegistryCandidateReason] = []
        if stub.kind != "MCPServer" or stub.kind not in query.kinds:
            reasons.append(RegistryCandidateReason.KIND)
        if query.namespace is not None and stub.namespace != query.namespace:
            reasons.append(RegistryCandidateReason.NAMESPACE)
        advertised = {
            item.strip()
            for item in stub.annotations.get(
                "discovery.agentic.dev/capabilities",
                "",
            ).split(",")
            if item.strip()
        }
        attribute_capabilities = _text_tuple(stub.attributes.get("capabilities"))
        if attribute_capabilities is not None:
            advertised.update(attribute_capabilities)
        if not set(policy.required_capabilities).issubset(advertised):
            reasons.append(RegistryCandidateReason.CAPABILITY)
        return tuple(reasons)

    @staticmethod
    def _verify_exact_identity(
        stub: RegistrySearchStub,
        artifact: RegistryArtifact,
        *,
        request_id: str,
    ) -> None:
        if (
            artifact.kind != stub.kind
            or artifact.name != stub.name
            or artifact.namespace != stub.namespace
            or artifact.tag != stub.tag
            or artifact.arn != stub.arn
            or artifact.ref != stub.ref
        ):
            raise RegistryArtifactRaceError(request_id=request_id, ref=stub.ref)
        if artifact.digest != stub.digest:
            raise RegistryArtifactRaceError(request_id=request_id, ref=stub.ref)
        if artifact.computed_digest != artifact.digest:
            raise RegistryDigestMismatchError(request_id=request_id, ref=stub.ref)

    def _project(
        self,
        artifact: RegistryArtifact,
        *,
        policy: RegistryResolutionPolicy,
        context: CallContext,
    ) -> tuple[RegistryADKServer | None, tuple[RegistryCandidateReason, ...]]:
        extension = _mapping(artifact.spec.get("x-tesserix"))
        if extension is None:
            return None, (RegistryCandidateReason.CONTRACT,)
        lifecycle = extension.get("lifecycle")
        if not isinstance(lifecycle, str) or lifecycle not in policy.allowed_lifecycles:
            return None, (RegistryCandidateReason.LIFECYCLE,)
        protocols = _text_tuple(extension.get("protocolVersions"))
        if protocols is None or not set(protocols) & set(policy.supported_protocol_versions):
            return None, (RegistryCandidateReason.PROTOCOL,)
        scopes = _text_tuple(extension.get("requiredScopes"))
        if scopes is None or not set(scopes).issubset(context.scopes):
            return None, (RegistryCandidateReason.SCOPE,)
        semantic = _mapping(extension.get("semantic"))
        capabilities = None if semantic is None else _text_tuple(semantic.get("capabilities"))
        if capabilities is None or not set(policy.required_capabilities).issubset(capabilities):
            return None, (RegistryCandidateReason.CAPABILITY,)
        route = _mapping(extension.get("routePolicy"))
        path = None if route is None else route.get("gatewayPath")
        if not self._gateway_path(path):
            return None, (RegistryCandidateReason.GATEWAY,)
        tools = extension.get("tools")
        if not _is_sequence(tools):
            return None, (RegistryCandidateReason.CONTRACT,)
        by_name: dict[str, Mapping[str, object]] = {}
        for tool in tools:
            if not _is_text_mapping(tool):
                continue
            tool_name = tool.get("name")
            if _is_str(tool_name):
                by_name[tool_name] = tool
        allowed = (
            tuple(name for name in by_name if name not in policy.tool_deny)
            if "*" in policy.tool_allow
            else tuple(name for name in policy.tool_allow if name not in policy.tool_deny)
        )
        if not allowed or any(name not in by_name for name in allowed):
            return None, (RegistryCandidateReason.TOOL_POLICY,)
        if len(allowed) > policy.max_tools:
            return None, (RegistryCandidateReason.TOOL_POLICY,)
        requirements = {requirement.name: requirement for requirement in policy.tool_requirements}
        resolved: list[_ResolvedTool] = []
        for name in allowed:
            requirement = requirements.get(name)
            if requirement is None:
                return None, (RegistryCandidateReason.FINGERPRINT,)
            resolved_tool, reason = self._resolve_tool(
                name,
                by_name[name],
                requirement=requirement,
                policy=policy,
                context=context,
            )
            if resolved_tool is None:
                return None, (reason,)
            resolved.append(resolved_tool)
        if sum(tool.schema_bytes for tool in resolved) > policy.max_schema_bytes:
            return None, (RegistryCandidateReason.SCHEMA,)
        pins = tuple(
            RegistryToolPin(
                name=tool.name,
                input_fingerprint=tool.input_fingerprint,
                output_fingerprint=tool.output_fingerprint,
            )
            for tool in resolved
        )
        return (
            RegistryADKServer(
                name=policy.server_name,
                endpoint=policy.gateway_origin + path,
                allow=allowed,
                deny=policy.tool_deny,
                prefix=policy.tool_prefix,
                max_tools=policy.max_tools,
                max_schema_bytes=policy.max_schema_bytes,
                artifact_ref=artifact.ref,
                artifact_digest=artifact.digest,
                tool_pins=pins,
            ),
            (),
        )

    @staticmethod
    def _resolve_tool(
        name: str,
        tool: Mapping[str, object],
        *,
        requirement: RegistryToolRequirement,
        policy: RegistryResolutionPolicy,
        context: CallContext,
    ) -> tuple[_ResolvedTool | None, RegistryCandidateReason]:
        status = tool.get("status")
        if not isinstance(status, str) or status not in policy.allowed_lifecycles:
            return None, RegistryCandidateReason.LIFECYCLE
        scopes = _text_tuple(tool.get("requiredScopes"))
        if scopes is None or not set(scopes).issubset(context.scopes):
            return None, RegistryCandidateReason.SCOPE
        capabilities = _text_tuple(tool.get("capabilities"))
        if capabilities is None or not set(policy.required_capabilities).issubset(capabilities):
            return None, RegistryCandidateReason.CAPABILITY
        input_schema = _schema(tool.get("inputSchema"))
        input_fingerprint = tool.get("inputFingerprint")
        output_fingerprint = tool.get("outputFingerprint")
        if (
            input_schema is None
            or not isinstance(input_fingerprint, str)
            or not isinstance(output_fingerprint, str)
            or _FINGERPRINT.fullmatch(input_fingerprint) is None
            or _FINGERPRINT.fullmatch(output_fingerprint) is None
        ):
            return None, RegistryCandidateReason.CONTRACT
        if schema_fingerprint(input_schema) != input_fingerprint:
            return None, RegistryCandidateReason.FINGERPRINT
        if (
            requirement.expected_input_fingerprint is not None
            and requirement.expected_input_fingerprint != input_fingerprint
        ) or (
            requirement.expected_output_fingerprint is not None
            and requirement.expected_output_fingerprint != output_fingerprint
        ):
            return None, RegistryCandidateReason.FINGERPRINT
        baseline = requirement.compatible_input_schema
        if baseline is not None:
            baseline_schema = _schema(baseline)
            if (
                baseline_schema is None
                or classify_schema_change(
                    baseline_schema,
                    input_schema,
                    direction=SchemaDirection.INPUT,
                )
                is SchemaChange.BREAKING
            ):
                return None, RegistryCandidateReason.SCHEMA
        encoded_schema = json.dumps(
            input_schema,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return (
            _ResolvedTool(
                name=name,
                input_fingerprint=input_fingerprint,
                output_fingerprint=output_fingerprint,
                schema_bytes=len(encoded_schema),
            ),
            RegistryCandidateReason.CONTRACT,
        )

    @staticmethod
    def _gateway_path(value: object) -> TypeGuard[str]:
        if not isinstance(value, str) or not value or len(value) > 2048:
            return False
        parsed = urlsplit(value)
        return (
            not parsed.scheme
            and not parsed.netloc
            and not parsed.query
            and not parsed.fragment
            and parsed.path.startswith("/")
            and not parsed.path.startswith("//")
            and "\\" not in value
            and all(part not in {".", ".."} for part in parsed.path.split("/"))
        )


__all__ = [
    "InMemoryRegistryCache",
    "RegistryADKServer",
    "RegistryArtifact",
    "RegistryArtifactCacheKey",
    "RegistryArtifactRaceError",
    "RegistryAuthenticationError",
    "RegistryAuthorizationError",
    "RegistryCachePolicy",
    "RegistryCacheUnavailableError",
    "RegistryCandidateDecision",
    "RegistryCandidateExplanation",
    "RegistryCandidateReason",
    "RegistryContractError",
    "RegistryDigestMismatchError",
    "RegistryDiscovery",
    "RegistryDiscoveryCache",
    "RegistryDiscoveryError",
    "RegistryResolution",
    "RegistryResolutionPolicy",
    "RegistryResolutionSource",
    "RegistryResolver",
    "RegistrySearchCacheKey",
    "RegistrySearchQuery",
    "RegistrySearchStub",
    "RegistryToolPin",
    "RegistryToolRequirement",
    "RegistryUnavailableError",
    "registry_artifact_digest",
]
