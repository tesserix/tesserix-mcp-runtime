from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Never, Protocol, cast, overload
from urllib.parse import urlsplit

import httpx2 as httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from tesserix_mcp_runtime.contracts import JsonValue
from tesserix_mcp_testkit.journey import JourneyEvidenceError, scan_journey_surfaces

EVALUATION_SCHEMA_VERSION: Literal[1] = 1
SECRET_CANARY_PLACEHOLDER = "${TESSERIX_EVAL_SECRET_CANARY}"
TENANT_CANARY_PLACEHOLDER = "${TESSERIX_EVAL_TENANT_CANARY}"

_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?")
_SEMVER = re.compile(r"0|[1-9][0-9]*\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?")
_ISSUE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TIMESTAMP = re.compile(
    r"(?:19|20)[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)
_MAX_BUNDLE_BYTES = 1024 * 1024
_MAX_BUNDLE_DEPTH = 64
_MAX_BUNDLE_NODES = 100_000


class EvaluationContractError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class EvaluationVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _AmbiguousJsonError(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise _AmbiguousJsonError
        document[key] = value
    return document


def _reject_json_constant(value: str) -> Never:
    del value
    raise _AmbiguousJsonError


def _validate_json_structure(document: object) -> None:
    pending = [(document, 1)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if depth > _MAX_BUNDLE_DEPTH or nodes > _MAX_BUNDLE_NODES:
            raise EvaluationContractError("bundle_too_complex")
        if isinstance(value, dict):
            mapping = cast(dict[object, object], value)
            pending.extend((child, depth + 1) for child in mapping.values())
        elif isinstance(value, list):
            sequence = cast(list[object], value)
            pending.extend((child, depth + 1) for child in sequence)


def _collection_items(value: object) -> tuple[object, ...] | None:
    if isinstance(value, (tuple, list, set, frozenset)):
        return tuple(cast(Iterable[object], value))
    return None


class AssertionOperator(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    EXISTS = "exists"
    ABSENT = "absent"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"


class EvaluationMetric(StrEnum):
    CORRECTNESS = "correctness"
    SCHEMA_CONFORMANCE = "schema_conformance"
    SECRET_LEAKAGE = "secret_leakage"
    TENANT_ISOLATION = "tenant_isolation"
    AUTHORIZATION_DENIAL = "authorization_denial"
    IDEMPOTENCY = "idempotency"
    LATENCY = "latency"
    AVAILABILITY = "availability"


class EvaluationMode(StrEnum):
    IN_PROCESS = "in_process"
    STREAMABLE_HTTP = "streamable_http"


class EvaluationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"
    QUARANTINED = "quarantined"


class PromotionStage(StrEnum):
    EXPERIMENTAL = "experimental"
    INTERNAL = "internal"
    GA = "ga"


class ReviewerRole(StrEnum):
    EVALUATION_OWNER = "evaluation_owner"
    SECURITY_REVIEWER = "security_reviewer"
    REGISTRY_OWNER = "registry_owner"
    RELEASE_REVIEWER = "release_reviewer"


class EvaluationApproval(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    required: bool
    granted: bool
    approval_id: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_grant(self) -> EvaluationApproval:
        if self.granted != (self.approval_id is not None):
            raise ValueError("a granted approval requires exactly one approval id")
        return self


class EvaluationContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    tenant: str = Field(min_length=1, max_length=128)
    scopes: tuple[str, ...] = Field(max_length=64)
    approval: EvaluationApproval
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("scopes", mode="before")
    @classmethod
    def normalize_scopes(cls, value: object) -> object:
        items = _collection_items(value)
        if items is not None:
            return tuple(sorted(items, key=str))
        return value

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(not scope or len(scope) > 128 for scope in value):
            raise ValueError("scopes must be unique bounded strings")
        return value


class StructuredResultExpectation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["structured_result"] = "structured_result"
    value: JsonValue


class EvaluationAssertion(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pointer: str = Field(min_length=1, max_length=512)
    operator: AssertionOperator
    value: JsonValue = None

    @field_validator("pointer")
    @classmethod
    def validate_pointer(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("assertion pointers must be RFC 6901 paths")
        return value

    @model_validator(mode="after")
    def validate_value(self) -> EvaluationAssertion:
        if self.operator in {AssertionOperator.EXISTS, AssertionOperator.ABSENT} and (
            self.value is not None
        ):
            raise ValueError("existence assertions do not accept a value")
        return self


class AssertionsExpectation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["assertions"] = "assertions"
    assertions: tuple[EvaluationAssertion, ...] = Field(min_length=1, max_length=64)


class ErrorExpectation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["error"] = "error"
    code: str = Field(min_length=1, max_length=128)

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("error code must be a safe identifier")
        return value


class CancellationExpectation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["cancellation"] = "cancellation"


EvaluationExpectation = Annotated[
    StructuredResultExpectation
    | AssertionsExpectation
    | ErrorExpectation
    | CancellationExpectation,
    Field(discriminator="kind"),
]


class TelemetryExpectation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    required_events: tuple[str, ...] = Field(default=(), max_length=32)
    forbidden_events: tuple[str, ...] = Field(default=(), max_length=32)

    @field_validator("required_events", "forbidden_events", mode="before")
    @classmethod
    def normalize_events(cls, value: object) -> object:
        items = _collection_items(value)
        if items is not None:
            return tuple(sorted(items, key=str))
        return value

    @model_validator(mode="after")
    def validate_events(self) -> TelemetryExpectation:
        required = set(self.required_events)
        forbidden = set(self.forbidden_events)
        if (
            len(required) != len(self.required_events)
            or len(forbidden) != len(self.forbidden_events)
            or required & forbidden
            or any(_IDENTIFIER.fullmatch(event) is None for event in required | forbidden)
        ):
            raise ValueError("telemetry events must be disjoint unique safe identifiers")
        return self


class EvaluationQuarantine(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    owner: str = Field(min_length=1, max_length=128)
    issue: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=1, max_length=512)

    @field_validator("owner")
    @classmethod
    def validate_owner(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("quarantine owner must be a safe identifier")
        return value

    @field_validator("issue")
    @classmethod
    def validate_issue(cls, value: str) -> str:
        if _ISSUE.fullmatch(value) is None:
            raise ValueError("quarantine must reference an owned GitHub issue")
        return value


class PromotionMetricGate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: EvaluationMetric
    minimum_score: float = Field(ge=0, le=1)


class PromotionStagePolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    stage: PromotionStage
    gates: tuple[PromotionMetricGate, ...] = Field(min_length=1)
    allowed_modes: tuple[EvaluationMode, ...] = Field(min_length=1)
    required_reviewer_roles: tuple[ReviewerRole, ...] = Field(min_length=1)
    minimum_reviewers: int = Field(ge=1, le=16)
    allow_quarantine: bool

    @field_validator(
        "gates",
        "allowed_modes",
        "required_reviewer_roles",
        mode="before",
    )
    @classmethod
    def normalize_policy_sets(cls, value: object) -> object:
        items = _collection_items(value)
        if items is not None:
            return tuple(sorted(items, key=str))
        return value

    @model_validator(mode="after")
    def validate_unique_policy_entries(self) -> PromotionStagePolicy:
        metrics = [gate.metric for gate in self.gates]
        if (
            len(metrics) != len(set(metrics))
            or len(self.allowed_modes) != len(set(self.allowed_modes))
            or len(self.required_reviewer_roles) != len(set(self.required_reviewer_roles))
        ):
            raise ValueError("promotion policy entries must be unique")
        return self


class EvaluationPromotionPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    stages: tuple[PromotionStagePolicy, ...] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def validate_stages(self) -> EvaluationPromotionPolicy:
        stages = [policy.stage for policy in self.stages]
        if len(stages) != len(set(stages)):
            raise ValueError("promotion stages must be unique")
        return self

    def for_stage(self, stage: PromotionStage) -> PromotionStagePolicy:
        for policy in self.stages:
            if policy.stage is stage:
                return policy
        raise EvaluationContractError(f"promotion_stage_missing:{stage.value}")


def default_evaluation_promotion_policy() -> EvaluationPromotionPolicy:
    all_metrics = tuple(
        PromotionMetricGate(
            metric=metric,
            minimum_score=(
                0.95
                if metric is EvaluationMetric.LATENCY
                else 0.99
                if metric is EvaluationMetric.AVAILABILITY
                else 1.0
            ),
        )
        for metric in EvaluationMetric
    )
    strict_metrics = tuple(
        PromotionMetricGate(metric=metric, minimum_score=1.0) for metric in EvaluationMetric
    )
    return EvaluationPromotionPolicy(
        stages=(
            PromotionStagePolicy(
                stage=PromotionStage.EXPERIMENTAL,
                gates=all_metrics,
                allowed_modes=(EvaluationMode.IN_PROCESS, EvaluationMode.STREAMABLE_HTTP),
                required_reviewer_roles=(ReviewerRole.EVALUATION_OWNER,),
                minimum_reviewers=1,
                allow_quarantine=True,
            ),
            PromotionStagePolicy(
                stage=PromotionStage.INTERNAL,
                gates=strict_metrics,
                allowed_modes=(EvaluationMode.STREAMABLE_HTTP,),
                required_reviewer_roles=(
                    ReviewerRole.EVALUATION_OWNER,
                    ReviewerRole.SECURITY_REVIEWER,
                ),
                minimum_reviewers=2,
                allow_quarantine=False,
            ),
            PromotionStagePolicy(
                stage=PromotionStage.GA,
                gates=strict_metrics,
                allowed_modes=(EvaluationMode.STREAMABLE_HTTP,),
                required_reviewer_roles=(
                    ReviewerRole.EVALUATION_OWNER,
                    ReviewerRole.REGISTRY_OWNER,
                    ReviewerRole.RELEASE_REVIEWER,
                    ReviewerRole.SECURITY_REVIEWER,
                ),
                minimum_reviewers=3,
                allow_quarantine=False,
            ),
        )
    )


class EvaluationCase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = EVALUATION_SCHEMA_VERSION
    case_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=256)
    arguments: dict[str, JsonValue]
    expectation: EvaluationExpectation
    tags: tuple[str, ...] = Field(min_length=1, max_length=32)
    context: EvaluationContext
    metrics: tuple[EvaluationMetric, ...] = Field(min_length=1)
    blocking_metrics: tuple[EvaluationMetric, ...]
    telemetry: TelemetryExpectation = Field(default_factory=TelemetryExpectation)
    latency_budget_ms: int = Field(ge=1, le=60_000)
    timeout_ms: int = Field(default=60_000, ge=1, le=60_000)
    attempts: int = Field(default=1, ge=1, le=10)
    quarantine: EvaluationQuarantine | None = None

    @field_validator("case_id", "tool")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("identifier must use lowercase safe characters")
        return value

    @field_validator("tags", "metrics", "blocking_metrics", mode="before")
    @classmethod
    def normalize_sets(cls, value: object) -> object:
        items = _collection_items(value)
        if items is not None:
            return tuple(sorted(items, key=str))
        return value

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)) or any(
            _IDENTIFIER.fullmatch(tag) is None for tag in value
        ):
            raise ValueError("tags must be unique safe identifiers")
        return value

    @model_validator(mode="after")
    def validate_metrics(self) -> EvaluationCase:
        if len(self.metrics) != len(set(self.metrics)):
            raise ValueError("metrics must be unique")
        if len(self.blocking_metrics) != len(set(self.blocking_metrics)):
            raise ValueError("blocking metrics must be unique")
        if not set(self.blocking_metrics) <= set(self.metrics):
            raise ValueError("blocking metrics must be evaluated by the case")
        if self.latency_budget_ms > self.timeout_ms:
            raise ValueError("latency budget cannot exceed the case timeout")
        has_canary = _contains_value(self.arguments, SECRET_CANARY_PLACEHOLDER)
        evaluates_secrets = EvaluationMetric.SECRET_LEAKAGE in self.metrics
        if has_canary != evaluates_secrets:
            raise ValueError("secret leakage cases require exactly one safe canary placeholder")
        has_tenant_canary = _contains_value(self.arguments, TENANT_CANARY_PLACEHOLDER)
        evaluates_tenancy = EvaluationMetric.TENANT_ISOLATION in self.metrics
        if has_tenant_canary != evaluates_tenancy:
            raise ValueError("tenant isolation cases require a safe tenant canary placeholder")
        if EvaluationMetric.IDEMPOTENCY in self.metrics and (
            self.attempts < 2 or self.context.idempotency_key is None
        ):
            raise ValueError("idempotency cases require duplicate attempts under one key")
        if EvaluationMetric.AUTHORIZATION_DENIAL in self.metrics and not isinstance(
            self.expectation,
            ErrorExpectation,
        ):
            raise ValueError("authorization denial cases require an expected error")
        return self


class EvaluationBundle(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        title="Tesserix MCP evaluation bundle v1",
        json_schema_extra={"$id": "https://schemas.tesserix.dev/mcp/evaluation-bundle/v1"},
    )

    schema_version: Literal[1] = EVALUATION_SCHEMA_VERSION
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=5, max_length=64)
    cases: tuple[EvaluationCase, ...] = Field(min_length=1, max_length=1_000)
    promotion_policy: EvaluationPromotionPolicy = Field(
        default_factory=default_evaluation_promotion_policy
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("bundle name must be a safe identifier")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if _SEMVER.fullmatch(value) is None:
            raise ValueError("bundle version must be semantic")
        return value

    @model_validator(mode="after")
    def validate_cases(self) -> EvaluationBundle:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("evaluation case ids must be unique")
        return self

    @property
    def dataset_digest(self) -> str:
        document = self.model_dump(mode="json")
        canonical = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()


def evaluation_bundle_json_schema() -> dict[str, object]:
    return cast(dict[str, object], EvaluationBundle.model_json_schema(mode="validation"))


class EvaluationArtifactBinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    source_digest: str
    runtime_digest: str
    manifest_digest: str
    image_digest: str
    dataset_digest: str

    @field_validator(
        "source_digest",
        "runtime_digest",
        "manifest_digest",
        "image_digest",
        "dataset_digest",
    )
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if _DIGEST.fullmatch(value) is None:
            raise ValueError("artifact digests must be exact sha256 values")
        return value

    def assert_matches(self, bundle: EvaluationBundle) -> None:
        if self.dataset_digest != bundle.dataset_digest:
            raise EvaluationContractError("dataset_digest_mismatch")


class EvaluationInvocation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    tool: str
    arguments: dict[str, JsonValue]
    context: EvaluationContext
    attempt: int = Field(ge=1, le=10)


class EvaluationObservation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    structured_result: JsonValue = None
    error_code: str | None = Field(default=None, min_length=1, max_length=128)
    cancelled: bool = False
    available: bool = True
    schema_valid: bool
    telemetry_events: tuple[str, ...] = Field(default=(), max_length=64)
    side_effect_digest: str | None = None

    @field_validator("telemetry_events", mode="before")
    @classmethod
    def normalize_telemetry(cls, value: object) -> object:
        items = _collection_items(value)
        if items is not None:
            return tuple(sorted(items, key=str))
        return value

    @model_validator(mode="after")
    def validate_observation(self) -> EvaluationObservation:
        if self.cancelled and self.error_code is not None:
            raise ValueError("cancelled observations cannot also be errors")
        if self.error_code is not None and _IDENTIFIER.fullmatch(self.error_code) is None:
            raise ValueError("observation error code must be a safe identifier")
        if len(self.telemetry_events) != len(set(self.telemetry_events)) or any(
            _IDENTIFIER.fullmatch(event) is None for event in self.telemetry_events
        ):
            raise ValueError("telemetry events must be unique safe identifiers")
        if (
            self.side_effect_digest is not None
            and _DIGEST.fullmatch(self.side_effect_digest) is None
        ):
            raise ValueError("side effect evidence must be an exact sha256 digest")
        return self


class EvaluationTarget(Protocol):
    mode: EvaluationMode

    async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation: ...


class InProcessEvaluationTarget:
    mode = EvaluationMode.IN_PROCESS

    def __init__(
        self,
        handler: Callable[[EvaluationInvocation], Awaitable[EvaluationObservation]],
    ) -> None:
        self._handler = handler

    async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation:
        return await self._handler(invocation)


class StreamableHttpEvaluationTarget:
    mode = EvaluationMode.STREAMABLE_HTTP

    def __init__(
        self,
        *,
        url: str,
        http_client: httpx.AsyncClient | None = None,
        http_client_factory: Callable[
            [EvaluationContext], AbstractAsyncContextManager[httpx.AsyncClient]
        ]
        | None = None,
        allowed_hosts: tuple[str, ...] = (),
    ) -> None:
        parsed = urlsplit(url)
        if (
            len(url) > 2_048
            or parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or (parsed.scheme != "https" and http_client is None and http_client_factory is None)
            or (http_client is not None and http_client_factory is not None)
        ):
            raise EvaluationContractError("streamable_http_url")
        normalized_hosts = tuple(host.lower() for host in allowed_hosts)
        if len(normalized_hosts) != len(set(normalized_hosts)) or any(
            not host
            or len(host) > 253
            or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for character in host)
            for host in normalized_hosts
        ):
            raise EvaluationContractError("streamable_http_host")
        owns_network = http_client is None and http_client_factory is None
        if (owns_network or normalized_hosts) and parsed.hostname.lower() not in normalized_hosts:
            raise EvaluationContractError("streamable_http_host")
        self._url = url
        self._http_client = http_client
        self._http_client_factory = http_client_factory

    async def observe(self, invocation: EvaluationInvocation) -> EvaluationObservation:
        try:
            if self._http_client_factory is not None:
                async with self._http_client_factory(invocation.context) as client:
                    result = await self._call(invocation, client)
            elif self._http_client is not None:
                result = await self._call(invocation, self._http_client)
            else:
                async with httpx.AsyncClient() as client:
                    result = await self._call(invocation, client)
        except MCPError as error:
            return EvaluationObservation(
                error_code=_mcp_error_code(error),
                schema_valid=True,
            )
        structured = result.structured_content
        if result.is_error:
            return EvaluationObservation(
                error_code=_structured_error_code(structured) or "tool_error",
                schema_valid=structured is not None,
            )
        return EvaluationObservation(
            structured_result=structured,
            schema_valid=structured is not None,
        )

    async def _call(
        self,
        invocation: EvaluationInvocation,
        client: httpx.AsyncClient,
    ) -> CallToolResult:
        async with (
            streamable_http_client(
                self._url,
                http_client=client,
                terminate_on_close=False,
            ) as streams,
            ClientSession(streams[0], streams[1]) as session,
        ):
            await session.initialize()
            return await session.call_tool(
                invocation.tool,
                invocation.arguments,
            )


class EvaluationMetricResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: EvaluationMetric
    passed: bool
    code: str


class EvaluationCaseResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    case_id: str
    status: EvaluationStatus
    attempts: int = Field(ge=0, le=10)
    duration_ms: float = Field(ge=0, le=600_000)
    outcome_digest: str
    telemetry_digest: str
    metrics: tuple[EvaluationMetricResult, ...]
    failure_codes: tuple[str, ...]
    quarantine_owner: str | None = None
    quarantine_issue: str | None = None


class EvaluationMetricSummary(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: EvaluationMetric
    passed_cases: int = Field(ge=0)
    total_cases: int = Field(ge=1)
    score: float = Field(ge=0, le=1)


class EvaluationSignature(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=88, max_length=88)

    @field_validator("key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("signature key id must be a safe identifier")
        return value


class EvaluationReviewer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str = Field(min_length=1, max_length=128)
    roles: tuple[ReviewerRole, ...] = Field(min_length=1, max_length=4)

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("reviewer subject must be a safe identifier")
        return value

    @field_validator("roles", mode="before")
    @classmethod
    def normalize_roles(cls, value: object) -> object:
        items = _collection_items(value)
        if items is not None:
            return tuple(sorted(items, key=str))
        return value

    @field_validator("roles")
    @classmethod
    def validate_roles(cls, value: tuple[ReviewerRole, ...]) -> tuple[ReviewerRole, ...]:
        if len(value) != len(set(value)):
            raise ValueError("reviewer roles must be unique")
        return value


class EvaluationReview(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    author: str = Field(min_length=1, max_length=128)
    reviewers: tuple[EvaluationReviewer, ...] = Field(max_length=16)

    @field_validator("author")
    @classmethod
    def validate_author(cls, value: str) -> str:
        if _IDENTIFIER.fullmatch(value) is None:
            raise ValueError("evaluation author must be a safe identifier")
        return value

    @model_validator(mode="after")
    def validate_independence(self) -> EvaluationReview:
        subjects = [reviewer.subject for reviewer in self.reviewers]
        if len(subjects) != len(set(subjects)):
            raise ValueError("evaluation reviewers must be unique")
        if self.author in subjects:
            raise ValueError("evaluation author cannot approve their own evidence")
        return self


class EvaluationPromotionDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    stage: PromotionStage
    approved: bool
    reasons: tuple[str, ...]
    evidence_digest: str


class EvaluationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = EVALUATION_SCHEMA_VERSION
    bundle_name: str
    bundle_version: str
    mode: EvaluationMode
    created_at: str
    binding: EvaluationArtifactBinding
    cases: tuple[EvaluationCaseResult, ...]
    metrics: tuple[EvaluationMetricSummary, ...]
    complete: bool
    passed: bool
    signature: EvaluationSignature | None = None

    def metric(self, metric: EvaluationMetric) -> EvaluationMetricSummary:
        for summary in self.metrics:
            if summary.metric is metric:
                return summary
        raise EvaluationContractError(f"metric_missing:{metric.value}")

    def to_json(self) -> str:
        return _canonical_json(self.model_dump(mode="json")).decode("utf-8")

    def to_markdown(self) -> str:
        lines = [
            f"# Evaluation: {self.bundle_name} {self.bundle_version}",
            "",
            f"Status: {'passed' if self.passed else 'failed'}",
            f"Mode: {self.mode.value}",
            f"Complete: {'yes' if self.complete else 'no'}",
            "",
            "## Artifact bindings",
            "",
            "| Artifact | Digest |",
            "| --- | --- |",
            f"| Source | {self.binding.source_digest} |",
            f"| Runtime | {self.binding.runtime_digest} |",
            f"| Manifest | {self.binding.manifest_digest} |",
            f"| Image | {self.binding.image_digest} |",
            f"| Dataset | {self.binding.dataset_digest} |",
            "",
            "## Cases",
            "",
            "| Case | Status | Attempts | Duration ms | Failures |",
            "| --- | --- | ---: | ---: | --- |",
        ]
        lines.extend(
            f"| {case.case_id} | {case.status.value} | {case.attempts} | "
            f"{case.duration_ms:.3f} | {', '.join(case.failure_codes) or '-'} |"
            for case in self.cases
        )
        lines.extend(
            [
                "",
                "## Metrics",
                "",
                "| Metric | Passed | Total | Score |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        lines.extend(
            f"| {summary.metric.value} | {summary.passed_cases} | "
            f"{summary.total_cases} | {summary.score:.6f} |"
            for summary in self.metrics
        )
        return "\n".join(lines) + "\n"


def sign_evaluation_report(
    report: EvaluationReport,
    *,
    key_id: str,
    private_key: Ed25519PrivateKey,
) -> EvaluationReport:
    if report.signature is not None:
        raise EvaluationVerificationError("already_signed")
    signature = private_key.sign(_report_signature_payload(report))
    return report.model_copy(
        update={
            "signature": EvaluationSignature(
                key_id=key_id,
                value=base64.b64encode(signature).decode("ascii"),
            )
        }
    )


def _revalidate_bundle(bundle: EvaluationBundle) -> EvaluationBundle:
    try:
        return EvaluationBundle.model_validate(bundle.model_dump(mode="json"))
    except ValidationError:
        raise EvaluationContractError("invalid_bundle") from None


def verify_evaluation_report(
    report: EvaluationReport,
    *,
    bundle: EvaluationBundle,
    binding: EvaluationArtifactBinding,
    public_keys: Mapping[str, Ed25519PublicKey],
) -> None:
    try:
        bundle = _revalidate_bundle(bundle)
    except EvaluationContractError:
        raise EvaluationVerificationError("invalid_bundle") from None
    try:
        binding.assert_matches(bundle)
    except EvaluationContractError:
        raise EvaluationVerificationError("dataset_digest_mismatch") from None
    if report.binding != binding:
        raise EvaluationVerificationError("binding_mismatch")
    if report.bundle_name != bundle.name or report.bundle_version != bundle.version:
        raise EvaluationVerificationError("bundle_identity_mismatch")
    signature = report.signature
    if signature is None:
        raise EvaluationVerificationError("signature_missing")
    public_key = public_keys.get(signature.key_id)
    if public_key is None:
        raise EvaluationVerificationError("signing_key_unknown")
    try:
        raw_signature = base64.b64decode(signature.value, validate=True)
        if len(raw_signature) != 64:
            raise ValueError
        public_key.verify(raw_signature, _report_signature_payload(report))
    except (binascii.Error, InvalidSignature, TypeError, ValueError):
        raise EvaluationVerificationError("signature_invalid") from None
    _validate_report_against_bundle(report, bundle)


def _validate_report_against_bundle(
    report: EvaluationReport,
    bundle: EvaluationBundle,
) -> None:
    if _TIMESTAMP.fullmatch(report.created_at) is None:
        raise EvaluationVerificationError("report_inconsistent")
    if tuple(result.case_id for result in report.cases) != tuple(
        case.case_id for case in bundle.cases
    ):
        raise EvaluationVerificationError("report_inconsistent")
    for case, result in zip(bundle.cases, report.cases, strict=True):
        metric_results = {metric.metric: metric for metric in result.metrics}
        if (
            len(metric_results) != len(result.metrics)
            or set(metric_results) != set(case.metrics)
            or _DIGEST.fullmatch(result.outcome_digest) is None
            or _DIGEST.fullmatch(result.telemetry_digest) is None
        ):
            raise EvaluationVerificationError("report_inconsistent")
        expected_failures = tuple(
            sorted({metric.code for metric in result.metrics if not metric.passed})
        )
        if result.failure_codes != expected_failures:
            raise EvaluationVerificationError("report_inconsistent")
        expected_quarantine = case.quarantine
        if result.quarantine_owner != (
            expected_quarantine.owner if expected_quarantine is not None else None
        ) or result.quarantine_issue != (
            expected_quarantine.issue if expected_quarantine is not None else None
        ):
            raise EvaluationVerificationError("report_inconsistent")
        if expected_quarantine is not None:
            expected_status = EvaluationStatus.QUARANTINED
            if any(metric_results[metric].passed for metric in case.blocking_metrics):
                raise EvaluationVerificationError("report_inconsistent")
        elif result.status is EvaluationStatus.INCOMPLETE:
            expected_status = EvaluationStatus.INCOMPLETE
            if result.attempts >= case.attempts:
                raise EvaluationVerificationError("report_inconsistent")
        else:
            if result.attempts != case.attempts:
                raise EvaluationVerificationError("report_inconsistent")
            failed_blocking = any(
                not metric_results[metric].passed for metric in case.blocking_metrics
            )
            expected_status = (
                EvaluationStatus.FAILED if failed_blocking else EvaluationStatus.PASSED
            )
        if result.status is not expected_status:
            raise EvaluationVerificationError("report_inconsistent")
    expected_summaries = _summarize_metrics(report.cases)
    expected_complete = all(
        result.status is not EvaluationStatus.INCOMPLETE for result in report.cases
    )
    expected_passed = expected_complete and all(
        result.status is EvaluationStatus.PASSED for result in report.cases
    )
    if (
        report.metrics != expected_summaries
        or report.complete is not expected_complete
        or report.passed is not expected_passed
    ):
        raise EvaluationVerificationError("report_inconsistent")


def assess_evaluation_promotion(
    report: EvaluationReport,
    *,
    bundle: EvaluationBundle,
    binding: EvaluationArtifactBinding,
    public_keys: Mapping[str, Ed25519PublicKey],
    stage: PromotionStage,
    review: EvaluationReview,
) -> EvaluationPromotionDecision:
    verify_evaluation_report(
        report,
        bundle=bundle,
        binding=binding,
        public_keys=public_keys,
    )
    policy = bundle.promotion_policy.for_stage(stage)
    reasons: set[str] = set()
    if not report.complete:
        reasons.add("report_incomplete")
    if not report.passed:
        reasons.add("blocking_case_failed")
    if report.mode not in policy.allowed_modes:
        reasons.add("execution_mode_not_allowed")
    if not policy.allow_quarantine and any(
        case.status is EvaluationStatus.QUARANTINED for case in report.cases
    ):
        reasons.add("quarantine_not_allowed")
    summaries = {summary.metric: summary for summary in report.metrics}
    for gate in policy.gates:
        summary = summaries.get(gate.metric)
        if summary is None:
            reasons.add(f"metric_missing:{gate.metric.value}")
        elif summary.score < gate.minimum_score:
            reasons.add(f"metric_below_threshold:{gate.metric.value}")
    if len(review.reviewers) < policy.minimum_reviewers:
        reasons.add("reviewers_insufficient")
    observed_roles = {role for reviewer in review.reviewers for role in reviewer.roles}
    for role in policy.required_reviewer_roles:
        if role not in observed_roles:
            reasons.add(f"reviewer_role_missing:{role.value}")
    return EvaluationPromotionDecision(
        stage=stage,
        approved=not reasons,
        reasons=tuple(sorted(reasons)),
        evidence_digest=_sha256(report.model_dump(mode="json")),
    )


def _report_signature_payload(report: EvaluationReport) -> bytes:
    return _canonical_json(report.model_dump(mode="json", exclude={"signature"}))


class EvaluationRunner:
    def __init__(
        self,
        *,
        bundle: EvaluationBundle,
        binding: EvaluationArtifactBinding,
        target: EvaluationTarget,
        now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        validated_bundle = _revalidate_bundle(bundle)
        binding.assert_matches(validated_bundle)
        self._bundle = validated_bundle
        self._binding = binding
        self._target = target
        self._now = now or (lambda: datetime.now(tz=UTC))
        self._monotonic = monotonic or time.perf_counter

    async def run(self) -> EvaluationReport:
        try:
            scan_journey_surfaces((self._bundle.model_dump_json(),))
        except JourneyEvidenceError:
            raise EvaluationContractError("unsafe_bundle") from None
        results = tuple([await self._run_case(case) for case in self._bundle.cases])
        summaries = _summarize_metrics(results)
        complete = all(result.status is not EvaluationStatus.INCOMPLETE for result in results)
        passed = complete and all(result.status is EvaluationStatus.PASSED for result in results)
        created_at = self._now().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        return EvaluationReport(
            bundle_name=self._bundle.name,
            bundle_version=self._bundle.version,
            mode=self._target.mode,
            created_at=created_at,
            binding=self._binding,
            cases=results,
            metrics=summaries,
            complete=complete,
            passed=passed,
        )

    async def _run_case(self, case: EvaluationCase) -> EvaluationCaseResult:
        observations: list[EvaluationObservation] = []
        durations: list[float] = []
        secret_canary = (
            _derive_secret_canary(self._binding, case.case_id)
            if EvaluationMetric.SECRET_LEAKAGE in case.metrics
            else None
        )
        tenant_canary = (
            _derive_canary(self._binding, case.case_id, "tenant")
            if EvaluationMetric.TENANT_ISOLATION in case.metrics
            else None
        )
        arguments = (
            _replace_value(case.arguments, SECRET_CANARY_PLACEHOLDER, secret_canary)
            if secret_canary is not None
            else case.arguments
        )
        if tenant_canary is not None:
            arguments = _replace_value(
                arguments,
                TENANT_CANARY_PLACEHOLDER,
                tenant_canary,
            )
        if not isinstance(arguments, dict):
            raise EvaluationContractError("invalid_arguments")
        for attempt in range(1, case.attempts + 1):
            started = self._monotonic()
            try:
                async with asyncio.timeout(case.timeout_ms / 1_000):
                    observation = await self._target.observe(
                        EvaluationInvocation(
                            case_id=case.case_id,
                            tool=case.tool,
                            arguments=arguments,
                            context=case.context,
                            attempt=attempt,
                        )
                    )
            except asyncio.CancelledError:
                current_task = asyncio.current_task()
                if current_task is None or current_task.cancelling():
                    raise
                observation = EvaluationObservation(cancelled=True, schema_valid=True)
            except TimeoutError:
                durations.append(max(0.0, (self._monotonic() - started) * 1_000))
                return _incomplete_result(case, durations, len(observations), "timeout")
            except Exception:
                durations.append(max(0.0, (self._monotonic() - started) * 1_000))
                return _incomplete_result(case, durations, len(observations), "target_error")
            durations.append(max(0.0, (self._monotonic() - started) * 1_000))
            observations.append(observation)
        return _evaluate_case(
            case,
            tuple(observations),
            tuple(durations),
            secret_canary=secret_canary,
            tenant_canary=tenant_canary,
        )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _mcp_error_code(error: MCPError) -> str:
    data = error.error.data
    if isinstance(data, Mapping):
        mapping = cast(Mapping[object, object], data)
        code = mapping.get("code")
        if isinstance(code, str) and _IDENTIFIER.fullmatch(code) is not None:
            return code
    return "mcp_error"


def _structured_error_code(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    mapping = cast(Mapping[object, object], value)
    candidate = mapping.get("code")
    nested_error = mapping.get("error")
    if candidate is None and isinstance(nested_error, Mapping):
        nested_mapping = cast(Mapping[object, object], nested_error)
        candidate = nested_mapping.get("code")
    if isinstance(candidate, str) and _IDENTIFIER.fullmatch(candidate) is not None:
        return candidate
    return None


def _sha256(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value)).hexdigest()


def _contains_value(value: JsonValue, expected: str) -> bool:
    if value == expected:
        return True
    if isinstance(value, list):
        return any(_contains_value(item, expected) for item in value)
    if isinstance(value, dict):
        return any(_contains_value(item, expected) for item in value.values())
    return False


def _replace_value(value: JsonValue, expected: str, replacement: str) -> JsonValue:
    if value == expected:
        return replacement
    if isinstance(value, list):
        return [_replace_value(item, expected, replacement) for item in value]
    if isinstance(value, dict):
        return {key: _replace_value(item, expected, replacement) for key, item in value.items()}
    return value


def _derive_secret_canary(binding: EvaluationArtifactBinding, case_id: str) -> str:
    return _derive_canary(binding, case_id, "secret")


def _derive_canary(
    binding: EvaluationArtifactBinding,
    case_id: str,
    kind: str,
) -> str:
    seed = _canonical_json(
        {
            "binding": binding.model_dump(mode="json"),
            "case_id": case_id,
            "kind": kind,
        }
    )
    return f"tesserix-eval-{kind}-canary-" + hashlib.sha256(seed).hexdigest()


def _expectation_passed(
    expectation: EvaluationExpectation,
    observation: EvaluationObservation,
) -> bool:
    if isinstance(expectation, StructuredResultExpectation):
        return (
            not observation.cancelled
            and observation.error_code is None
            and observation.structured_result == expectation.value
        )
    if isinstance(expectation, ErrorExpectation):
        return not observation.cancelled and observation.error_code == expectation.code
    if isinstance(expectation, CancellationExpectation):
        return observation.cancelled and observation.error_code is None
    return all(
        _assertion_passed(assertion, observation.structured_result)
        for assertion in expectation.assertions
    )


def _assertion_passed(assertion: EvaluationAssertion, document: JsonValue) -> bool:
    exists, actual = _resolve_pointer(document, assertion.pointer)
    if assertion.operator is AssertionOperator.EXISTS:
        return exists
    if assertion.operator is AssertionOperator.ABSENT:
        return not exists
    if not exists:
        return False
    if assertion.operator is AssertionOperator.EQUALS:
        return actual == assertion.value
    if assertion.operator is AssertionOperator.NOT_EQUALS:
        return actual != assertion.value
    try:
        contains = assertion.value in actual  # type: ignore[operator]
    except TypeError:
        return False
    if assertion.operator is AssertionOperator.CONTAINS:
        return contains
    return not contains


def _resolve_pointer(document: JsonValue, pointer: str) -> tuple[bool, JsonValue]:
    current = document
    for raw_part in pointer.removeprefix("/").split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if part not in current:
                return False, None
            current = current[part]
            continue
        if isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                return False, None
            current = current[int(part)]
            continue
        return False, None
    return True, current


def _telemetry_passed(
    expectation: TelemetryExpectation,
    observation: EvaluationObservation,
) -> bool:
    events = set(observation.telemetry_events)
    return set(expectation.required_events) <= events and not (
        set(expectation.forbidden_events) & events
    )


def _metric_passed(
    metric: EvaluationMetric,
    case: EvaluationCase,
    observations: tuple[EvaluationObservation, ...],
    durations: tuple[float, ...],
    secret_canary: str | None,
    tenant_canary: str | None,
) -> bool:
    if metric is EvaluationMetric.SCHEMA_CONFORMANCE:
        return all(observation.schema_valid for observation in observations)
    if metric is EvaluationMetric.LATENCY:
        return all(duration <= case.latency_budget_ms for duration in durations)
    if metric is EvaluationMetric.AVAILABILITY:
        return all(observation.available for observation in observations)
    if metric is EvaluationMetric.SECRET_LEAKAGE:
        if secret_canary is None:
            return False
        return _observations_exclude_canary(observations, secret_canary)
    if metric is EvaluationMetric.TENANT_ISOLATION:
        return (
            tenant_canary is not None
            and _observations_exclude_canary(observations, tenant_canary)
            and all(
                _expectation_passed(case.expectation, observation) for observation in observations
            )
        )
    if metric is EvaluationMetric.IDEMPOTENCY:
        side_effects = [observation.side_effect_digest for observation in observations]
        outcome_digests = {
            _sha256(
                {
                    "cancelled": observation.cancelled,
                    "error_code": observation.error_code,
                    "structured_result": observation.structured_result,
                }
            )
            for observation in observations
        }
        return (
            len(observations) >= 2
            and all(side_effect is not None for side_effect in side_effects)
            and len(set(side_effects)) == 1
            and len(outcome_digests) == 1
            and all(
                _expectation_passed(case.expectation, observation)
                and _telemetry_passed(case.telemetry, observation)
                for observation in observations
            )
        )
    return all(
        _expectation_passed(case.expectation, observation)
        and _telemetry_passed(case.telemetry, observation)
        for observation in observations
    )


def _evaluate_case(
    case: EvaluationCase,
    observations: tuple[EvaluationObservation, ...],
    durations: tuple[float, ...],
    *,
    secret_canary: str | None,
    tenant_canary: str | None,
) -> EvaluationCaseResult:
    evaluated_metrics = tuple(
        (
            metric,
            _metric_passed(
                metric,
                case,
                observations,
                durations,
                secret_canary,
                tenant_canary,
            ),
        )
        for metric in case.metrics
    )
    metric_results = tuple(
        EvaluationMetricResult(
            metric=metric,
            passed=passed,
            code="passed" if passed else metric.value,
        )
        for metric, passed in evaluated_metrics
    )
    failed_blocking = {result.metric for result in metric_results if not result.passed} & set(
        case.blocking_metrics
    )
    status = EvaluationStatus.FAILED if failed_blocking else EvaluationStatus.PASSED
    if case.quarantine is not None:
        status = EvaluationStatus.QUARANTINED
        metric_results = tuple(
            result.model_copy(update={"passed": False, "code": "quarantined"})
            if result.metric in case.blocking_metrics
            else result
            for result in metric_results
        )
    failure_codes = tuple(sorted({result.code for result in metric_results if not result.passed}))
    outcome_values = [
        observation.model_dump(mode="json", exclude={"telemetry_events"})
        for observation in observations
    ]
    telemetry_values = [list(observation.telemetry_events) for observation in observations]
    return EvaluationCaseResult(
        case_id=case.case_id,
        status=status,
        attempts=len(observations),
        duration_ms=max(durations, default=0.0),
        outcome_digest=_sha256(outcome_values),
        telemetry_digest=_sha256(telemetry_values),
        metrics=metric_results,
        failure_codes=failure_codes,
        quarantine_owner=case.quarantine.owner if case.quarantine is not None else None,
        quarantine_issue=case.quarantine.issue if case.quarantine is not None else None,
    )


def _observations_exclude_canary(
    observations: tuple[EvaluationObservation, ...],
    canary: str,
) -> bool:
    try:
        scan_journey_surfaces(
            tuple(
                _canonical_json(observation.model_dump(mode="json")) for observation in observations
            ),
            canaries=(canary,),
        )
    except JourneyEvidenceError:
        return False
    return True


def _incomplete_result(
    case: EvaluationCase,
    durations: list[float],
    attempts: int,
    code: str,
) -> EvaluationCaseResult:
    return EvaluationCaseResult(
        case_id=case.case_id,
        status=EvaluationStatus.INCOMPLETE,
        attempts=attempts,
        duration_ms=max(durations, default=0.0),
        outcome_digest=_sha256({"code": code}),
        telemetry_digest=_sha256([]),
        metrics=tuple(
            EvaluationMetricResult(metric=metric, passed=False, code=code)
            for metric in case.metrics
        ),
        failure_codes=(code,),
        quarantine_owner=case.quarantine.owner if case.quarantine is not None else None,
        quarantine_issue=case.quarantine.issue if case.quarantine is not None else None,
    )


def _summarize_metrics(
    results: tuple[EvaluationCaseResult, ...],
) -> tuple[EvaluationMetricSummary, ...]:
    summaries: list[EvaluationMetricSummary] = []
    for metric in EvaluationMetric:
        matching = [
            result
            for case_result in results
            for result in case_result.metrics
            if result.metric is metric
        ]
        if not matching:
            continue
        passed = sum(result.passed for result in matching)
        summaries.append(
            EvaluationMetricSummary(
                metric=metric,
                passed_cases=passed,
                total_cases=len(matching),
                score=passed / len(matching),
            )
        )
    return tuple(summaries)


@overload
def load_evaluation_bundle(payload: str) -> EvaluationBundle: ...


@overload
def load_evaluation_bundle(payload: bytes) -> EvaluationBundle: ...


def load_evaluation_bundle(payload: object) -> EvaluationBundle:
    if isinstance(payload, str):
        encoded = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        encoded = payload
    else:
        raise EvaluationContractError("bundle_type")
    if not encoded or len(encoded) > _MAX_BUNDLE_BYTES:
        raise EvaluationContractError("bundle_bounds")
    try:
        scan_journey_surfaces((encoded,))
    except JourneyEvidenceError:
        raise EvaluationContractError("unsafe_bundle") from None
    try:
        document = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _AmbiguousJsonError):
        raise EvaluationContractError("invalid_json") from None
    _validate_json_structure(document)
    try:
        return EvaluationBundle.model_validate(document)
    except ValidationError:
        raise EvaluationContractError("invalid_bundle") from None
