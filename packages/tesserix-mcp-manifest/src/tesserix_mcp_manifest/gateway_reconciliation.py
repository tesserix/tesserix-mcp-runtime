from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self, TypeGuard, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from tesserix_mcp_manifest.errors import ManifestError
from tesserix_mcp_manifest.models import ManifestLifecycle, ManifestVisibility
from tesserix_mcp_runtime import JsonValue

_TENANT_ID_PATTERN = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_SERVER_NAMESPACE_PATTERN = (
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)
_SERVER_LEAF_PATTERN = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_SERVER_NAME_PATTERN = rf"{_SERVER_NAMESPACE_PATTERN}/{_SERVER_LEAF_PATTERN}"
_VERSION_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}"
_TENANT_ID = re.compile(rf"{_TENANT_ID_PATTERN}\Z")
_SERVER_NAME = re.compile(rf"{_SERVER_NAME_PATTERN}\Z")
_TENANT_ID_SCHEMA = rf"^{_TENANT_ID_PATTERN}$"
_SERVER_NAME_SCHEMA = rf"^{_SERVER_NAME_PATTERN}$"
_NON_DNS = re.compile(r"[^a-z0-9]+")
_DIGEST = r"^sha256:[0-9a-f]{64}$"
_DNS_LABEL = r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
_ROUTE_PATH = r"^/mcp/[a-z0-9-]+/[a-z0-9-]+$"
_SCOPE = r"^mcp:[a-z0-9-]+:[a-z0-9-]+$"
_REF = re.compile(
    rf"mcpservers/({_TENANT_ID_PATTERN})/({_SERVER_NAME_PATTERN})@{_VERSION_PATTERN}\Z"
)
_REF_SCHEMA = rf"^mcpservers/{_TENANT_ID_PATTERN}/{_SERVER_NAME_PATTERN}@{_VERSION_PATTERN}$"
_ENVIRONMENT = r"^[a-z][a-z0-9-]{0,31}$"
_MAX_GENERATION = (1 << 63) - 1
_MAX_ROUTES = 1_000
_REQUEST_ID = r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$"
_SCHEMA_VERSION: Literal["v1alpha1"] = "v1alpha1"


class _GatewayModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
    )


def _camel_alias(name: str) -> str:
    head, *tail = name.split("_")
    return head + "".join(item.title() for item in tail)


class _GatewayContractModel(_GatewayModel):
    model_config = ConfigDict(
        alias_generator=_camel_alias,
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        strict=True,
        populate_by_name=True,
    )


class GatewayApprovalState(StrEnum):
    APPROVED = "approved"
    PENDING = "pending"
    DENIED = "denied"


class GatewayTenantState(StrEnum):
    READY = "ready"
    PENDING = "pending"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"


class GatewayEligibilityReason(StrEnum):
    ELIGIBLE = "eligible"
    ACTIVATION_NOT_READY = "activation_not_ready"
    LIFECYCLE_INELIGIBLE = "lifecycle_ineligible"
    VISIBILITY_INELIGIBLE = "visibility_ineligible"
    TENANT_NOT_READY = "tenant_not_ready"
    GATEWAY_DISABLED = "gateway_disabled"
    APPROVAL_REQUIRED = "approval_required"
    WRONG_ENVIRONMENT = "wrong_environment"
    SCOPE_NOT_READY = "scope_not_ready"
    TENANT_QUOTA_EXCEEDED = "tenant_quota_exceeded"
    GLOBAL_QUOTA_EXCEEDED = "global_quota_exceeded"


class GatewayReconciliationContractError(ManifestError):
    """A candidate set cannot safely produce one authoritative Gateway snapshot."""

    def __init__(self) -> None:
        super().__init__("gateway reconciliation contract is invalid")


class GatewayRouteIdentity(_GatewayModel):
    """Collision-resistant route identity derived only from trusted Registry identity."""

    tenant_id: str = Field(min_length=1, max_length=63, pattern=_TENANT_ID_SCHEMA)
    server_name: str = Field(min_length=3, max_length=200, pattern=_SERVER_NAME_SCHEMA)
    identity_digest: str = Field(pattern=_DIGEST)
    resource_name: str = Field(min_length=1, max_length=63, pattern=_DNS_LABEL)
    route_path: str = Field(min_length=1, max_length=132, pattern=_ROUTE_PATH)
    scope: str = Field(min_length=1, max_length=131, pattern=_SCOPE)

    @model_validator(mode="after")
    def values_are_derived(self) -> Self:
        identity_digest, resource_name, route_path, scope = _derived_route_values(
            tenant_id=self.tenant_id,
            server_name=self.server_name,
        )
        if (
            self.identity_digest != identity_digest
            or self.resource_name != resource_name
            or self.route_path != route_path
            or self.scope != scope
        ):
            raise ValueError("route identity must be derived from tenant and server")
        return self


class GatewayEligibilityCandidate(_GatewayModel):
    """Registry-owned facts used to decide one exact server's route eligibility."""

    ref: str = Field(min_length=1, max_length=512, pattern=_REF_SCHEMA)
    tenant_id: str = Field(min_length=1, max_length=63, pattern=_TENANT_ID_SCHEMA)
    server_name: str = Field(min_length=3, max_length=200, pattern=_SERVER_NAME_SCHEMA)
    registry_digest: str = Field(pattern=_DIGEST)
    artifact_digest: str = Field(pattern=_DIGEST)
    activation_generation: int = Field(ge=1, le=_MAX_GENERATION)
    published_at: str = Field(min_length=20, max_length=32)
    lifecycle: ManifestLifecycle
    visibility: ManifestVisibility
    tenant_state: GatewayTenantState
    gateway_enabled: bool
    approval_state: GatewayApprovalState
    environment: str = Field(min_length=1, max_length=32, pattern=_ENVIRONMENT)
    activation_ready: bool
    scope_ready: bool
    currently_routed: bool

    @field_validator("published_at")
    @classmethod
    def validate_published_at(cls, value: str) -> str:
        return _canonical_timestamp(value, field="published_at")

    @model_validator(mode="after")
    def identity_matches_ref(self) -> Self:
        match = _REF.fullmatch(self.ref)
        if match is None or match.group(1) != self.tenant_id or match.group(2) != self.server_name:
            raise ValueError("ref must match tenant_id and server_name")
        return self


class GatewayEligibilityPolicy(_GatewayModel):
    """Bounded target-environment admission limits for one complete snapshot."""

    target_environment: str = Field(min_length=1, max_length=32, pattern=_ENVIRONMENT)
    tenant_route_limit: int = Field(default=50, ge=1, le=1_000)
    global_route_limit: int = Field(default=500, ge=1, le=1_000)
    max_candidates: int = Field(default=2_000, ge=1, le=2_000)

    @model_validator(mode="after")
    def tenant_limit_fits_global_limit(self) -> Self:
        if self.tenant_route_limit > self.global_route_limit:
            raise ValueError("tenant_route_limit must not exceed global_route_limit")
        return self


class GatewayEligibilityDecision(_GatewayModel):
    """Payload-free admission decision and derived identity for one candidate."""

    candidate: GatewayEligibilityCandidate
    reason: GatewayEligibilityReason
    route: GatewayRouteIdentity | None

    @property
    def eligible(self) -> bool:
        return self.reason is GatewayEligibilityReason.ELIGIBLE

    @model_validator(mode="after")
    def route_matches_reason(self) -> Self:
        if (self.reason is GatewayEligibilityReason.ELIGIBLE) != (self.route is not None):
            raise ValueError("eligible decisions require exactly one route identity")
        return self


class GatewayRouteRecord(_GatewayContractModel):
    """Payload-free desired route identity bound to one active immutable artifact."""

    ref: str = Field(min_length=1, max_length=512, pattern=_REF_SCHEMA)
    tenant_id: str = Field(min_length=1, max_length=63, pattern=_TENANT_ID_SCHEMA)
    server_name: str = Field(min_length=3, max_length=200, pattern=_SERVER_NAME_SCHEMA)
    registry_digest: str = Field(pattern=_DIGEST)
    artifact_digest: str = Field(pattern=_DIGEST)
    rendered_digest: str = Field(pattern=_DIGEST)
    resource_count: int = Field(ge=3, le=4)
    activation_generation: int = Field(
        ge=1,
        le=_MAX_GENERATION,
    )
    identity_digest: str = Field(pattern=_DIGEST)
    resource_name: str = Field(
        min_length=1,
        max_length=63,
        pattern=_DNS_LABEL,
    )
    route_path: str = Field(
        min_length=1,
        max_length=132,
        pattern=_ROUTE_PATH,
    )
    scope: str = Field(min_length=1, max_length=131, pattern=_SCOPE)
    policy_name: str = Field(
        min_length=1,
        max_length=63,
        pattern=_DNS_LABEL,
    )

    @classmethod
    def from_decision(
        cls,
        decision: GatewayEligibilityDecision,
        *,
        rendered_digest: str,
        resource_count: int,
    ) -> Self:
        if not decision.eligible:
            raise GatewayReconciliationContractError
        route = decision.route
        if route is None:
            raise GatewayReconciliationContractError
        candidate = decision.candidate
        return cls(
            ref=candidate.ref,
            tenant_id=candidate.tenant_id,
            server_name=candidate.server_name,
            registry_digest=candidate.registry_digest,
            artifact_digest=candidate.artifact_digest,
            rendered_digest=rendered_digest,
            resource_count=resource_count,
            activation_generation=candidate.activation_generation,
            identity_digest=route.identity_digest,
            resource_name=route.resource_name,
            route_path=route.route_path,
            scope=route.scope,
            policy_name=route.resource_name,
        )

    @model_validator(mode="after")
    def identity_is_registry_derived(self) -> Self:
        expected = derive_gateway_route_identity(
            tenant_id=self.tenant_id,
            server_name=self.server_name,
        )
        if (
            self.identity_digest != expected.identity_digest
            or self.resource_name != expected.resource_name
            or self.route_path != expected.route_path
            or self.scope != expected.scope
            or self.policy_name != expected.resource_name
        ):
            raise ValueError("route identity must be derived from tenant and server")
        match = _REF.fullmatch(self.ref)
        if match is None or match.group(1) != self.tenant_id or match.group(2) != self.server_name:
            raise ValueError("route ref must match tenant and server")
        return self


class GatewayTenantSnapshot(_GatewayContractModel):
    """Explicit per-tenant completeness and prune authority for one generation."""

    tenant_id: str = Field(min_length=1, max_length=63, pattern=_TENANT_ID_SCHEMA)
    generation: int = Field(ge=1, le=_MAX_GENERATION)
    state: GatewayTenantState
    desired_route_count: int = Field(ge=0, le=1_000)
    complete: Literal[True]
    prune_authorized: bool
    request_id: str = Field(min_length=1, max_length=256, pattern=_REQUEST_ID)

    @model_validator(mode="after")
    def nonready_tenant_has_no_routes(self) -> Self:
        if self.state is not GatewayTenantState.READY and self.desired_route_count != 0:
            raise ValueError("non-ready tenants cannot declare desired routes")
        if self.state is GatewayTenantState.PENDING and self.prune_authorized:
            raise ValueError("pending onboarding cannot authorize pruning")
        return self


class GatewayReconciliationSnapshot(_GatewayContractModel):
    """One complete, canonical desired state assembled before apply or prune."""

    schema_version: Literal["v1alpha1"]
    environment: str = Field(min_length=1, max_length=32, pattern=_ENVIRONMENT)
    generation: int = Field(ge=1, le=_MAX_GENERATION)
    observed_at: str = Field(min_length=20, max_length=32)
    complete: Literal[True]
    route_count: int = Field(ge=0, le=1_000)
    resource_count: int = Field(ge=0, le=4_000)
    tenant_count: int = Field(ge=0, le=1_000)
    routes: tuple[GatewayRouteRecord, ...] = Field(max_length=1_000)
    tenants: tuple[GatewayTenantSnapshot, ...] = Field(max_length=1_000)
    snapshot_digest: str = Field(pattern=_DIGEST)
    request_id: str = Field(min_length=1, max_length=256, pattern=_REQUEST_ID)

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: str) -> str:
        return _canonical_timestamp(value, field="observed_at")

    @model_validator(mode="after")
    def snapshot_is_complete_and_canonical(self) -> Self:
        if (
            self.route_count != len(self.routes)
            or self.resource_count != sum(route.resource_count for route in self.routes)
            or self.tenant_count != len(self.tenants)
        ):
            raise ValueError("snapshot counts must match contents")
        if self.routes != tuple(sorted(self.routes, key=lambda item: item.resource_name)):
            raise ValueError("routes must use canonical order")
        if self.tenants != tuple(sorted(self.tenants, key=lambda item: item.tenant_id)):
            raise ValueError("tenants must use canonical order")

        route_keys = (
            (
                route.ref,
                route.identity_digest,
                route.resource_name,
                route.route_path,
                route.scope,
            )
            for route in self.routes
        )
        key_columns = tuple(zip(*route_keys, strict=True)) if self.routes else ()
        if any(len(set(column)) != len(column) for column in key_columns):
            raise ValueError("snapshot route identities must be unique")

        tenant_by_id = {tenant.tenant_id: tenant for tenant in self.tenants}
        if len(tenant_by_id) != len(self.tenants):
            raise ValueError("snapshot tenants must be unique")
        route_counts = Counter(route.tenant_id for route in self.routes)
        if any(
            route.tenant_id not in tenant_by_id
            or tenant_by_id[route.tenant_id].state is not GatewayTenantState.READY
            for route in self.routes
        ):
            raise ValueError("every route requires one ready tenant projection")
        if any(
            tenant.desired_route_count != route_counts.get(tenant.tenant_id, 0)
            for tenant in self.tenants
        ):
            raise ValueError("tenant route counts must match snapshot routes")
        if self.snapshot_digest != _gateway_snapshot_digest(
            environment=self.environment,
            generation=self.generation,
            routes=self.routes,
            tenants=self.tenants,
        ):
            raise ValueError("snapshot digest must match canonical desired state")
        return self

    @classmethod
    def create(
        cls,
        *,
        environment: str,
        generation: int,
        observed_at: str,
        routes: tuple[GatewayRouteRecord, ...],
        tenants: tuple[GatewayTenantSnapshot, ...],
        request_id: str,
    ) -> Self:
        ordered_routes = tuple(sorted(routes, key=lambda item: item.resource_name))
        ordered_tenants = tuple(sorted(tenants, key=lambda item: item.tenant_id))
        return cls(
            schema_version=_SCHEMA_VERSION,
            environment=environment,
            generation=generation,
            observed_at=observed_at,
            complete=True,
            route_count=len(ordered_routes),
            resource_count=sum(route.resource_count for route in ordered_routes),
            tenant_count=len(ordered_tenants),
            routes=ordered_routes,
            tenants=ordered_tenants,
            snapshot_digest=_gateway_snapshot_digest(
                environment=environment,
                generation=generation,
                routes=ordered_routes,
                tenants=ordered_tenants,
            ),
            request_id=request_id,
        )

    @classmethod
    def from_document(cls, value: object) -> Self:
        if not _is_string_mapping(value):
            raise GatewayReconciliationContractError
        try:
            encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
            return cls.model_validate_json(encoded, strict=True)
        except (TypeError, ValueError, ValidationError):
            raise GatewayReconciliationContractError from None

    def to_document(self) -> dict[str, JsonValue]:
        document = json.loads(self.model_dump_json(by_alias=True))
        return cast(dict[str, JsonValue], document)


class GatewayReconciliationPage(_GatewayContractModel):
    """One bounded page that is unusable until the complete snapshot is assembled."""

    schema_version: Literal["v1alpha1"]
    environment: str = Field(min_length=1, max_length=32, pattern=_ENVIRONMENT)
    generation: int = Field(ge=1, le=_MAX_GENERATION)
    observed_at: str = Field(min_length=20, max_length=32)
    snapshot_digest: str = Field(pattern=_DIGEST)
    page_index: int = Field(ge=0, le=9)
    page_size: int = Field(ge=1, le=100)
    route_count: int = Field(ge=0, le=1_000)
    resource_count: int = Field(ge=0, le=4_000)
    tenant_count: int = Field(ge=0, le=1_000)
    cursor: str | None = Field(default=None, min_length=1, max_length=256, pattern=_REQUEST_ID)
    next_cursor: str | None = Field(
        default=None,
        min_length=1,
        max_length=256,
        pattern=_REQUEST_ID,
    )
    complete: bool
    routes: tuple[GatewayRouteRecord, ...] = Field(max_length=100)
    tenants: tuple[GatewayTenantSnapshot, ...] = Field(max_length=100)
    request_id: str = Field(min_length=1, max_length=256, pattern=_REQUEST_ID)

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: str) -> str:
        return _canonical_timestamp(value, field="observed_at")

    @model_validator(mode="after")
    def cursor_matches_completion(self) -> Self:
        if self.complete == (self.next_cursor is not None):
            raise ValueError("only incomplete pages carry a next cursor")
        if self.page_index == 0 and self.cursor is not None:
            raise ValueError("the first page cannot have a cursor")
        if self.page_index > 0 and self.cursor is None:
            raise ValueError("continuation pages require a cursor")
        return self

    @classmethod
    def from_document(cls, value: object) -> Self:
        if not _is_string_mapping(value):
            raise GatewayReconciliationContractError
        try:
            encoded = json.dumps(value, allow_nan=False, separators=(",", ":"))
            return cls.model_validate_json(encoded, strict=True)
        except (TypeError, ValueError, ValidationError):
            raise GatewayReconciliationContractError from None

    def to_document(self) -> dict[str, JsonValue]:
        document = json.loads(self.model_dump_json(by_alias=True))
        return cast(dict[str, JsonValue], document)


def assemble_gateway_reconciliation_pages(
    pages: tuple[GatewayReconciliationPage, ...],
) -> GatewayReconciliationSnapshot:
    """Fail closed unless every cursor-bound page forms one exact complete snapshot."""
    if not pages or len(pages) > 10:
        raise GatewayReconciliationContractError

    first = next(iter(pages))
    expected_pages = max(
        1,
        (first.route_count + first.page_size - 1) // first.page_size,
        (first.tenant_count + first.page_size - 1) // first.page_size,
    )
    if expected_pages != len(pages) or expected_pages > 10:
        raise GatewayReconciliationContractError

    routes: list[GatewayRouteRecord] = []
    tenants: list[GatewayTenantSnapshot] = []
    expected_cursor: str | None = None
    seen_cursors: set[str] = set()
    for index, page in enumerate(pages):
        if (
            page.schema_version != first.schema_version
            or page.environment != first.environment
            or page.generation != first.generation
            or page.observed_at != first.observed_at
            or page.snapshot_digest != first.snapshot_digest
            or page.page_size != first.page_size
            or page.route_count != first.route_count
            or page.resource_count != first.resource_count
            or page.tenant_count != first.tenant_count
            or page.request_id != first.request_id
            or page.page_index != index
            or page.cursor != expected_cursor
            or page.complete != (index == expected_pages - 1)
        ):
            raise GatewayReconciliationContractError

        expected_routes = max(
            0,
            min(first.page_size, first.route_count - (index * first.page_size)),
        )
        expected_tenants = max(
            0,
            min(first.page_size, first.tenant_count - (index * first.page_size)),
        )
        if len(page.routes) != expected_routes or len(page.tenants) != expected_tenants:
            raise GatewayReconciliationContractError
        if page.next_cursor is not None:
            if page.next_cursor in seen_cursors:
                raise GatewayReconciliationContractError
            seen_cursors.add(page.next_cursor)
        expected_cursor = page.next_cursor
        routes.extend(page.routes)
        tenants.extend(page.tenants)

    route_tuple = tuple(routes)
    tenant_tuple = tuple(tenants)
    if route_tuple != tuple(sorted(route_tuple, key=lambda item: item.resource_name)):
        raise GatewayReconciliationContractError
    if tenant_tuple != tuple(sorted(tenant_tuple, key=lambda item: item.tenant_id)):
        raise GatewayReconciliationContractError
    try:
        snapshot = GatewayReconciliationSnapshot.create(
            environment=first.environment,
            generation=first.generation,
            observed_at=first.observed_at,
            routes=route_tuple,
            tenants=tenant_tuple,
            request_id=first.request_id,
        )
    except (TypeError, ValueError, ValidationError):
        raise GatewayReconciliationContractError from None
    if (
        snapshot.resource_count != first.resource_count
        or snapshot.snapshot_digest != first.snapshot_digest
    ):
        raise GatewayReconciliationContractError
    return snapshot


def _canonical_timestamp(value: str, *, field: str) -> str:
    if not value.endswith("Z"):
        raise ValueError(f"{field} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{field} must be canonical UTC") from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ValueError(f"{field} must be canonical UTC")
    return value


def _is_string_mapping(value: object) -> TypeGuard[Mapping[str, object]]:
    if not isinstance(value, Mapping):
        return False
    mapping = cast(Mapping[object, object], value)
    return all(isinstance(key, str) for key in mapping)


def _gateway_snapshot_digest(
    *,
    environment: str,
    generation: int,
    routes: tuple[GatewayRouteRecord, ...],
    tenants: tuple[GatewayTenantSnapshot, ...],
) -> str:
    document = {
        "complete": True,
        "environment": environment,
        "generation": generation,
        "routeCount": len(routes),
        "resourceCount": sum(route.resource_count for route in routes),
        "routes": [route.model_dump(mode="json", by_alias=True) for route in routes],
        "schemaVersion": _SCHEMA_VERSION,
        "tenantCount": len(tenants),
        "tenants": [tenant.model_dump(mode="json", by_alias=True) for tenant in tenants],
    }
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _digest(domain: str, value: str) -> str:
    return hashlib.sha256(f"{domain}\0{value}".encode()).hexdigest()


def _slug(value: str) -> str:
    return _NON_DNS.sub("-", value.lower()).strip("-") or "mcp"


def _dns_identity(value: str, *, digest: str) -> str:
    prefix = _slug(value)[:46].rstrip("-") or "mcp"
    return f"{prefix}-{digest[:16]}"


def _derived_route_values(
    *,
    tenant_id: str,
    server_name: str,
) -> tuple[str, str, str, str]:
    identity_hash = _digest("gateway-route-v1", f"{tenant_id}\0{server_name}")
    tenant_segment = _dns_identity(
        tenant_id,
        digest=_digest("gateway-tenant-v1", tenant_id),
    )
    server_segment = _dns_identity(
        server_name,
        digest=_digest("gateway-server-v1", server_name),
    )
    return (
        f"sha256:{identity_hash}",
        _dns_identity(f"mcp-{tenant_id}-{server_name}", digest=identity_hash),
        f"/mcp/{tenant_segment}/{server_segment}",
        f"mcp:{tenant_segment}:{server_segment}",
    )


def derive_gateway_route_identity(
    *,
    tenant_id: str,
    server_name: str,
) -> GatewayRouteIdentity:
    """Derive stable Kubernetes, path, and scope identity without lossy collisions."""
    if _TENANT_ID.fullmatch(tenant_id) is None:
        raise ValueError("tenant_id must be a canonical DNS label")
    if _SERVER_NAME.fullmatch(server_name) is None:
        raise ValueError("server_name must be a canonical reverse-domain/name")

    identity_digest, resource_name, route_path, scope = _derived_route_values(
        tenant_id=tenant_id,
        server_name=server_name,
    )
    return GatewayRouteIdentity(
        tenant_id=tenant_id,
        server_name=server_name,
        identity_digest=identity_digest,
        resource_name=resource_name,
        route_path=route_path,
        scope=scope,
    )


def _base_reason(
    candidate: GatewayEligibilityCandidate,
    policy: GatewayEligibilityPolicy,
) -> GatewayEligibilityReason:
    if candidate.tenant_state is not GatewayTenantState.READY:
        return GatewayEligibilityReason.TENANT_NOT_READY
    if not candidate.activation_ready:
        return GatewayEligibilityReason.ACTIVATION_NOT_READY
    if candidate.lifecycle is not ManifestLifecycle.ACTIVE:
        return GatewayEligibilityReason.LIFECYCLE_INELIGIBLE
    if candidate.visibility is ManifestVisibility.PRIVATE:
        return GatewayEligibilityReason.VISIBILITY_INELIGIBLE
    if not candidate.gateway_enabled:
        return GatewayEligibilityReason.GATEWAY_DISABLED
    if candidate.approval_state is not GatewayApprovalState.APPROVED:
        return GatewayEligibilityReason.APPROVAL_REQUIRED
    if candidate.environment != policy.target_environment:
        return GatewayEligibilityReason.WRONG_ENVIRONMENT
    if not candidate.scope_ready:
        return GatewayEligibilityReason.SCOPE_NOT_READY
    return GatewayEligibilityReason.ELIGIBLE


def evaluate_gateway_eligibility(
    candidates: tuple[GatewayEligibilityCandidate, ...],
    *,
    policy: GatewayEligibilityPolicy,
) -> tuple[GatewayEligibilityDecision, ...]:
    """Evaluate trusted Registry facts without accepting publisher-owned routing fields."""
    if len(candidates) > policy.max_candidates:
        raise GatewayReconciliationContractError
    seen_refs: set[str] = set()
    seen_servers: set[tuple[str, str]] = set()
    base_reasons: dict[str, GatewayEligibilityReason] = {}
    for candidate in candidates:
        server_key = (candidate.tenant_id, candidate.server_name)
        if candidate.ref in seen_refs or server_key in seen_servers:
            raise GatewayReconciliationContractError
        seen_refs.add(candidate.ref)
        seen_servers.add(server_key)
        base_reasons[candidate.ref] = _base_reason(candidate, policy)

    admitted: set[str] = {
        candidate.ref
        for candidate in candidates
        if candidate.currently_routed
        and base_reasons[candidate.ref] is GatewayEligibilityReason.ELIGIBLE
    }
    if len(admitted) > _MAX_ROUTES:
        raise GatewayReconciliationContractError
    tenant_counts: dict[str, int] = {}
    for candidate in candidates:
        if candidate.ref in admitted:
            tenant_counts[candidate.tenant_id] = tenant_counts.get(candidate.tenant_id, 0) + 1
    global_count = len(admitted)
    quota_reasons: dict[str, GatewayEligibilityReason] = {}
    pending = sorted(
        (
            candidate
            for candidate in candidates
            if not candidate.currently_routed
            and base_reasons[candidate.ref] is GatewayEligibilityReason.ELIGIBLE
        ),
        key=lambda item: (
            datetime.fromisoformat(item.published_at[:-1] + "+00:00"),
            item.ref,
        ),
    )
    for candidate in pending:
        tenant_count = tenant_counts.get(candidate.tenant_id, 0)
        if tenant_count >= policy.tenant_route_limit:
            quota_reasons[candidate.ref] = GatewayEligibilityReason.TENANT_QUOTA_EXCEEDED
            continue
        if global_count >= policy.global_route_limit:
            quota_reasons[candidate.ref] = GatewayEligibilityReason.GLOBAL_QUOTA_EXCEEDED
            continue
        admitted.add(candidate.ref)
        tenant_counts[candidate.tenant_id] = tenant_count + 1
        global_count += 1

    seen_routes: set[tuple[str, str, str]] = set()
    decisions: list[GatewayEligibilityDecision] = []
    for candidate in candidates:
        reason = base_reasons[candidate.ref]
        if reason is GatewayEligibilityReason.ELIGIBLE and candidate.ref not in admitted:
            reason = quota_reasons[candidate.ref]
        route = (
            derive_gateway_route_identity(
                tenant_id=candidate.tenant_id,
                server_name=candidate.server_name,
            )
            if reason is GatewayEligibilityReason.ELIGIBLE
            else None
        )
        if route is not None:
            route_key = (route.resource_name, route.route_path, route.scope)
            if route_key in seen_routes:
                raise GatewayReconciliationContractError
            seen_routes.add(route_key)
        decisions.append(
            GatewayEligibilityDecision(
                candidate=candidate,
                reason=reason,
                route=route,
            )
        )
    return tuple(decisions)


__all__ = [
    "GatewayApprovalState",
    "GatewayEligibilityCandidate",
    "GatewayEligibilityDecision",
    "GatewayEligibilityPolicy",
    "GatewayEligibilityReason",
    "GatewayReconciliationContractError",
    "GatewayReconciliationPage",
    "GatewayReconciliationSnapshot",
    "GatewayRouteIdentity",
    "GatewayRouteRecord",
    "GatewayTenantSnapshot",
    "GatewayTenantState",
    "assemble_gateway_reconciliation_pages",
    "derive_gateway_route_identity",
    "evaluate_gateway_eligibility",
]
