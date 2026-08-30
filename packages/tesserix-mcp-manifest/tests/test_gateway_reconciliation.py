from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, cast

import pytest
from tesserix_mcp_manifest import (
    GatewayApprovalState,
    GatewayEligibilityCandidate,
    GatewayEligibilityPolicy,
    GatewayEligibilityReason,
    GatewayReconciliationContractError,
    GatewayReconciliationPage,
    GatewayReconciliationSnapshot,
    GatewayRouteIdentity,
    GatewayRouteRecord,
    GatewayTenantSnapshot,
    GatewayTenantState,
    ManifestLifecycle,
    ManifestVisibility,
    assemble_gateway_reconciliation_pages,
    derive_gateway_route_identity,
    evaluate_gateway_eligibility,
)

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_REGISTRY_DIGEST = "sha256:" + ("a" * 64)
_ARTIFACT_DIGEST = "sha256:" + ("b" * 64)
_RENDERED_DIGEST = "sha256:" + ("c" * 64)


def candidate(**overrides: object) -> GatewayEligibilityCandidate:
    values: dict[str, object] = {
        "ref": "mcpservers/tenant-blue/io.example/orders@1.2.3",
        "tenant_id": "tenant-blue",
        "server_name": "io.example/orders",
        "registry_digest": _REGISTRY_DIGEST,
        "artifact_digest": _ARTIFACT_DIGEST,
        "activation_generation": 7,
        "published_at": "2026-08-30T12:00:00Z",
        "lifecycle": ManifestLifecycle.ACTIVE,
        "visibility": ManifestVisibility.INTERNAL,
        "tenant_state": GatewayTenantState.READY,
        "gateway_enabled": True,
        "approval_state": GatewayApprovalState.APPROVED,
        "environment": "production",
        "activation_ready": True,
        "scope_ready": True,
        "currently_routed": False,
    }
    values.update(overrides)
    return GatewayEligibilityCandidate.model_validate(values)


def named_candidate(
    *,
    tenant_id: str,
    server: str,
    minute: int,
    currently_routed: bool = False,
) -> GatewayEligibilityCandidate:
    return candidate(
        ref=f"mcpservers/{tenant_id}/io.example/{server}@1.2.3",
        tenant_id=tenant_id,
        server_name=f"io.example/{server}",
        published_at=f"2026-08-30T12:{minute:02d}:00Z",
        currently_routed=currently_routed,
    )


def test_route_identity_is_exact_deterministic_and_collision_safe() -> None:
    first = derive_gateway_route_identity(
        tenant_id="tenant-blue",
        server_name="io.example/foo.bar",
    )
    replay = derive_gateway_route_identity(
        tenant_id="tenant-blue",
        server_name="io.example/foo.bar",
    )
    other_tenant = derive_gateway_route_identity(
        tenant_id="tenant-green",
        server_name="io.example/foo.bar",
    )
    legacy_slug_collision = derive_gateway_route_identity(
        tenant_id="tenant-blue",
        server_name="io-example/foo-bar",
    )

    assert first == replay
    assert len(first.resource_name) <= 63
    assert _DNS_LABEL.fullmatch(first.resource_name)
    assert first.route_path.startswith("/mcp/")
    assert ".." not in first.route_path
    assert "%" not in first.route_path
    assert "?" not in first.route_path
    assert first.scope.startswith("mcp:")
    assert first.identity_digest.startswith("sha256:")
    assert len(first.identity_digest) == 71
    assert len({first.resource_name, other_tenant.resource_name}) == 2
    assert len({first.route_path, other_tenant.route_path}) == 2
    assert len({first.scope, other_tenant.scope}) == 2
    assert first.resource_name != legacy_slug_collision.resource_name
    assert first.route_path != legacy_slug_collision.route_path


def test_route_identity_cannot_be_forged_through_the_public_model() -> None:
    with pytest.raises(ValueError):
        GatewayRouteIdentity(
            tenant_id="tenant-blue",
            server_name="io.example/orders",
            identity_digest=_REGISTRY_DIGEST,
            resource_name="forged-resource",
            route_path="/mcp/forged/route",
            scope="mcp:forged:route",
        )


@pytest.mark.parametrize("server_name", ("../orders", "io.example/.."))
def test_route_identity_rejects_path_traversal_names(server_name: str) -> None:
    with pytest.raises(ValueError, match="server_name"):
        derive_gateway_route_identity(
            tenant_id="tenant-blue",
            server_name=server_name,
        )


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"activation_ready": False}, GatewayEligibilityReason.ACTIVATION_NOT_READY),
        (
            {"lifecycle": ManifestLifecycle.DEPRECATED},
            GatewayEligibilityReason.LIFECYCLE_INELIGIBLE,
        ),
        (
            {"visibility": ManifestVisibility.PRIVATE},
            GatewayEligibilityReason.VISIBILITY_INELIGIBLE,
        ),
        (
            {"tenant_state": GatewayTenantState.PENDING},
            GatewayEligibilityReason.TENANT_NOT_READY,
        ),
        ({"gateway_enabled": False}, GatewayEligibilityReason.GATEWAY_DISABLED),
        (
            {"approval_state": GatewayApprovalState.PENDING},
            GatewayEligibilityReason.APPROVAL_REQUIRED,
        ),
        ({"environment": "staging"}, GatewayEligibilityReason.WRONG_ENVIRONMENT),
        ({"scope_ready": False}, GatewayEligibilityReason.SCOPE_NOT_READY),
    ],
    ids=[
        "activation",
        "lifecycle",
        "private",
        "tenant",
        "disabled",
        "approval",
        "environment",
        "scope",
    ],
)
def test_eligibility_is_default_deny_at_every_authoritative_boundary(
    overrides: dict[str, object],
    reason: GatewayEligibilityReason,
) -> None:
    policy = GatewayEligibilityPolicy(target_environment="production")

    eligible = evaluate_gateway_eligibility((candidate(),), policy=policy)[0]
    rejected = evaluate_gateway_eligibility(
        (candidate(**overrides),),
        policy=policy,
    )[0]

    assert eligible.eligible is True
    assert eligible.reason is GatewayEligibilityReason.ELIGIBLE
    assert eligible.route is not None
    assert rejected.eligible is False
    assert rejected.reason is reason
    assert rejected.route is None


def test_quota_admission_preserves_existing_routes_and_is_order_stable() -> None:
    policy = GatewayEligibilityPolicy(
        target_environment="production",
        tenant_route_limit=2,
        global_route_limit=2,
    )
    existing = tuple(
        named_candidate(
            tenant_id="tenant-blue",
            server=f"existing-{index}",
            minute=index,
            currently_routed=True,
        )
        for index in range(3)
    )
    new_for_over_quota_tenant = named_candidate(
        tenant_id="tenant-blue",
        server="new",
        minute=3,
    )

    retained = evaluate_gateway_eligibility(
        (*existing, new_for_over_quota_tenant),
        policy=policy,
    )

    assert all(decision.eligible for decision in retained[:3])
    assert retained[3].reason is GatewayEligibilityReason.TENANT_QUOTA_EXCEEDED

    globally_competing = (
        named_candidate(tenant_id="tenant-blue", server="one", minute=1),
        named_candidate(tenant_id="tenant-green", server="one", minute=2),
        named_candidate(tenant_id="tenant-blue", server="two", minute=3),
        named_candidate(tenant_id="tenant-green", server="two", minute=4),
    )
    forward = evaluate_gateway_eligibility(globally_competing, policy=policy)
    reverse = evaluate_gateway_eligibility(
        tuple(reversed(globally_competing)),
        policy=policy,
    )
    forward_reasons = {item.candidate.ref: item.reason for item in forward}
    reverse_reasons = {item.candidate.ref: item.reason for item in reverse}

    assert forward_reasons == reverse_reasons
    assert [item.reason for item in forward] == [
        GatewayEligibilityReason.ELIGIBLE,
        GatewayEligibilityReason.ELIGIBLE,
        GatewayEligibilityReason.GLOBAL_QUOTA_EXCEEDED,
        GatewayEligibilityReason.GLOBAL_QUOTA_EXCEEDED,
    ]


def test_hard_route_ceiling_rejects_oversized_existing_state() -> None:
    existing = tuple(
        candidate(
            ref=f"mcpservers/tenant-blue/io.example/existing-{index}@1.2.3",
            server_name=f"io.example/existing-{index}",
            currently_routed=True,
        )
        for index in range(1_001)
    )

    with pytest.raises(GatewayReconciliationContractError):
        evaluate_gateway_eligibility(
            existing,
            policy=GatewayEligibilityPolicy(target_environment="production"),
        )


def test_target_scale_assembles_five_complete_pages() -> None:
    candidates = tuple(
        candidate(
            ref=f"mcpservers/tenant-{tenant:02d}/io.example/server-{server:02d}@1.2.3",
            tenant_id=f"tenant-{tenant:02d}",
            server_name=f"io.example/server-{server:02d}",
        )
        for tenant in range(10)
        for server in range(50)
    )
    decisions = evaluate_gateway_eligibility(
        candidates,
        policy=GatewayEligibilityPolicy(target_environment="production"),
    )
    routes = tuple(
        sorted(
            (
                GatewayRouteRecord.from_decision(
                    decision,
                    rendered_digest=_RENDERED_DIGEST,
                    resource_count=4,
                )
                for decision in decisions
            ),
            key=lambda item: item.resource_name,
        )
    )
    tenants = tuple(
        GatewayTenantSnapshot(
            tenant_id=f"tenant-{tenant:02d}",
            generation=1,
            state=GatewayTenantState.READY,
            desired_route_count=50,
            complete=True,
            prune_authorized=True,
            request_id=f"tenant-{tenant:02d}-export-1",
        )
        for tenant in range(10)
    )
    snapshot = GatewayReconciliationSnapshot.create(
        environment="production",
        generation=1,
        observed_at="2026-08-30T12:05:00Z",
        routes=routes,
        tenants=tenants,
        request_id="gateway-export-500",
    )
    pages = tuple(
        GatewayReconciliationPage(
            schema_version="v1alpha1",
            environment=snapshot.environment,
            generation=snapshot.generation,
            observed_at=snapshot.observed_at,
            snapshot_digest=snapshot.snapshot_digest,
            page_index=index,
            page_size=100,
            route_count=snapshot.route_count,
            resource_count=snapshot.resource_count,
            tenant_count=snapshot.tenant_count,
            cursor=None if index == 0 else f"gateway-export-500-page-{index}",
            next_cursor=(None if index == 4 else f"gateway-export-500-page-{index + 1}"),
            complete=index == 4,
            routes=routes[index * 100 : (index + 1) * 100],
            tenants=tenants[index * 100 : (index + 1) * 100],
            request_id=snapshot.request_id,
        )
        for index in range(5)
    )

    assert all(decision.eligible for decision in decisions)
    assert snapshot.route_count == 500
    assert snapshot.resource_count == 2_000
    assert len(pages) == 5
    assert assemble_gateway_reconciliation_pages(pages) == snapshot


def test_complete_snapshot_is_canonical_digest_bound_and_tenant_scoped() -> None:
    decisions = evaluate_gateway_eligibility(
        (
            named_candidate(tenant_id="tenant-green", server="orders", minute=2),
            named_candidate(tenant_id="tenant-blue", server="orders", minute=1),
        ),
        policy=GatewayEligibilityPolicy(target_environment="production"),
    )
    routes = tuple(
        GatewayRouteRecord.from_decision(
            item,
            rendered_digest=_RENDERED_DIGEST,
            resource_count=3,
        )
        for item in decisions
    )
    tenants = (
        GatewayTenantSnapshot(
            tenant_id="tenant-green",
            generation=4,
            state=GatewayTenantState.READY,
            desired_route_count=1,
            complete=True,
            prune_authorized=True,
            request_id="tenant-green-export-4",
        ),
        GatewayTenantSnapshot(
            tenant_id="tenant-blue",
            generation=9,
            state=GatewayTenantState.READY,
            desired_route_count=1,
            complete=True,
            prune_authorized=True,
            request_id="tenant-blue-export-9",
        ),
    )

    snapshot = GatewayReconciliationSnapshot.create(
        environment="production",
        generation=12,
        observed_at="2026-08-30T12:05:00Z",
        routes=tuple(reversed(routes)),
        tenants=tenants,
        request_id="gateway-export-12",
    )
    replay = GatewayReconciliationSnapshot.create(
        environment="production",
        generation=12,
        observed_at="2026-08-30T12:06:00Z",
        routes=routes,
        tenants=tuple(reversed(tenants)),
        request_id="gateway-export-replay",
    )
    document = cast(dict[str, Any], snapshot.to_document())

    assert snapshot.complete is True
    assert snapshot.route_count == 2
    assert snapshot.resource_count == 6
    assert snapshot.tenant_count == 2
    assert snapshot.snapshot_digest == replay.snapshot_digest
    assert [item.tenant_id for item in snapshot.tenants] == ["tenant-blue", "tenant-green"]
    assert [item.resource_name for item in snapshot.routes] == sorted(
        item.resource_name for item in snapshot.routes
    )
    assert document["schemaVersion"] == "v1alpha1"
    assert document["snapshotDigest"] == snapshot.snapshot_digest
    assert document["resourceCount"] == 6
    assert document["routes"][0]["renderedDigest"] == _RENDERED_DIGEST
    assert document["routes"][0]["resourceCount"] == 3
    assert "candidate" not in document
    assert GatewayReconciliationSnapshot.from_document(document) == snapshot

    malformed_documents: list[dict[str, Any]] = []
    incomplete = deepcopy(document)
    incomplete["complete"] = False
    malformed_documents.append(incomplete)
    unsafe_path = deepcopy(document)
    unsafe_path["routes"][0]["routePath"] = "/mcp/unsafe"
    malformed_documents.append(unsafe_path)
    moved_digest = deepcopy(document)
    moved_digest["routes"][0]["registryDigest"] = _ARTIFACT_DIGEST
    malformed_documents.append(moved_digest)
    missing_tenant = deepcopy(document)
    missing_tenant["tenants"] = missing_tenant["tenants"][:1]
    missing_tenant["tenantCount"] = 1
    malformed_documents.append(missing_tenant)

    for malformed in malformed_documents:
        with pytest.raises(GatewayReconciliationContractError) as invalid:
            GatewayReconciliationSnapshot.from_document(malformed)
        assert str(invalid.value) == "gateway reconciliation contract is invalid"
        assert "tenant-blue" not in str(invalid.value)


def test_page_assembly_rejects_stopped_mixed_and_cursor_broken_exports() -> None:
    decisions = evaluate_gateway_eligibility(
        (
            named_candidate(tenant_id="tenant-blue", server="orders", minute=1),
            named_candidate(tenant_id="tenant-green", server="orders", minute=2),
        ),
        policy=GatewayEligibilityPolicy(target_environment="production"),
    )
    routes = tuple(
        sorted(
            (
                GatewayRouteRecord.from_decision(
                    item,
                    rendered_digest=_RENDERED_DIGEST,
                    resource_count=3,
                )
                for item in decisions
            ),
            key=lambda item: item.resource_name,
        )
    )
    tenants = (
        GatewayTenantSnapshot(
            tenant_id="tenant-blue",
            generation=9,
            state=GatewayTenantState.READY,
            desired_route_count=1,
            complete=True,
            prune_authorized=True,
            request_id="tenant-blue-export-9",
        ),
        GatewayTenantSnapshot(
            tenant_id="tenant-green",
            generation=4,
            state=GatewayTenantState.READY,
            desired_route_count=1,
            complete=True,
            prune_authorized=True,
            request_id="tenant-green-export-4",
        ),
    )
    snapshot = GatewayReconciliationSnapshot.create(
        environment="production",
        generation=12,
        observed_at="2026-08-30T12:05:00Z",
        routes=routes,
        tenants=tenants,
        request_id="gateway-export-12",
    )
    first = GatewayReconciliationPage(
        schema_version="v1alpha1",
        environment=snapshot.environment,
        generation=snapshot.generation,
        observed_at=snapshot.observed_at,
        snapshot_digest=snapshot.snapshot_digest,
        page_index=0,
        page_size=1,
        route_count=2,
        resource_count=6,
        tenant_count=2,
        cursor=None,
        next_cursor="gateway-export-12-page-1",
        complete=False,
        routes=routes[:1],
        tenants=tenants[:1],
        request_id=snapshot.request_id,
    )
    final = GatewayReconciliationPage(
        schema_version="v1alpha1",
        environment=snapshot.environment,
        generation=snapshot.generation,
        observed_at=snapshot.observed_at,
        snapshot_digest=snapshot.snapshot_digest,
        page_index=1,
        page_size=1,
        route_count=2,
        resource_count=6,
        tenant_count=2,
        cursor="gateway-export-12-page-1",
        next_cursor=None,
        complete=True,
        routes=routes[1:],
        tenants=tenants[1:],
        request_id=snapshot.request_id,
    )

    assert assemble_gateway_reconciliation_pages((first, final)) == snapshot

    broken_exports = (
        (first,),
        (first, final.model_copy(update={"cursor": "wrong-cursor"})),
        (first, final.model_copy(update={"generation": 13})),
        (first.model_copy(update={"complete": True, "next_cursor": None}), final),
        (first, final.model_copy(update={"routes": routes[:1]})),
        (
            first.model_copy(update={"resource_count": 7}),
            final.model_copy(update={"resource_count": 7}),
        ),
    )
    for pages in broken_exports:
        with pytest.raises(GatewayReconciliationContractError):
            assemble_gateway_reconciliation_pages(pages)
