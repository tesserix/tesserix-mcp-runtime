from __future__ import annotations

import pytest

from tesserix_mcp_runtime.egress import (
    DeclaredEgressPolicy,
    EgressDestination,
    EgressManifest,
    EgressPolicy,
    EgressPolicyViolation,
)


def test_destination_canonicalizes_an_exact_https_authority() -> None:
    destination = EgressDestination(host="API.Example.Test.", port=8443)

    assert destination.host == "api.example.test"
    assert destination.port == 8443
    assert destination.authority == "api.example.test:8443"


@pytest.mark.parametrize(
    "host",
    [
        "",
        "https://example.test",
        "user@example.test",
        "example.test/path",
        "example%2etest",
        "2130706433",
        "0177.0.0.1",
        "0x7f.0.0.1",
        "bad_label.example",
        "-bad.example",
    ],
)
def test_destination_rejects_urls_credentials_encoded_and_alternate_hosts(host: str) -> None:
    with pytest.raises(ValueError, match="host"):
        EgressDestination(host=host)


@pytest.mark.parametrize("port", [0, 65_536, -1, True])
def test_destination_rejects_invalid_ports(port: int) -> None:
    with pytest.raises(ValueError, match="port"):
        EgressDestination(host="api.example.test", port=port)


def test_policy_allows_only_exact_declared_hosts_and_ports() -> None:
    policy = DeclaredEgressPolicy(
        manifest=EgressManifest(
            destinations=(EgressDestination(host="api.example.test", port=443),)
        )
    )

    policy.authorize_destination(EgressDestination(host="api.example.test", port=443))
    with pytest.raises(EgressPolicyViolation):
        policy.authorize_destination(EgressDestination(host="api.example.test", port=8443))
    with pytest.raises(EgressPolicyViolation):
        policy.authorize_destination(EgressDestination(host="other.example.test", port=443))


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.2.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:0001::",
    ],
)
def test_policy_blocks_non_public_and_embedded_internal_addresses(address: str) -> None:
    destination = EgressDestination(host="api.example.test")
    policy = DeclaredEgressPolicy(manifest=EgressManifest(destinations=(destination,)))

    with pytest.raises(EgressPolicyViolation) as captured:
        policy.authorize_connection(destination, (address,))

    assert address not in str(captured.value)
    assert destination.host not in str(captured.value)


def test_policy_rejects_a_mixed_public_private_dns_answer() -> None:
    destination = EgressDestination(host="api.example.test")
    policy = DeclaredEgressPolicy(manifest=EgressManifest(destinations=(destination,)))

    with pytest.raises(EgressPolicyViolation):
        policy.authorize_connection(destination, ("93.184.216.34", "127.0.0.1"))


def test_policy_accepts_public_addresses_for_a_declared_destination() -> None:
    destination = EgressDestination(host="api.example.test")
    policy = DeclaredEgressPolicy(manifest=EgressManifest(destinations=(destination,)))

    policy.authorize_connection(destination, ("93.184.216.34", "2606:2800:220:1::34"))


def test_internal_networks_require_an_explicit_narrow_policy() -> None:
    destination = EgressDestination(host="internal.example.test", port=8443)
    policy = DeclaredEgressPolicy(
        manifest=EgressManifest(destinations=(destination,)),
        permitted_internal_networks=("10.24.0.0/24",),
    )

    policy.authorize_connection(destination, ("10.24.0.7",))
    with pytest.raises(EgressPolicyViolation):
        policy.authorize_connection(destination, ("10.25.0.7",))


@pytest.mark.parametrize(
    "network",
    ["0.0.0.0/0", "93.184.216.0/24", "224.0.0.0/4", "::/0", "2001:4860::/32"],
)
def test_internal_policy_rejects_broad_public_or_multicast_networks(network: str) -> None:
    with pytest.raises(ValueError, match="internal networks"):
        DeclaredEgressPolicy(
            manifest=EgressManifest(
                destinations=(EgressDestination(host="internal.example.test"),)
            ),
            permitted_internal_networks=(network,),
        )


def test_policy_rejects_empty_oversized_and_invalid_dns_answers() -> None:
    destination = EgressDestination(host="api.example.test")
    policy = DeclaredEgressPolicy(manifest=EgressManifest(destinations=(destination,)))

    for addresses in ((), tuple("93.184.216.34" for _ in range(17)), ("not-an-ip",)):
        with pytest.raises(EgressPolicyViolation):
            policy.authorize_connection(destination, addresses)


def test_egress_policy_is_independently_replaceable() -> None:
    policy: EgressPolicy = DeclaredEgressPolicy(manifest=EgressManifest())

    assert isinstance(policy, EgressPolicy)


def test_policy_violation_has_no_destination_or_dependency_detail() -> None:
    violation = EgressPolicyViolation()

    assert str(violation) == "forbidden"
    assert "host" not in repr(violation).lower()


def test_egress_manifest_has_a_stable_https_only_document() -> None:
    manifest = EgressManifest(destinations=(EgressDestination(host="api.example.test", port=8443),))

    assert manifest.to_dict() == {
        "destinations": [{"scheme": "https", "host": "api.example.test", "port": 8443}]
    }


def test_egress_manifest_canonicalizes_destination_order() -> None:
    manifest = EgressManifest(
        destinations=(
            EgressDestination(host="z.example.test", port=443),
            EgressDestination(host="a.example.test", port=8443),
        )
    )

    assert tuple(item.host for item in manifest.destinations) == (
        "a.example.test",
        "z.example.test",
    )


def test_egress_manifest_rejects_duplicates_and_hard_maximum_bypass() -> None:
    destination = EgressDestination(host="api.example.test")

    with pytest.raises(ValueError, match="egress manifest"):
        EgressManifest(destinations=(destination, destination))
    with pytest.raises(ValueError, match="egress manifest"):
        EgressManifest(
            destinations=tuple(
                EgressDestination(host=f"host-{index}.example.test") for index in range(257)
            )
        )
