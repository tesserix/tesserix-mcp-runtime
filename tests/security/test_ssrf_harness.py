from __future__ import annotations

from security.ssrf_harness import run_ssrf_harness


async def test_isolated_ssrf_harness_proves_every_required_network_attack(
    socket_enabled: None,
) -> None:
    assert socket_enabled is None
    report = await run_ssrf_harness()

    assert report == {
        "cases": [
            "egress.alternate_port",
            "egress.dns_rebinding",
            "egress.encoded_ip",
            "egress.ipv6",
            "egress.loopback",
            "egress.metadata",
            "egress.private_range",
            "egress.redirect",
        ],
        "connections": 5,
        "passed": True,
    }
