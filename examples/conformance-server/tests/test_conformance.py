from collections.abc import Callable

from tesserix_mcp_testkit import ConformanceCase, ConformanceTarget


def test_contract(
    conformance_target: ConformanceTarget,
    conformance_case: ConformanceCase,
    assert_mcp_conformance: Callable[[ConformanceTarget, ConformanceCase], None],
) -> None:
    assert_mcp_conformance(conformance_target, conformance_case)
