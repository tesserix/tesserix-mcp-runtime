from __future__ import annotations

import pytest

pytest_plugins = ("pytester",)


def test_external_target_runs_required_cases_and_skips_optional_cases(
    pytester: pytest.Pytester,
) -> None:
    pytester.makeconftest(
        """
import pytest
from tesserix_mcp_testkit import (
    CONFORMANCE_TOOL_NAME,
    REQUIRED_CAPABILITIES,
    ConformanceObservation,
)

class ExternalTarget:
    capabilities = REQUIRED_CAPABILITIES

    async def observe(self, case):
        return ConformanceObservation(
            error_code=case.expected_error,
            tool_names=(CONFORMANCE_TOOL_NAME,) if case.required_tool else (),
            value=case.expected_value if case.check_value else None,
        )

@pytest.fixture
def conformance_target():
    return ExternalTarget()
"""
    )
    (pytester.path / "test_external_contract.py").write_text(
        """
def test_contract(conformance_target, conformance_case, assert_mcp_conformance):
    assert_mcp_conformance(conformance_target, conformance_case)
""",
        encoding="utf-8",
    )

    result = pytester.runpytest("--disable-socket", "--allow-unix-socket", "-q")

    result.assert_outcomes(passed=2, skipped=22)


def test_missing_external_target_fails_with_actionable_configuration(
    pytester: pytest.Pytester,
) -> None:
    (pytester.path / "test_missing_target_contract.py").write_text(
        """
def test_contract(conformance_target, conformance_case, assert_mcp_conformance):
    assert_mcp_conformance(conformance_target, conformance_case)
""",
        encoding="utf-8",
    )

    result = pytester.runpytest("-q", "-k", "discovery.tools")

    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(
        ["*define a conformance_target fixture that implements ConformanceTarget*"]
    )
