from __future__ import annotations

from collections.abc import Callable
from typing import Never

import pytest

from tesserix_mcp_testkit.contract import (
    CONFORMANCE_CASES,
    ConformanceCase,
    ConformanceNotApplicable,
    ConformanceTarget,
    run_conformance_case,
)


@pytest.fixture(params=CONFORMANCE_CASES, ids=lambda case: case.id)
def conformance_case(request: pytest.FixtureRequest) -> ConformanceCase:
    value = request.param
    if not isinstance(value, ConformanceCase):
        raise TypeError("conformance case fixture received an invalid case")
    return value


@pytest.fixture
def conformance_target() -> Never:
    pytest.fail(
        "define a conformance_target fixture that implements ConformanceTarget; "
        "see the tesserix-mcp-testkit external example"
    )


@pytest.fixture
def assert_mcp_conformance() -> Callable[[ConformanceTarget, ConformanceCase], None]:
    def run(target: ConformanceTarget, case: ConformanceCase) -> None:
        try:
            run_conformance_case(target, case)
        except ConformanceNotApplicable as error:
            pytest.skip(str(error))

    return run


__all__ = ["assert_mcp_conformance", "conformance_case", "conformance_target"]
