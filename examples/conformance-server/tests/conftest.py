from __future__ import annotations

import pytest
from server import ExternalServerTarget


@pytest.fixture
def conformance_target() -> ExternalServerTarget:
    return ExternalServerTarget()
