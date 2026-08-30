from __future__ import annotations

import json

import pytest
from compatibility.run_inspector import validate_inspector_tool_error


def test_inspector_tool_error_requires_its_exact_cli_exit_and_envelopes() -> None:
    stdout = json.dumps(
        {
            "result": {
                "content": [{"type": "text", "text": "payload-not-retained"}],
                "isError": True,
            }
        }
    )
    stderr = json.dumps(
        {
            "error": {
                "code": "tool_is_error",
                "message": "Tool returned isError:true.",
            }
        }
    )

    validate_inspector_tool_error(5, stdout, stderr)

    with pytest.raises(RuntimeError, match="tool-error contract"):
        validate_inspector_tool_error(0, stdout, stderr)
