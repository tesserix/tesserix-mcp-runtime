from __future__ import annotations

import subprocess
import sys
from importlib.metadata import version

import tesserix_mcp_runtime


def test_version_command_reports_installed_distribution_metadata() -> None:
    expected = version("tesserix-mcp-runtime")

    completed = subprocess.run(
        [sys.executable, "-m", "tesserix_mcp_runtime", "--version"],
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0
    assert completed.stdout == f"tesserix-mcp-runtime {expected}\n"
    assert completed.stderr == ""
    assert tesserix_mcp_runtime.__version__ == expected
