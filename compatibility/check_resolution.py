from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).parents[1]


def resolves(sdk: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="tesserix-mcp-resolution-") as directory:
        consumer = Path(directory)
        dependency = f"tesserix-mcp-runtime @ {ROOT.as_uri()}"
        document = "\n".join(
            [
                "[project]",
                'name = "compatibility-consumer"',
                'version = "0.0.0"',
                'requires-python = ">=3.12,<3.15"',
                f"dependencies = [{json.dumps(dependency)}, {json.dumps(f'mcp=={sdk}')}]",
            ]
        )
        (consumer / "pyproject.toml").write_text(document, encoding="utf-8")
        completed = subprocess.run(
            ["uv", "lock", "--directory", str(consumer), "--offline"],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        return completed.returncode == 0


def main() -> int:
    report = {
        "mcp_1_29_1_rejected": not resolves("1.29.1"),
        "mcp_2_1_1_resolved": resolves("2.1.1"),
        "mcp_3_0_0_rejected": not resolves("3.0.0"),
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if all(report.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
