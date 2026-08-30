from __future__ import annotations

import argparse
import importlib
import sys
from difflib import unified_diff
from pathlib import Path
from types import ModuleType

DEFAULT_PACKAGE = "tesserix_mcp_runtime"


def exported_owner(module: ModuleType, name: str) -> str:
    value = getattr(module, name)
    owner_module = getattr(value, "__module__", None)
    owner_name = getattr(value, "__qualname__", None) or getattr(value, "__name__", None)
    if not owner_module or not owner_name:
        owner_module = module.__name__
        owner_name = name
    return f"{name} = {owner_module}.{owner_name}"


def current_snapshot(module: ModuleType) -> str:
    exports = sorted(module.__all__)
    return "".join(f"{exported_owner(module, name)}\n" for name in exports)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "snapshot",
        nargs="?",
        type=Path,
        default=Path(__file__).with_name("public-api.txt"),
    )
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    arguments = parser.parse_args()
    snapshot_path = arguments.snapshot
    module = importlib.import_module(arguments.package)
    expected = snapshot_path.read_text(encoding="utf-8")
    actual = current_snapshot(module)
    if expected == actual:
        print(f"Public API snapshot matches ({len(module.__all__)} exports).")
        return 0

    sys.stderr.writelines(
        unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=str(snapshot_path),
            tofile=f"current {arguments.package} exports",
        )
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
