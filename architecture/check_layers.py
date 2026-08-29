from __future__ import annotations

import ast
import json
import sys
import tomllib
from pathlib import Path
from typing import TypedDict

CORE_MODULE_PREFIXES = (
    "tesserix_mcp_runtime.application",
    "tesserix_mcp_runtime.clock",
    "tesserix_mcp_runtime.context",
    "tesserix_mcp_runtime.contracts",
    "tesserix_mcp_runtime.errors",
    "tesserix_mcp_runtime.lifecycle",
    "tesserix_mcp_runtime.policy",
    "tesserix_mcp_runtime.tool",
)
IMPORT_CONTRACT_ID = "core-does-not-depend-on-adapters"


class Violation(TypedDict):
    imported: str
    module: str
    reason: str


def module_name(package_root: Path, path: Path) -> str:
    relative = path.relative_to(package_root.parent).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def imported_modules(tree: ast.AST) -> set[str]:
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    return imported


def is_core(module: str) -> bool:
    return any(
        module == prefix or module.startswith(f"{prefix}.") for prefix in CORE_MODULE_PREFIXES
    )


def forbidden_dependencies() -> tuple[str, ...]:
    pyproject_path = Path(__file__).parents[1] / "pyproject.toml"
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    contracts = pyproject["tool"]["importlinter"]["contracts"]
    contract = next(item for item in contracts if item["id"] == IMPORT_CONTRACT_ID)
    return tuple(contract["forbidden_modules"])


def is_adapter_dependency(imported: str, forbidden: tuple[str, ...]) -> bool:
    return any(imported == prefix or imported.startswith(f"{prefix}.") for prefix in forbidden)


def check(source: Path) -> list[Violation]:
    package_root = source / "tesserix_mcp_runtime"
    forbidden = forbidden_dependencies()
    violations: list[Violation] = []
    for path in sorted(package_root.rglob("*.py")):
        module = module_name(package_root, path)
        if not is_core(module):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for imported in sorted(imported_modules(tree)):
            if is_adapter_dependency(imported, forbidden):
                violations.append(
                    {
                        "imported": imported,
                        "module": module,
                        "reason": "core cannot import adapter dependencies",
                    }
                )
    return violations


def main() -> int:
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("src")
    violations = check(source)
    print(json.dumps({"passed": not violations, "violations": violations}, sort_keys=True))
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
