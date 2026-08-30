from __future__ import annotations

import json
from pathlib import Path

from tesserix_mcp_manifest import (
    DiscoveryEvaluationDataset,
    evaluate_discovery,
    lint_semantic_manifest,
    load_authoring_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
GOLDENS = ROOT / "packages" / "tesserix-mcp-manifest" / "tests" / "goldens"
DATASET = ROOT / "packages" / "tesserix-mcp-manifest" / "evaluation" / "semantic-discovery.json"


class SemanticDiscoveryCheckError(RuntimeError):
    pass


def check() -> dict[str, object]:
    manifest_count = 0
    for authoring_path in sorted(GOLDENS.glob("*/authoring.json")):
        manifest = load_authoring_manifest(authoring_path.read_bytes())
        findings = lint_semantic_manifest(manifest)
        if findings:
            codes = ",".join(finding.code.value for finding in findings)
            raise SemanticDiscoveryCheckError(f"{authoring_path.parent.name}: {codes}")
        manifest_count += 1
    if manifest_count == 0:
        raise SemanticDiscoveryCheckError("no semantic manifest examples found")

    dataset = DiscoveryEvaluationDataset.model_validate_json(DATASET.read_bytes())
    metrics = evaluate_discovery(
        dataset.cases,
        dataset.recorded_results,
        k=dataset.k,
    )
    if (
        metrics.precision_at_k < 0.8
        or metrics.no_match_accuracy < 1.0
        or metrics.incompatible_recommendations
        or metrics.deprecated_recommendations
        or metrics.forbidden_exposure_count
    ):
        raise SemanticDiscoveryCheckError("semantic discovery evaluation threshold failed")
    return {
        "dataset": dataset.name,
        "manifests_linted": manifest_count,
        "metrics": metrics.model_dump(mode="json"),
    }


def main() -> int:
    print(json.dumps(check(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
