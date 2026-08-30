from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "containers.yml"


def test_container_workflow_is_read_only_pinned_and_evidence_complete() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "permissions:\n  contents: read\n" in workflow
    assert "core.Dockerfile" in workflow
    assert "adk.Dockerfile" in workflow
    assert "python deploy/container/verify.py" in workflow
    assert "docker image save" in workflow
    assert (
        "anchore/syft:v1.51.1@sha256:"
        "95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c"
    ) in workflow
    assert (
        "aquasec/trivy:0.74.0@sha256:"
        "62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"
    ) in workflow
    assert "--pkg-types os" in workflow
    assert 'sbom "/artifacts/${{ matrix.variant }}.spdx.json"' in workflow
    assert "--pkg-types library" in workflow
    assert (
        "ghcr.io/yannh/kubeconform:v0.8.0@sha256:"
        "faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e"
    ) in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert "docker push" not in workflow
    assert "--push" not in workflow
    assert "packages: write" not in workflow
    assert "id-token: write" not in workflow
    assert "secrets." not in workflow
