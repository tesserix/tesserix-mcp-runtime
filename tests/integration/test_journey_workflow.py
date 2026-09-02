from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release-journey.yml"


def test_release_journey_workflow_is_pinned_read_only_and_sanitized() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert '    - cron: "23 4 * * *"' in workflow
    assert '      - "v*-rc*"' in workflow
    assert "  workflow_call:" in workflow
    assert "  workflow_dispatch:" in workflow
    assert "permissions:\n  contents: read\n" in workflow
    assert "timeout-minutes: 10" in workflow
    assert workflow.count("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1") == 2
    assert "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e" in workflow
    assert "version: v0.36.1" in workflow
    assert "astral-sh/setup-uv@20cfd1bf945f4377ade1205e4dbc17946fc9a30d" in workflow
    assert 'version: "0.12.7"' in workflow
    assert "6921474591b6c59e89025370c310c7f85859246f" in workflow
    assert (
        "cr.agentgateway.dev/agentgateway:v1.4.1@sha256:"
        "efd79355b89094a8225a9db465d9a01dc656b377f0bab458761b935a13231d29"
    ) in workflow
    assert "docker-compose-linux-x86_64" in workflow
    assert "c57ab918abd5b05ca7e7d0f275875dd1330a695074f309dc9eab1b49efafcd4b" in workflow
    assert "python -m integration.journey.run" in workflow
    assert "uv build --wheel --out-dir artifacts/security-package" in workflow
    assert '--package-digest "$package_digest"' in workflow
    assert '--source-revision "$GITHUB_SHA"' in workflow
    assert "security-evidence.json" in workflow
    assert "scan_journey_surfaces" in workflow
    assert "steps.sanitize.outcome == 'success'" in workflow
    assert "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a" in workflow
    assert "retention-days: 7" in workflow
    assert "docker push" not in workflow
    assert "--push" not in workflow
    assert workflow.count("secrets.GO_PRIVATE_TOKEN") == 1
    assert "token: ${{ secrets.GO_PRIVATE_TOKEN }}" in workflow
    assert "kubectl" not in workflow
    assert "kubeconfig" not in workflow.lower()
