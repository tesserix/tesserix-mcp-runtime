from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
AUTH_ACTION = ROOT / ".github" / "actions" / "auth-private-dependencies" / "action.yml"


def _read(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_private_dependency_auth_uses_the_existing_read_credential() -> None:
    action = AUTH_ACTION.read_text(encoding="utf-8")

    assert "uv auth login github.com" in action
    assert "--username x-access-token" in action
    assert '"$PRIVATE_REPOSITORY_TOKEN"' in action
    assert "secrets.GO_PRIVATE_TOKEN" not in action


def test_every_uv_workflow_authenticates_before_resolving_private_dependencies() -> None:
    expected_auth_steps = {
        "compatibility.yml": 2,
        "containers.yml": 1,
        "quality.yml": 2,
        "release-journey.yml": 1,
        "release.yml": 4,
        "security.yml": 1,
    }

    for name, count in expected_auth_steps.items():
        workflow = _read(name)
        assert workflow.count("uses: ./.github/actions/auth-private-dependencies") == count
        assert workflow.count("token: ${{ secrets.GO_PRIVATE_TOKEN }}") >= count


def test_private_cross_repository_reads_do_not_use_the_repository_token() -> None:
    compatibility = _read("compatibility.yml")
    journey = _read("release-journey.yml")
    release = _read("release.yml")

    assert compatibility.count("token: ${{ secrets.GO_PRIVATE_TOKEN }}") >= 3
    assert "GH_TOKEN: ${{ secrets.GO_PRIVATE_TOKEN }}" in compatibility
    assert "GH_TOKEN: ${{ github.token }}" not in compatibility
    assert journey.count("token: ${{ secrets.GO_PRIVATE_TOKEN }}") >= 2
    assert release.count("secrets: inherit") == 5
