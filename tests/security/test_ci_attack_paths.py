from __future__ import annotations

from pathlib import Path

from security.check_ci_attack_paths import check_ci_attack_paths

ROOT = Path(__file__).parents[2]


def test_repository_ci_attack_paths_are_fail_closed_and_release_blocking() -> None:
    report = check_ci_attack_paths(ROOT)

    assert report == {
        "ci.immutable_actions": True,
        "ci.least_privilege_permissions": True,
        "ci.untrusted_pull_request": True,
        "dependency.release_policy": True,
    }
