from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import yaml

ROOT = Path(__file__).parents[2]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
RELEASE_JOURNEY = ROOT / ".github" / "workflows" / "release-journey.yml"
RELEASING = ROOT / "docs" / "releasing.md"
README = ROOT / "README.md"
REUSABLE_GATES = (
    ROOT / ".github" / "workflows" / "compatibility.yml",
    ROOT / ".github" / "workflows" / "containers.yml",
    ROOT / ".github" / "workflows" / "quality.yml",
    ROOT / ".github" / "workflows" / "release-journey.yml",
    ROOT / ".github" / "workflows" / "security.yml",
)
PINNED_ACTIONS = {
    "actions/attest": "1e69f48acb82d1966a394da916b4c1698aa569d6",
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "astral-sh/setup-uv": "20cfd1bf945f4377ade1205e4dbc17946fc9a30d",
    "docker/build-push-action": "53b7df96c91f9c12dcc8a07bcb9ccacbed38856a",
    "docker/login-action": "dbcb813823bdd20940b903addbd779551569679f",
    "docker/setup-buildx-action": "37fe631027851001ddb9b187196cc803df7f5f0e",
    "sigstore/cosign-installer": "6f9f17788090df1f26f669e9d70d6ae9567deba6",
}


def _workflow(path: Path) -> dict[str, object]:
    return cast(
        dict[str, object],
        yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader),
    )


def test_release_is_tag_only_and_privilege_is_scoped_to_protected_jobs() -> None:
    workflow = _workflow(RELEASE)

    assert workflow["on"] == {"push": {"tags": ["v*"]}}
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "cancel-in-progress": "false",
        "group": "release-${{ github.ref }}",
    }
    jobs = cast(dict[str, dict[str, object]], workflow["jobs"])
    assert set(jobs) == {
        "adversarial",
        "compatibility",
        "containers",
        "finalize",
        "guard",
        "publish",
        "public_smoke",
        "quality",
        "security",
        "smoke",
    }
    assert jobs["publish"]["environment"] == "release"
    assert jobs["publish"]["permissions"] == {
        "artifact-metadata": "write",
        "attestations": "write",
        "contents": "write",
        "id-token": "write",
        "packages": "write",
    }
    assert jobs["finalize"]["environment"] == "release"
    assert jobs["finalize"]["permissions"] == {"contents": "write"}
    assert jobs["smoke"]["permissions"] == {
        "attestations": "read",
        "contents": "read",
        "packages": "read",
    }
    assert jobs["public_smoke"]["permissions"] == jobs["smoke"]["permissions"]
    for name in (
        "adversarial",
        "guard",
        "quality",
        "security",
        "compatibility",
        "containers",
    ):
        assert jobs[name].get("environment") is None
    assert jobs["publish"]["needs"] == [
        "guard",
        "quality",
        "security",
        "compatibility",
        "containers",
        "adversarial",
    ]


def test_release_reuses_every_gate_and_pins_every_external_action() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    quality = (ROOT / ".github" / "workflows" / "quality.yml").read_text(encoding="utf-8")
    containers = (ROOT / ".github" / "workflows" / "containers.yml").read_text(encoding="utf-8")

    for gate in REUSABLE_GATES:
        assert "workflow_call:" in gate.read_text(encoding="utf-8")
        assert f"uses: ./.github/workflows/{gate.name}" in text
    uses = re.findall(r"^\s*uses:\s+([^\s#]+)(?:\s+#.*)?$", text, flags=re.MULTILINE)
    external = [value for value in uses if not value.startswith("./")]
    assert external
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in external)
    observed = {value.split("@", 1)[0]: value.split("@", 1)[1] for value in external}
    assert observed == PINNED_ACTIONS
    assert "mypy --strict src tests release" in quality
    assert "pyright src tests release" in quality
    assert containers.count('- "release/**"') == 2


def test_release_journey_loads_single_platform_images_without_provenance() -> None:
    text = RELEASE_JOURNEY.read_text(encoding="utf-8")

    assert text.count("--load") == 3
    assert text.count("--provenance=false") == 3
    assert "--provenance=mode=max" not in text


def test_release_publishes_only_exact_signed_and_publicly_verified_artifacts() -> None:
    text = RELEASE.read_text(encoding="utf-8")

    assert set(re.findall(r"secrets\.([A-Z0-9_]+)", text)) == {"GO_PRIVATE_TOKEN"}
    assert text.count("GO_PRIVATE_TOKEN: ${{ secrets.GO_PRIVATE_TOKEN }}") == 2
    assert ":latest" not in text
    assert "PUBLISH_TO_PYPI" not in text
    assert "--push" not in text
    assert "push: true" in text
    assert "provenance: mode=max" in text
    assert "sbom: true" in text
    assert "cosign sign --yes" in text
    assert "cosign attest --yes" in text
    assert text.count("uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6") == 6
    assert "gh release create" in text
    assert "--draft" in text
    assert "--verify-tag" in text
    assert "gh release edit" in text
    assert "--draft=false" in text
    assert "ghcr.io/${{ github.repository }}:${{ needs.guard.outputs.oci_tag }}-core" in text
    assert "ghcr.io/${{ github.repository }}:${{ needs.guard.outputs.oci_tag }}-adk" in text
    assert "scan_journey_surfaces" in text
    assert "gitleaks dir" in text
    assert "docker logout ghcr.io" in text
    assert "api.github.com/repos/${GITHUB_REPOSITORY}/releases/tags/${TAG}" in text
    assert "architecture/smoke_install_artifacts.py" in text
    assert text.count("deploy/container/verify.py") >= 2
    assert "gh attestation verify" in text
    assert "cosign verify-attestation" in text
    assert "--predicate-type https://cyclonedx.org/bom" in text
    assert "visibility=public" not in text
    assert "scope=repository:${GITHUB_REPOSITORY}:pull" in text
    assert "docker-content-digest" in text


def test_release_sboms_prove_artifacts_lock_and_base_image_contents() -> None:
    text = RELEASE.read_text(encoding="utf-8")

    assert "uv export --frozen --format cyclonedx1.5" in text
    assert "--override-default-catalogers python-installed-package-cataloger" in text
    assert "python-artifacts.cdx.json" in text
    assert "python-dependencies.cdx.json" in text
    assert "for variant in core adk" in text
    assert "${variant}-base.cdx.json" in text
    assert "python -m release.sbom python" in text
    assert text.count("python -m release.sbom image") == 1


def test_release_scans_every_high_and_critical_vulnerability() -> None:
    release = RELEASE.read_text(encoding="utf-8")
    containers = (ROOT / ".github" / "workflows" / "containers.yml").read_text(encoding="utf-8")

    assert "--severity HIGH,CRITICAL --exit-code 0" in release
    assert "--ignore-unfixed" not in release
    assert "--ignore-unfixed" not in containers
    assert release.count("python -m release.vulnerabilities") == 1
    assert containers.count("python -m release.vulnerabilities") == 2
    assert "${variant}-trivy-policy.json" in release


def test_public_smoke_retries_propagation_and_lists_every_release_asset() -> None:
    text = RELEASE.read_text(encoding="utf-8")

    assert text.count("--retry 5") >= 3
    assert text.count("--retry-all-errors") >= 3
    assert "releases/${release_id}/assets?per_page=100" in text
    assert "retry_public_command" in text


def test_release_refuses_to_replace_existing_image_tags_and_checks_labels() -> None:
    text = RELEASE.read_text(encoding="utf-8")

    assert "Could not prove release tag is unused" in text
    assert '"release not found"' in text
    guard = text.index("docker buildx imagetools inspect")
    first_push = text.index("- name: Build and push core image")
    assert guard < first_push
    assert "Immutable image tag already exists" in text
    assert "docker image inspect" in text
    assert "org.opencontainers.image.revision" in text
    assert "org.opencontainers.image.version" in text


def test_release_attestation_verification_receives_explicit_job_token() -> None:
    workflow = _workflow(RELEASE)
    jobs = cast(dict[str, dict[str, object]], workflow["jobs"])

    for job_name in ("smoke", "public_smoke"):
        steps = cast(list[dict[str, object]], jobs[job_name]["steps"])
        verification = next(
            step for step in steps if "gh attestation verify" in str(step.get("run", ""))
        )
        assert cast(dict[str, str], verification["env"])["GH_TOKEN"] == "${{ github.token }}"


def test_release_operator_contract_documents_fallback_recovery_and_cost() -> None:
    guide = RELEASING.read_text(encoding="utf-8")

    assert "docs/releasing.md" in README.read_text(encoding="utf-8")
    assert "GitHub Release fallback" in guide
    assert "PyPI trusted publishing" in guide
    assert "tesserix-mcp-runtime does not yet exist on PyPI" in guide
    assert "environment: release" in guide
    assert "environment: pypi" in guide
    assert "gh attestation verify" in guide
    assert "cosign verify-attestation" in guide
    assert "Never delete or move a published tag" in guide
    assert "yank" in guide.lower()
    assert "CVE" in guide
    assert "RTO" in guide and "RPO" in guide
    assert "cost" in guide.lower()
    assert "superseding version" in guide
    assert "production token" in guide
    assert "SBOM-to-lock" in guide
    assert "base-image SBOM" in guide
