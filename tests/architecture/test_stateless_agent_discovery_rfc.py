from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RFC = ROOT / "docs" / "adr" / "0031-stateless-agent-capability-discovery.md"
ADR_INDEX = ROOT / "docs" / "adr" / "README.md"
PROJECT_README = ROOT / "README.md"


def test_stateless_agent_capability_discovery_rfc_is_complete_and_indexed() -> None:
    document = RFC.read_text(encoding="utf-8")
    index = ADR_INDEX.read_text(encoding="utf-8")
    readme = PROJECT_README.read_text(encoding="utf-8")

    for section in (
        "## Status",
        "## Context and quantitative envelope",
        "## Decision",
        "## Architecture",
        "## Discovery workflow",
        "## Invocation workflow",
        "## Durable workflow",
        "## Security and tenancy",
        "## Observability and evaluation",
        "## Dependency failure behavior",
        "## Rollout and rollback",
        "## Alternatives considered",
        "## Consequences",
    ):
        assert section in document

    for contract in (
        "Status: Accepted",
        "stateless",
        "MCP Registry",
        "MCP Gateway",
        "ADK",
        "Tool catalog",
        "Skill catalog",
        "Agent Registry",
        "Context sources",
        "tools/list",
        "tools/call",
        "at most 20",
        "at most one exact fetch",
        "40 tools",
        "256 KiB",
        "Idempotency-Key",
        "SurfacePin",
        "Qdrant",
        "PostgreSQL",
        "Temporal",
        "precision@K",
        "forbidden exposure",
        "traceparent",
        "payloads are not recorded",
        "session affinity",
        "one Git revert",
    ):
        assert contract in document

    assert document.count("```mermaid") >= 4
    assert "[0031](0031-stateless-agent-capability-discovery.md)" in index
    assert "docs/adr/0031-stateless-agent-capability-discovery.md" in readme
