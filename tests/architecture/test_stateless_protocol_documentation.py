from pathlib import Path

ROOT = Path(__file__).parents[2]
GUIDE = ROOT / "docs" / "stateless-mcp.md"


def test_stateless_protocol_guide_covers_the_modern_production_contract() -> None:
    document = GUIDE.read_text(encoding="utf-8")

    for requirement in (
        "2026-07-28",
        "MCP-Protocol-Version",
        "MCP-Method",
        "io.modelcontextprotocol/protocolVersion",
        "io.modelcontextprotocol/clientCapabilities",
        "server/discover",
        "subscriptions/listen",
        "Last-Event-ID",
        "-32022",
        "sessionAffinity: None",
        "idempotency",
        "tenant",
        "tasks",
    ):
        assert requirement in document

    sep = (
        "https://github.com/modelcontextprotocol/modelcontextprotocol/"
        "blob/main/seps/2575-stateless-mcp.md"
    )
    assert sep in document
    assert "MCPMarket" in document
    assert "Medium" in document
