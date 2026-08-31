# Build an MCP server

## Five-minute local path

Use Python 3.14 and the checked-in example; it is hermetic and never contacts a Registry, Gateway, production host, or identity system.

```sh
uv sync --frozen
uv run --frozen pytest examples/conformance-server/tests
uv run --frozen python examples/conformance-server/server.py
```

Start with `callable_tool`, a closed Pydantic input/output model, and `ToolMetadata`. Identity and tenant come from verified `CallContext`, never a tool argument. Reads use `not_applicable` idempotency; writes require an idempotency key forwarded to the owning product API. The runtime process is stateless—PostgreSQL/Temporal, not the pod, owns durable state.

The executable plain-runtime reference is
[`examples/conformance-server`](../examples/conformance-server): it constructs
an `Application`, exposes one bounded tool, and proves the reusable
conformance contract. The executable ADK-backed reference is
[`compatibility/adk/test_bridge.py`](../compatibility/adk/test_bridge.py); it
proves an explicit `AgentToolView` export behaves identically over Streamable
HTTP. Follow the [ADK bridge guide](adk-bridge.md) for its optional dependency,
tenant authority, approval, redaction, and image-selection contract.

## Production path

Build an immutable Python 3.14 core (or ADK) image and define egress, scopes, effects, approvals, and semantics. Compile portable `server.json` and the Agentic Registry manifest from one source. Run `tesserix-mcp-runtime publish --dry-run` with immutable evidence; real publication uses one stable idempotency key. Wait for exact-digest Gateway activation, invoke through AgentGateway, observe telemetry, and use GitOps revert for rollback.

The production path needs external Registry, identity, AgentGateway, and GitOps prerequisites. Local success does not imply production authorization or route safety.

## Discovery and lifecycle

Semantic metadata describes when a tool is useful; it grants no authority. Search is tenant-filtered, progressive, and may return no-match. Resolve the selected immutable version and schema/tool-surface fingerprint exactly, then authorize again before invocation. Deprecate first, observe callers, then retire the exact route/version; never delete a live route from a partial Registry view.

## Version policy and incidents

The supported clients are DevAI 1.28.1, MCP SDK 1.29.1, and MCP v2.1.1. MCP SDK 1.34 is not a target because no such Python SDK release exists; “1.34” is often a Python 3.14 misunderstanding. See ADR-0002 for pinned evidence.

For a credential/identity incident, rotate through the owning identity system, fail closed, and never put credentials in manifests or command lines. For an outage, follow [operations](operations.md); for migration use [migration](migration.md), and for safe retirement preserve the previous immutable GitOps target until telemetry confirms no callers.
