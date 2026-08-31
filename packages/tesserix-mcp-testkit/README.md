# Tesserix MCP test kit

Reusable, offline pytest conformance cases and deterministic fault helpers for
MCP runtime adapters and downstream servers. Install through
`tesserix-mcp-runtime[testkit]`; production installations do not include this
distribution or its pytest dependencies.

Contract 1.0 requires tool discovery and invocation, with optional error,
lifecycle, authorization, tenancy, limit, telemetry, and cancellation cases.
Downstream projects provide a `conformance_target` fixture and inherit the
entry-point fixtures without copying tests. Configure pytest with
`--disable-socket --allow-unix-socket`; every bundled fake and fault is synthetic
and deterministic.

The complete guide and external server live in the
[`tesserix-mcp-runtime` repository](https://github.com/tesserix/tesserix-mcp-runtime/blob/main/docs/conformance.md).
The package also exposes the 51-case digest-bound adversarial contract described
in the [security verification guide](https://github.com/tesserix/tesserix-mcp-runtime/blob/main/docs/security-verification.md).
