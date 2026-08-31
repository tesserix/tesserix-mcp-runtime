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

Evaluation contract v1 adds reusable, digest-bound correctness and promotion
evidence. One bundle runs through `InProcessEvaluationTarget` during authoring
and `StreamableHttpEvaluationTarget` against a canary. It covers correctness,
schema conformance, secret leakage, tenant isolation, authorization denial,
idempotency, latency, and availability; emits payload-free JSON and Markdown;
and verifies Ed25519 signatures before experimental, internal, or GA policy is
assessed. `reference_evaluation_bundle()` includes happy, boundary, denial,
duplicate, timeout, cancellation, tenant-canary, and secret-canary examples.

The packaged schema is
`tesserix_mcp_testkit/schemas/evaluation-bundle-v1.schema.json`. See the
[evaluation and promotion guide](https://github.com/tesserix/tesserix-mcp-runtime/blob/main/docs/evaluation.md)
for local, HTTP, signing, and reviewer examples.
