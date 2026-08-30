# Runtime envelope checker

envelope-targets.json is the machine-readable form of ADR-0001's initial
capacity and SLO contract. check_envelope.py compares one observed result
document with every committed target:

    python3 benchmarks/check_envelope.py benchmarks/example-observations.json

Exit codes are stable:

- 0: every observation meets the target;
- 1: the document is valid and at least one target is missed;
- 2: the measurement document is incomplete or invalid.

The JSON report includes every actual value, operator, target, unit, and result.
CI can archive it without parsing human text.

## Observation contract

Input has one top-level observed object containing every metric named by the
target document. Values are finite JSON numbers. The example is synthetic and
exists only to prove the comparison contract; it is not production evidence.

## How later benchmarks collect each value

| Metric | Collection method |
|---|---|
| sustained_calls_per_second | Highest completed no-op tool rate maintained for the committed steady window without exceeding latency or error targets |
| burst_calls_per_second | Highest completed no-op tool rate during the committed short burst window without overload outside policy |
| supported_request_bytes | Largest accepted valid MCP request at the server-enforced boundary |
| supported_response_bytes | Largest accepted valid structured result at the server-enforced boundary |
| runtime_added_p99_milliseconds | Client-observed loopback p99 for a no-op handler through the runtime transport and policy path; gateway and product latency excluded |
| startup_seconds | Monotonic duration from process start until readiness first succeeds |
| idle_rss_mebibytes | Resident set after startup has settled with no active calls, sampled by the benchmark supervisor |
| monthly_invocation_availability_percent | Successful eligible invocations divided by all eligible invocations over the SLI window, excluding documented client faults |

The reliability issue will commit the load profile, steady and burst windows,
hardware or pod shape, exact package and image digests, sample count, and raw
sanitized results. A p99 is measured directly; percentiles from different
paths are not subtracted.

The checker deliberately does not collect measurements. Load generation and
process supervision arrive with the runtime and reliability slices; keeping
the target contract separate prevents each tool from redefining success.

## Execution-limit ceiling benchmark

`measure_execution_limits.py` exercises the default input bytes, result bytes,
JSON depth, object properties, array items, and total-node ceilings. Each case
is validated once for warmup, measured repeatedly without allocation tracing
for latency, then measured once with `tracemalloc` for peak temporary Python
allocation:

    uv run --frozen python benchmarks/measure_execution_limits.py --samples 100

The report records the configured ceiling and independently constructed units,
encoded bytes, p50/p99/maximum latency, Python version, platform, and peak
temporary bytes. The committed
`execution-limits-observations.json` is local regression evidence from Python
3.14 on arm64 macOS. It is not a production throughput, RSS, pod-shape, or SLO
claim; issue #29 owns those load and soak measurements.

## Observability hot-path benchmark

`measure_observability.py` measures complete successful no-op invocations
through `Application` and the in-process transport with synchronous local
observability enabled:

    uv run --frozen python benchmarks/measure_observability.py \
      --samples 5000 --warmup 500

Each measured invocation must exercise three spans, two in-flight changes, one
RED observation, and one structured log. The script fails if that seven-event
contract changes unexpectedly or if p99 is not below the unchanged 15 ms
runtime budget. `observability-observations.json` records a 0.313 ms local p99
on Python 3.14 arm64 macOS. This is instrumentation regression evidence, not a
production throughput or end-to-end network SLO claim; issue #29 still owns
load and soak proof.

## Conformance PR-lane measurement

`measure_conformance.py` runs the core, official SDK, and external published
contract lanes with network sockets disabled. It then runs two mutation probes
that corrupt timeout error mapping and bypass policy default-deny:

    uv run --frozen python benchmarks/measure_conformance.py

The command fails if a lane or mutation probe fails or if the three default
lanes exceed 10 seconds of pytest-reported time. The checked-in
`conformance-observations.json` records 0.56 seconds on Python 3.14 arm64 macOS
and both mutants killed. It is PR regression evidence, not a production
invocation-latency claim.
