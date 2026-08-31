# Reusable conformance and fault testkit

`tesserix-mcp-testkit` lets runtime adapters and downstream MCP servers run one
versioned behavioral contract without copying this repository's private tests.
It is published beside the runtime and is available through the
`tesserix-mcp-runtime[testkit]` test extra. A production installation of the
runtime does not resolve pytest, pytest-socket, the testkit, or its helpers.

## Install for tests

Add the extra only to a development or test dependency group:

```toml
[dependency-groups]
test = ["tesserix-mcp-runtime[testkit]>=0.0.1.dev0,<1"]
```

Then configure pytest to reject accidental network access. The Unix socket
allowance is required by Python's asyncio event loop and does not permit TCP or
UDP traffic:

```toml
[tool.pytest.ini_options]
addopts = "-q --strict-config --strict-markers --disable-socket --allow-unix-socket"
```

The built distributions and external example are verified offline in a fresh
Python 3.14 environment. The same package supports Python 3.12, 3.13, and 3.14.
The MCP SDK requirement follows the runtime's reviewed v2 constraint; there is
no MCP Python SDK 1.34 release.

## Provide a target

The pytest entry point supplies `conformance_case` and
`assert_mcp_conformance`. A downstream project supplies only its target and one
inherited test:

```python
from collections.abc import Callable

import pytest
from tesserix_mcp_testkit import ConformanceCase, ConformanceTarget

from server import ServerTarget


@pytest.fixture
def conformance_target() -> ServerTarget:
    return ServerTarget()


def test_mcp_contract(
    conformance_target: ConformanceTarget,
    conformance_case: ConformanceCase,
    assert_mcp_conformance: Callable[[ConformanceTarget, ConformanceCase], None],
) -> None:
    assert_mcp_conformance(conformance_target, conformance_case)
```

`ServerTarget.capabilities` is a frozen set of `ConformanceCapability` values.
Its asynchronous `observe(case)` method exercises the server and returns a
bounded `ConformanceObservation`. It must report behavior it actually observed;
copying `case.expected_*` values into the result does not test an implementation.

Discovery and invocation are required in contract 1.0. Error mapping,
lifecycle, authorization, tenancy, limits, telemetry, and cancellation are
optional declarations. An undeclared optional capability is skipped. Omitting
a required capability fails before the case reaches the target and names the
missing capability. An invalid target or observation fails with a stable,
payload-free conformance code.

The complete working target is in
[`examples/conformance-server`](../examples/conformance-server/README.md). The
repository also runs the same applicable case objects against core, the
official MCP SDK's in-memory client/server, and the isolated ADK bridge.

## Contract 1.0 coverage

The 24 cases cover:

- one discovery and one successful invocation case;
- every stable runtime `ErrorCode`;
- every `LifecycleState`;
- default-deny authorization and cross-tenant rejection;
- input, result, and concurrency limits;
- payload- and credential-free telemetry; and
- caller cancellation.

Cases are deterministic and do not require production identity, Registry,
Gateway, GKE, internet access, sleeps, or wall-clock progress. The checked-in
measurement runs core, SDK, and external lanes in 0.56 seconds of pytest-reported
time against a 10-second PR ceiling. It also proves that timeout-mapping and
policy-default-deny mutants are killed:

```bash
uv run --frozen python benchmarks/measure_conformance.py
```

## Fakes and deterministic faults

The public fakes cover clock, identity, credential issuance, backing API,
Gateway context, Registry search, and MCP client calls. They retain bounded
request records for assertions and never send network traffic.

```python
from tesserix_mcp_testkit import FakeBackingAPI, FaultKind, FaultScript, FaultStep

backing = FakeBackingAPI(
    FaultScript(
        (
            FaultStep.inject(FaultKind.UNAVAILABLE),
            FaultStep.success({"status": "recovered"}),
        )
    )
)
```

The stable fault vocabulary is slow, unavailable, malformed, truncated,
oversized, flapping, duplicate, cancelled, and cross-tenant. `success` is the
terminal scripted value rather than an injected failure. Cancellation raises
`asyncio.CancelledError`; every other injected failure uses one bounded
`InjectedFault` carrying only its `FaultKind`. `FakeClock` advances logical time
without waiting on wall time.

## Adversarial security evidence

The same package exports security contract 1.0 for release-blocking negative
tests. Its 51 required cases cover tenancy, identity, authority, isolated
egress, every named redaction sink, control-plane activation, and CI/dependency
policy. Observations are scanned, hashed, and discarded; canonical reports bind
the exact source, package, image, manifest, SBOM, Registry, and Gateway
identities. GA serialization can require a scope-bound independent review.

See the [adversarial security verification guide](security-verification.md) for
the case matrix, result and sink APIs, finding/retest rules, the pinned real
journey, and contract-version policy.

## Versioning and compatibility

`CONFORMANCE_CONTRACT_VERSION` is independent of the package release version.
Contract versions use `major.minor`:

- adding a new optional capability and cases is minor and older targets keep
  passing because they do not declare it;
- adding fakes or fault constructors without changing cases does not change the
  contract version;
- changing an existing case's meaning or expected result is major;
- adding a case to an existing declared capability is major;
- adding a required capability or required case is major;
- removing or renaming a case, capability, observation field, or target method
  is major; and
- adding a runtime error or lifecycle state is major because contract 1.0
  automatically covers the complete stable vocabulary.

During a major migration, publish both contract suites under distinct package
majors and keep the older suite runnable until downstream targets migrate. A
server may assert the exact contract version in its test configuration when it
needs reviewed upgrade control.

## Failure and trust boundaries

Each case creates isolated synthetic state. A failed or cancelled case leaves no
database record, message, credential, Registry version, or live route to recover.
Duplicate delivery is represented explicitly by the fault script rather than
claimed as exactly-once behavior. A backing fake outage produces the configured
failure; it cannot fall through to a real URL. If a helper attempts TCP or UDP,
pytest-socket fails the test.

The assets protected by the suite are tenant boundaries, authorization
decisions, stable error semantics, synthetic credentials, and payload
confidentiality. Threat actors include a malicious downstream fixture, a target
from another tenant, and a compromised test dependency. The target boundary
validates capabilities and bounded observations, network access is denied, and
only synthetic `.example.invalid` identity data is permitted. Production tokens,
tenant payloads, and secrets must never be placed in fixtures or reports.
