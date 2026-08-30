# ADR-0015: Reusable conformance and fault testkit

## Status

Accepted.

## Context

A reusable runtime needs portable evidence. Private repository tests prove this
implementation but do not let another adapter or product server prove the same
protocol, policy, tenancy, lifecycle, and failure semantics. Copying tests into
each repository would immediately create multiple contract authorities.

This is a CI library, not a serving service. It receives zero production
requests per second, persists zero bytes at 12 or 36 months, has no read/write
traffic ratio, and adds no production latency hop. Its workload is 24 core
cases, two applicable official-SDK cases, two applicable ADK cases, a 24-case
external collection with 22 explicit skips, and two mutation probes. Python
3.14 arm64 macOS observed the three default lanes in 0.56 seconds of
pytest-reported time. The PR target is less than 10 seconds with every required
case passing; there is no partial-availability mode for a verification gate.

The contract must evolve without making a future optional protocol feature fail
every older implementation. Test-only dependencies must never enter the
production runtime closure or wheel. Default execution must require no internet,
production identity, Registry, Gateway, GKE, wall-clock delay, or persistent
state.

## Decision

### Separate test distribution

Publish `tesserix-mcp-testkit` as a typed workspace distribution beside
`tesserix-mcp-runtime`. Expose it through the runtime's `testkit` extra and keep
it in development dependency groups only. Both artifacts derive the same VCS
version, carry Apache-2.0, and are built and validated together.

The production runtime wheel contains no testkit package, pytest plugin, fake,
or fault helper. Its core resolution remains 34 distributions. The explicit
testkit profile resolves 42 distributions, including pytest and pytest-socket.
The measured testkit wheel is 13,889 bytes. The runtime wheel remains below its
fixed 98,304-byte ceiling at 98,128 bytes.

### Versioned target contract

Contract 1.0 defines a structural `ConformanceTarget`: one frozen capability set
and one asynchronous observation method. Discovery and invocation are required.
Error mapping, lifecycle, authorization, tenancy, limits, telemetry, and
cancellation are optional declarations. The assertion validates the complete
required set before invoking a case. It skips only undeclared optional
capabilities and reports stable payload-free failure identifiers.

The suite has 24 cases: one discovery, one invocation, every stable
`ErrorCode`, every `LifecycleState`, default-deny authorization, cross-tenant
rejection, input/result/concurrency limits, payload-free telemetry, and caller
cancellation. Core declares and exercises all capabilities through real
`Application` behavior. The official SDK and ADK targets declare only discovery
and invocation and execute those same case objects without synthesizing
runtime-only outcomes.

### Compatibility rules

`CONFORMANCE_CONTRACT_VERSION` uses `major.minor` independently from the package
release version. A new optional capability is minor because older targets skip
it. Additive fakes and fault constructors do not change the contract version.
Changing an existing expectation, adding a case to a capability an
implementation may already declare, making a capability required, removing or
renaming public contract data, or adding a stable runtime error/lifecycle state
is major. A major transition publishes both package majors until consumers
migrate.

This makes optional protocol growth additive while preventing a target from
claiming a capability and silently receiving new mandatory semantics in a minor
upgrade.

### Deterministic faults and fakes

Publish bounded fakes for clock, identity, credentials, backing API, Gateway,
Registry, and MCP client boundaries. Publish scripted slow, unavailable,
malformed, truncated, oversized, flapping, duplicate, cancelled, and
cross-tenant faults. Scripts contain 1 to 256 immutable steps, preserve exact
order under a lock, and never fall through to a network client. Cancellation
uses `asyncio.CancelledError`; other failures carry one stable `FaultKind` and no
payload.

Every default pytest lane disables TCP and UDP through pytest-socket while
allowing only asyncio's internal Unix socket pair. A fresh Python 3.14
environment installs both built wheels and the runtime test extra offline, then
runs the external example from installed artifacts.

## Dependency and failure analysis

- Target omits discovery or invocation: the contract fails before calling
  `observe` and names the first missing required capability.
- Target omits an optional future capability: its cases skip and existing
  contract behavior remains green.
- Target returns a malformed capability set or observation: validation fails
  with a stable code and does not echo supplied values.
- Fake attempts a real network call: pytest-socket fails the test before bytes
  leave the process.
- Fault script is empty, exceeds 256 steps, or is exhausted: construction or
  resolution fails deterministically with a bounded exception.
- Case is cancelled: owned tasks unwind, cancellation is re-raised or mapped by
  the target under test, and no persistent recovery is required.
- Case is delivered twice: the duplicate fault is explicit; the suite does not
  claim transport-level exactly-once delivery.
- A test process crashes: only synthetic in-memory state is lost. There is no
  database transaction, outbox, queue, cache, saga, credential rotation, or
  compensation path.
- An SDK or ADK version changes behavior: its isolated applicable lane fails
  before the support claim or contract package is released.

## Alternatives considered

### Keep the suite private

Rejected. Downstream implementations could only copy tests or claim
compatibility without executable evidence.

### Put pytest and fakes in the runtime distribution

Rejected. It would enlarge the production artifact, add test dependencies to
every pod, and erase the dependency boundary the testkit is meant to prove.

### Publish cases but require every capability immediately

Rejected. SDK and ADK adapters cannot honestly expose runtime-only lifecycle,
policy, telemetry, and bulkhead observations. Future additions would break
older targets even when unrelated to their declared behavior.

### Let targets return expected values directly

Rejected. That tests the case table rather than the implementation. The core,
SDK, ADK, and external targets must exercise real application or protocol paths.

### Add a general mutation-testing framework

Rejected for this slice. A new framework and dependency closure is unnecessary
to prove the two selected high-risk assertions. Focused probes mutate timeout
mapping and policy default-deny behavior using existing pytest facilities. A
broader mutation program can be added when its measured value justifies its
cost.

## Security and residual risk

Protected assets are tenant separation, authorization decisions, stable error
semantics, synthetic credentials, and payload confidentiality. Attackers include
a malicious downstream fixture, an authenticated caller from another tenant, a
compromised dependency, and an insider who inserts production data into a test.
The downstream-target boundary validates bounded capabilities and observations;
the process-to-network boundary denies sockets; tenant and identity inputs use
synthetic `.example.invalid` data.

No production token, credential, tenant payload, secret, or environment dump may
enter source, fixtures, telemetry text, reports, or build artifacts. Fake
credentials use the runtime's redacted secret type. A malicious test still runs
with the developer or CI worker's filesystem authority; repository checkout and
CI permissions remain the outer sandbox, and dependency review plus lockfile
review remain required.

## Verification

Package tests cover every public contract validator, fake, fault, fixture, and
missing-target failure. Core passes all 24 cases in process. The official MCP
SDK and isolated attested ADK bridge each pass the two applicable required
cases. The external example passes two and explicitly skips 22. Network blocking
is active in each default lane.

The checked-in `conformance-observations.json` reports 0.56 seconds against the
10-second PR budget. Focused mutation probes change timeout mapping to internal
failure and bypass policy default-deny; both are killed by stable contract
assertions. Artifact checks build wheel and sdist for both distributions, verify
matching non-fallback versions, licenses and typing markers, smoke-install each,
then install and run the published extra offline in a separate environment.

Formatting, Ruff, strict mypy, Pyright, full coverage, import layering,
dependency budgets, license checks, security scans, Python 3.12/3.13/3.14, MCP
1.28.1/1.29.1/2.1.1, and ADK 0.53.1 compatibility remain required.

## Rollout

1. Merge contract 1.0, the testkit artifact, and all core/SDK/ADK evidence.
2. Publish runtime and testkit artifacts with the same reviewed VCS version.
3. Adopt the test extra in one non-production downstream server and declare only
   discovery and invocation.
4. Add optional capabilities as that server exposes observable behavior.
5. Require the inherited suite before Registry publication or Gateway activation
   work claims compatibility.

There is no infrastructure rollout, schema migration, live route mutation, or
production cost in this decision.

## Rollback

Revert downstream test dependencies to the previous runtime/testkit package pair
or remove the optional extra. Production installations are unchanged because
the testkit was never in their dependency graph. There is no persisted state to
migrate or recover. If contract 1.0 artifacts have already been published, do
not overwrite them; publish a corrected package release, and use a contract
major only when behavior itself must break.

## Consequences

Alternative adapters and product servers can prove one contract with minimal
configuration, deterministic failures, and no copied private tests. Optional
capabilities let the contract grow without false claims. The costs are one small
test-only distribution, eight additional distributions in its explicit profile,
about six seconds of wall time for the measurement test's isolated subprocesses,
and the discipline to version semantic changes rather than quietly editing case
expectations.
