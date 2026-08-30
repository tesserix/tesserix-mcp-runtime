# ADR-0002: Python and MCP compatibility policy

- Status: Accepted
- Date: 2026-08-31
- Tracking: [tesserix-mcp-runtime#3](https://github.com/tesserix/tesserix-mcp-runtime/issues/3), [tesserix-mcp-runtime#26](https://github.com/tesserix/tesserix-mcp-runtime/issues/26)
- Supersedes: none

## Evidence

The version decision was checked against package and source catalogs rather
than inferred from a requested number:

- PyPI reported mcp 2.1.1 as the current stable Python SDK on 2026-08-30.
- The official v2.1.1 release describes v2 as the current stable line, serving
  the 2026-07-28 MCP revision and every earlier revision.
- The maintained v1 branch had released 1.29.1. DevAI remained locked to
  mcp 1.28.1 with a less-than-2 upper bound.
- The Tesserix ADK v0.53.1 lock resolved mcp 2.1.0.
- DevAI commit `850379a833bb5740c82eb2a16cac452ff93695f0`
  resolved mcp 1.28.1 from its frozen lock. Its real downstream adapter is
  `devai.mcphub.downstream.DownstreamConnection`; the reviewed adapter file
  SHA-256 is
  `2971b73f96ffc050df5437edad5e32c5c5b29e4dd86654f5f620ae0467793ad5`.
- AgentGateway v1.4.1 is built from commit
  `163ea2146acb7b82082acea30ed691b29079095f`. Its MCP merge implementation
  returns the first page from each target without an aggregate cursor, while
  its call resolver follows upstream cursors with a 64-page bound.
- PyPI contained neither mcp 1.34 nor mcp 1.34.0. Version 1.34 is not a
  valid SDK target and must not appear in dependencies or support claims.
- Tesserix had published the dated 20260829 Python 3.14 runtime and ADK base
  images. Their observed digests were:
  - base-python-runtime-3.14:
    sha256:3854f5d9d00705b14077bf6715feb9c3bd6d1ad2e41d5594b3c09c0a74c22add
  - base-python-adk-3.14:
    sha256:5a6fd1863ed7f37f3929cc596d0ec063c3077c11713cd334f14d1df2b30ef386

The package version and protocol revision are different dimensions. A Python
SDK v1 client can speak the 2025-11-25 handshake protocol to a server
implemented by SDK v2. A Python SDK v2 client can use either the modern
2026-07-28 mode or the legacy handshake mode.

## Decision

Runtime container images use CPython 3.14. Library metadata supports CPython
3.12, 3.13, and 3.14 so local tooling and adopters can migrate independently
of the production image. Dropping a supported Python minor is a breaking
compatibility decision.

The server package declares:

    requires-python = ">=3.12,<3.15"
    dependencies = ["mcp>=2.1.1,<3"]

The lower bound is the first supported v2 release with the accepted
2026-07-28 and legacy dual-era behavior. The upper bound prevents an
unreviewed SDK v3 API migration. uv.lock pins the exact tested v2 release and
its transitive hashes.

Three exact client lanes are release requirements:

| Lane | Python SDK | Expected protocol evidence | Purpose |
|---|---:|---|---|
| DevAI SDK | 1.28.1 | 2025-11-25 | Preserve the exact SDK used by DevAI |
| Maintained v1 | 1.29.1 | 2025-11-25 | Detect regressions against the patched v1 line |
| Current v2 | 2.1.1 | 2026-07-28 and 2025-11-25 | Exercise modern and legacy paths in the current client |

Each lane uses an independent PEP 723 script and uv lock. Every client must
initialize, validate capabilities, list tools, call a structured tool, cancel
active work, receive a tool failure, close, and reconnect. Exact versions,
observed revisions, operations, artifact surface, and transport are emitted as
bounded JSON and JUnit. A separate negative probe requires unsupported modern
protocol initialization to fail with error `-32022`.

The compatibility server is a test fixture bound to loopback without
authentication. It must never be deployed or used as the production runtime.
The production transport and identity boundary arrive in their owning issues.

## Artifact and gateway evidence

Compatibility is a property of the published shape, not the checkout. The
release gate therefore runs the exact clients against three surfaces:

1. a server started by an isolated environment containing only the built
   runtime wheel and its dependencies;
2. the built, verified core image directly over loopback;
3. the same image through digest-pinned AgentGateway v1.4.1.

The real DevAI adapter runs only on the third surface from a fresh checkout at
the reviewed commit and its frozen environment. MCP Inspector 2.4.0 runs
against both image routes. The hand-written reverse proxy previously used as a
path smoke test is not compatibility evidence and has been removed.

AgentGateway's first-page merge behavior is recorded as
`agentgateway_pagination`, not reported as successful end-to-end pagination.
Direct wheel and image lanes must still traverse both server pages. Gateway
lanes must observe one page with no cursor and then successfully invoke the
tool deliberately placed on the hidden second page. This distinguishes a
known gateway feature gap from a regression in initialization, routing, calls,
cancellation, errors, closure, or reconnect.

DevAI's adapter also calls `list_tools()` only once. Its lane records a
separate pagination feature gap and proves the adapter can discover the
first-page `echo` tool, invoke it, close, and reconnect.

## CI bounds and threat model

One run contains 13 matrix cases and two Inspector surfaces. Each client
process has a 60-second timeout, the workflow has a 30-minute hard limit,
client JSON is capped at 64 KiB, aggregate matrix evidence at 256 KiB, and
retention at seven days. There is no persistent service, datastore, or cloud
resource, so recurring cost is bounded to one GitHub-hosted job per trigger.
The release-gate objective is a deterministic pass on every pull request,
release-candidate tag, main update, weekly schedule, and manual run; it is not
a production availability SLO.

Assets worth protecting are CI credentials, dependency integrity, and any
future tool/session data. Threats are an untrusted pull request, a compromised
dependency or container, and accidental logging. The trust boundaries are the
fresh DevAI checkout, isolated client processes, Docker network, and retained
artifact directory. Actions and images are immutable pins, downloaded Compose
is checksum-verified, clients receive an allowlisted environment, ports bind
only to loopback, and containers are non-root/read-only/capability-dropped.
No credentials are mounted into the stack. Raw gateway session logs and tool
payloads are not retained; the evidence scanner rejects bearer tokens, secret
assignments, or oversized surfaces before upload.

## Legacy-session consequence

SDK v2 routes modern and legacy requests through the same Streamable HTTP
application. Modern 2026-07-28 requests are sessionless. Legacy clients use an
initialize handshake and, by default, in-process sessions. Multiple workers
therefore require sticky routing unless the server chooses stateless legacy
HTTP and accepts losing legacy back-channel behavior.

The compatibility matrix uses one runtime replica per artifact surface, so it
proves protocol interoperability and AgentGateway session forwarding without
deciding a multi-replica production session policy. A disconnect must cancel
the active handler on direct and gateway routes; a fresh connection must then
initialize and list successfully. A timeout, dropped stream, or lost gateway
session therefore fails the exact client, protocol, and operation JUnit case.

## Update policy

1. Dependabot opens weekly Python dependency PRs and monthly GitHub Actions
   PRs. Automatic merge is forbidden.
2. Every dependency PR runs the frozen server lock, all three frozen client
   locks, package build, import smoke test, and compatibility matrix.
3. A new v2 patch or minor updates the project lock and current-v2 script lock.
   The minimum bound changes only when the runtime uses behavior unavailable
   in the old minimum.
4. A new maintained v1 release updates the maintained-v1 script and support
   matrix after it passes against the same server.
5. DevAI 1.28.1 remains until DevAI changes its checked-in dependency. Its SDK
   and real-adapter lanes are removed only after downstream migration evidence,
   two green release candidates, a reviewed compatibility change, and at least
   90 days' notice.
6. SDK v3 requires a new ADR, a parallel server adapter or migration branch,
   and an overlap period. The less-than-3 bound does not move automatically.
7. The required Compatibility / MCP SDK matrix check protects main. Scheduled
   weekly runs catch upstream yanks or environment changes even without a PR.
8. Release-candidate tags run the same artifact matrix. A failure blocks the
   release; bypassing or weakening a lane requires a reviewed ADR update.

Current means the newest reviewed release in the committed lock and matrix,
not whatever PyPI returns during a build.

## Emergency pin, yank, and rollback

For a security advisory or breaking upstream release:

1. reproduce the failure in the compatibility lane;
2. tighten the affected lower bound or add the narrow upstream exclusion;
3. regenerate only affected locks and retain their hashes;
4. run all client lanes and build/install smoke tests;
5. release a patched runtime and advisory;
6. keep the last known-good wheel and image digest available for rollback.

If a locked artifact is yanked, builds fail rather than silently selecting a
different release. A reviewed lock update restores builds. Existing published
runtime artifacts remain immutable.

Rollback reverts pyproject.toml, uv.lock, the affected script lock, and support
matrix together. A partial version rollback is invalid because documentation
and executable evidence would disagree.

## Alternatives considered

### Depend on unbounded mcp latest

Rejected. A clean build could change without a source revision, and an SDK
major could break imports before compatibility evidence exists.

### Stay on SDK v1 because DevAI uses it

Rejected. Server and client SDK API versions need not match. The v2 server
officially supports legacy protocol clients, and real compatibility tests
prove the boundary without freezing new server development on v1.

### Support only Python 3.14 in package metadata

Rejected for the initial library. The official SDK supports older Python, and
3.12 through 3.14 support costs little while products migrate. Runtime images
remain standardized on 3.14.

### Claim support for MCP SDK 1.34

Rejected because that package version does not exist.

### Use a hand-written proxy as gateway evidence

Rejected. A path-rewriting proxy cannot exercise AgentGateway's initialization,
catalog merge, target resolution, streaming cancellation, or session behavior.
The real digest-pinned image is small enough for the required CI lane.

## Consequences

The project carries three script locks in addition to the project lock. That
duplication is intentional because incompatible SDK majors cannot coexist in
one environment. Shared v1 client behavior and evidence encoding each live in
one reusable module, while every executable lane owns only its exact dependency
declaration. DevAI retains its own authoritative frozen lock.

Compatibility failures block dependency updates and releases. This costs CI
time but keeps the released lock reproducible and separates SDK API migration
from wire-protocol compatibility. The gateway pagination limitation is visible
to consumers and must be revisited when the pinned AgentGateway version changes.
Rollback is one Git revert plus reuse of the last immutable wheel/image digest;
the compatibility stack itself has no state to migrate or restore.

## References

- [PyPI mcp project](https://pypi.org/project/mcp/)
- [Official Python SDK v2.1.1](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.1.1)
- [Maintained Python SDK v1 branch](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x)
- [Serving legacy clients](https://github.com/modelcontextprotocol/python-sdk/blob/v2.1.1/docs/run/legacy-clients.md)
- [Tesserix Python 3.14 images](https://github.com/tesserix/base-docker-images/pull/24)
- [Tesserix ADK v0.53.1](https://github.com/tesserix/agent-development-kit/releases/tag/v0.53.1)
- [DevAI pinned adapter](https://github.com/tesserix/devai/blob/850379a833bb5740c82eb2a16cac452ff93695f0/src/devai/mcphub/downstream.py)
- [AgentGateway v1.4.1 MCP merge behavior](https://github.com/agentgateway/agentgateway/blob/163ea2146acb7b82082acea30ed691b29079095f/crates/agentgateway/src/mcp/handler.rs#L680-L745)
