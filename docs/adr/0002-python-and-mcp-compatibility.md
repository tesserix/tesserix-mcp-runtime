# ADR-0002: Python and MCP compatibility policy

- Status: Accepted
- Date: 2026-08-30
- Tracking: [tesserix-mcp-runtime#3](https://github.com/tesserix/tesserix-mcp-runtime/issues/3)
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
| DevAI | 1.28.1 | 2025-11-25 | Preserve the checked-in DevAI client |
| Maintained v1 | 1.29.1 | 2025-11-25 | Detect regressions against the patched v1 line |
| Current v2 | 2.1.1 | 2026-07-28 and 2025-11-25 | Exercise modern and legacy paths in the current client |

Each lane uses an independent PEP 723 script and uv lock. All connect to one
SDK v2.1.1 Streamable HTTP server process and must negotiate, list tools, call
a successful tool, receive a tool failure, and close. Exact versions and
observed revisions are emitted as machine-readable JSON.

The compatibility server is a test fixture bound to loopback without
authentication. It must never be deployed or used as the production runtime.
The production transport and identity boundary arrive in their owning issues.

## Legacy-session consequence

SDK v2 routes modern and legacy requests through the same Streamable HTTP
application. Modern 2026-07-28 requests are sessionless. Legacy clients use an
initialize handshake and, by default, in-process sessions. Multiple workers
therefore require sticky routing unless the server chooses stateless legacy
HTTP and accepts losing legacy back-channel behavior.

The compatibility matrix uses one server process, so it proves protocol
interoperability without deciding the production session policy. That
decision belongs to the bounded Streamable HTTP transport issue and must test
gateway routing explicitly.

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
5. DevAI 1.28.1 remains until DevAI changes its checked-in dependency. Its lane
   is removed only in a reviewed migration with downstream evidence.
6. SDK v3 requires a new ADR, a parallel server adapter or migration branch,
   and an overlap period. The less-than-3 bound does not move automatically.
7. The required Compatibility / MCP SDK matrix check protects main. Scheduled
   weekly runs catch upstream yanks or environment changes even without a PR.

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

## Consequences

The project carries four small locks: one server and three client lanes, in
addition to the package lock. That duplication is intentional because
incompatible SDK majors cannot coexist in one environment. Shared v1 client
behavior lives in one module, while each executable lane owns only its exact
dependency declaration.

Compatibility failures block dependency updates and releases. This costs CI
time but keeps the released lock reproducible and separates SDK API migration
from wire-protocol compatibility.

## References

- [PyPI mcp project](https://pypi.org/project/mcp/)
- [Official Python SDK v2.1.1](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.1.1)
- [Maintained Python SDK v1 branch](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x)
- [Serving legacy clients](https://github.com/modelcontextprotocol/python-sdk/blob/v2.1.1/docs/run/legacy-clients.md)
- [Tesserix Python 3.14 images](https://github.com/tesserix/base-docker-images/pull/24)
- [Tesserix ADK v0.53.1](https://github.com/tesserix/agent-development-kit/releases/tag/v0.53.1)
