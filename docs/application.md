# Compose and run an application

`Application` is the only composition root. Construct one instance per server
with explicit dependencies; construction does not bind a listener or install a
signal handler.

```python
import asyncio
import json
import sys

from tesserix_mcp_runtime import (
    Application,
    ApplicationLimits,
    SystemClock,
)
from tesserix_mcp_runtime.adapters.in_process import InProcessTransport
from tesserix_mcp_runtime.adapters.process_signals import ProcessSignalSource

# catalog is a validated ToolCatalog.
# Use ToolPolicy for the production default-deny authorizer.
# telemetry accepts ScrubbedError values and never receives tool payloads.
application = Application(
    catalog=catalog,
    authorizer=authorizer,
    transport=InProcessTransport(),
    telemetry=telemetry,
    limits=ApplicationLimits(drain_timeout=20.0, readiness_timeout=1.0),
    clock=SystemClock(),
    readiness_checks=(registry_check, backing_api_check),
)

result = asyncio.run(application.run(ProcessSignalSource()))
if result.diagnostic is not None:
    print(json.dumps(result.diagnostic.to_dict(), sort_keys=True), file=sys.stderr)
raise SystemExit(result.exit_code)
```

The catalog example in [Runtime contracts](contracts.md#define-and-register-a-tool)
defines a complete typed tool. Production transports arrive in issue #10; the
in-process transport above binds no socket and is intended for deterministic
composition, conformance, and smoke tests.

## Explicit dependencies

| Dependency | Responsibility when unavailable or invalid |
|---|---|
| `ToolCatalog` | Reject malformed or duplicate definitions before readiness |
| `Authorizer` | Fail closed immediately before handler execution |
| `ApplicationTransport` | Bind last, reject after drain begins, stop first |
| `Telemetry[ScrubbedError]` | Receive no payloads; sink failures are counted without changing the client result |
| `ApplicationLimits` | Supply the positive finite global drain duration |
| readiness checks | Return dependency ability to accept new work inside the bounded readiness timeout; never participate in liveness |
| `Clock` | Supply monotonic time and cancellable deadline waits |
| lifecycle tuple | Start in order and unwind in reverse |

`Application.state` progresses from `startup` to `ready`, `draining`, and
`stopped`. `list_tools()` and `invoke()` accept work only while ready. Drain
sets the state before its first hook, so a concurrent second call cannot enter.
Accepted work may finish until the deadline; remaining tasks are cancelled and
joined before the deadline failure returns.

`startup_status()`, `liveness_status()`, `readiness_status()`, and
`render_metrics()` form the typed operational endpoint used by HTTP transports.
Readiness is true only in lifecycle `ready` after every configured check returns
exactly `True`. Checks run concurrently within a one-second default and
five-second hard maximum. False, timeout, or exception returns false and emits
only a stable reason. Liveness is dependency-free.

## Manual lifecycle in tests

Tests can drive the same state machine without process signals:

```python
transport = InProcessTransport()
application = Application(
    catalog=catalog,
    authorizer=authorizer,
    transport=transport,
    telemetry=telemetry,
    limits=ApplicationLimits(drain_timeout=5.0),
    clock=fake_clock,
)

await application.start()
result = await transport.invoke(tool_name, arguments, context=trusted_context)
await application.drain()
await application.stop()
```

Use a fresh transport per application. Two instances share no mutable state.
Only one `ProcessSignalSource` should own SIGINT/SIGTERM in a process; drive
additional application instances from the same process-level shutdown event.
An invalid configuration raises `ApplicationConfigurationError` before
transport start. A global drain or stop deadline raises
`ApplicationDeadlineExceeded`. `run()` converts lifecycle and signal failures
to exit code 1 plus a payload-free `ApplicationDiagnostic`, and always attempts
stop after a post-readiness failure.

For non-ADK production tools, compose the concrete
[`ToolPolicy`](tool-policy.md). It filters experimental or disabled tools from
both listings and manifests, enforces exact review, scopes, effect,
idempotency, and approval before the handler, and appends payload-free policy
decisions. Structural test authorizers remain supported for existing read-only
fixtures. The ADK bridge keeps ADK's own policy authority.
