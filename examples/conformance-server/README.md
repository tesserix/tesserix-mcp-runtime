# External conformance server example

This separate project proves that a small server outside the testkit package can
inherit the published pytest contract. Its target uses the real runtime
`Application`, `ToolCatalog`, and `InProcessTransport`; it declares discovery
and invocation, so contract 1.0 passes two required cases and skips 22 optional
cases without pretending to implement them.

From this directory:

```bash
uv lock --check
uv run --frozen pytest
```

The project lock and pytest configuration disable network sockets while allowing
asyncio's local Unix socket pair. CI also builds both workspace wheels, installs
`tesserix-mcp-runtime[testkit]` into a fresh Python 3.14 environment with
`--offline`, changes into this directory, and runs the same suite from the
installed artifacts rather than editable source packages.

To adapt the example, keep `tests/test_conformance.py`, replace `EchoTool` with
the downstream server's real tool path, and declare only capabilities the target
actually observes. Optional cases will begin running as each capability is
implemented.
