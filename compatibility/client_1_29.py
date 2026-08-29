# /// script
# requires-python = ">=3.12,<3.15"
# dependencies = ["mcp==1.29.1"]
# ///
from __future__ import annotations

import asyncio

from client_v1 import exercise

if __name__ == "__main__":
    asyncio.run(exercise("1.29.1", "maintained-v1"))
