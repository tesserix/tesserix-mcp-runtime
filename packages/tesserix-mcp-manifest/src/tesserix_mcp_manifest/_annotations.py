from __future__ import annotations

from tesserix_mcp_manifest.constants import (
    DISCOVERY_ANNOTATION_PREFIX,
    REGISTRY_ANNOTATION_PREFIX,
)


def is_reserved_annotation(key: str) -> bool:
    return key.startswith((DISCOVERY_ANNOTATION_PREFIX, REGISTRY_ANNOTATION_PREFIX))


__all__ = ["is_reserved_annotation"]
