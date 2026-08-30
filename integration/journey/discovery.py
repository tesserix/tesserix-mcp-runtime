from __future__ import annotations

from collections.abc import Mapping

from tesserix_mcp_publisher import PreparedPublication

from integration.journey.registry import decode_json_object
from tesserix_mcp_runtime import RegistryResolutionPolicy, RegistryToolRequirement

_READ_TOOL = "journey.read_order"


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError("journey discovery contract is invalid")
    return value


def journey_read_policy(prepared: PreparedPublication) -> RegistryResolutionPolicy:
    if not isinstance(prepared, PreparedPublication):
        raise TypeError("prepared must be a PreparedPublication")
    try:
        document = decode_json_object(
            prepared.registry_manifest,
            maximum=1024 * 1024,
        )
        specification = _mapping(document.get("spec"))
        extension = _mapping(specification.get("x-tesserix"))
        tools = extension.get("tools")
        if not isinstance(tools, list) or not 1 <= len(tools) <= 128:
            raise ValueError
        matches = [
            _mapping(tool)
            for tool in tools
            if isinstance(tool, dict) and tool.get("name") == _READ_TOOL
        ]
        if len(matches) != 1:
            raise ValueError
        tool = matches[0]
        input_fingerprint = tool.get("inputFingerprint")
        output_fingerprint = tool.get("outputFingerprint")
        if not isinstance(input_fingerprint, str) or not isinstance(
            output_fingerprint,
            str,
        ):
            raise ValueError
        requirement = RegistryToolRequirement(
            name=_READ_TOOL,
            expected_input_fingerprint=input_fingerprint,
            expected_output_fingerprint=output_fingerprint,
        )
    except (KeyError, RuntimeError, TypeError, ValueError):
        raise ValueError("journey discovery contract is invalid") from None
    return RegistryResolutionPolicy(
        server_name="journey",
        gateway_origin="https://gateway.journey.invalid",
        supported_protocol_versions=("2025-11-25",),
        required_capabilities=("cap/order-read",),
        tool_allow=(_READ_TOOL,),
        tool_requirements=(requirement,),
        max_tools=6,
        max_schema_bytes=64 * 1024,
    )


__all__ = ["journey_read_policy"]
