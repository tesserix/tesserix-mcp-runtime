from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self

from mcp.client import Client
from mcp.server import MCPServer

from tesserix_mcp_runtime import (
    ApprovalRequirement,
    AuthenticatedIdentity,
    CallContext,
    ErrorCode,
    ErrorResponse,
    IdempotencyRequirement,
    InvocationResult,
    JsonValue,
    ToolEffect,
    ToolMetadata,
)
from tesserix_mcp_runtime.conformance import (
    ConformanceCase,
    assert_adapter_conforms,
)


@dataclass(frozen=True, slots=True)
class EchoInput:
    text: str


@dataclass(frozen=True, slots=True)
class EchoOutput:
    text: str


class EchoHandler:
    async def __call__(
        self,
        input_model: EchoInput,
        *,
        context: CallContext,
    ) -> EchoOutput:
        del context
        return EchoOutput(text=input_model.text)


@dataclass(frozen=True, slots=True)
class EchoDefinition:
    metadata: ToolMetadata
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    handler: EchoHandler

    def parse_input(self, arguments: Mapping[str, Any]) -> EchoInput:
        text = arguments["text"]
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        return EchoInput(text=text)

    def serialize_output(self, output_model: EchoOutput) -> dict[str, JsonValue]:
        return {"text": output_model.text}


def definition() -> EchoDefinition:
    schema = {
        "type": "object",
        "properties": {"text": {"type": "string", "maxLength": 128}},
        "required": ["text"],
        "additionalProperties": False,
    }
    return EchoDefinition(
        metadata=ToolMetadata(
            name="example.echo",
            title="Echo text",
            description="Return bounded synthetic text.",
            effect=ToolEffect.READ,
            approval=ApprovalRequirement.NOT_REQUIRED,
            idempotency=IdempotencyRequirement.NOT_APPLICABLE,
            required_scopes=("example:read",),
        ),
        input_schema=schema,
        output_schema=schema,
        handler=EchoHandler(),
    )


def call_context() -> CallContext:
    return CallContext(
        identity=AuthenticatedIdentity(
            tenant="tenant-example",
            subject="subject-example",
            issuer="https://identity.example.invalid",
            scopes=("example:read",),
        ),
        request_id="request-example",
        run_id="run-example",
    )


class InProcessAdapter:
    def __init__(self, tool: EchoDefinition, context: CallContext) -> None:
        self._tool = tool
        self._context = context

    async def list_tools(self) -> tuple[str, ...]:
        return (self._tool.metadata.name,)

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, Any],
    ) -> InvocationResult:
        if name != self._tool.metadata.name:
            return InvocationResult.failure(
                ErrorResponse.from_code(
                    ErrorCode.INVALID_INPUT,
                    request_id=self._context.request_id,
                )
            )
        try:
            input_model = self._tool.parse_input(arguments)
        except (KeyError, TypeError, ValueError):
            return InvocationResult.failure(
                ErrorResponse.from_code(
                    ErrorCode.INVALID_INPUT,
                    request_id=self._context.request_id,
                )
            )
        output = await self._tool.handler(input_model, context=self._context)
        return InvocationResult.success(self._tool.serialize_output(output))


class McpSdkAdapter(AbstractAsyncContextManager["McpSdkAdapter"]):
    def __init__(self, tool: EchoDefinition, context: CallContext) -> None:
        self._tool = tool
        self._context = context
        self._server = MCPServer("contract-conformance")

        async def _invoke_echo(text: str) -> dict[str, JsonValue]:
            input_model = tool.parse_input({"text": text})
            output = await tool.handler(input_model, context=context)
            return tool.serialize_output(output)

        self._server.tool(
            name=tool.metadata.name,
            title=tool.metadata.title,
            description=tool.metadata.description,
            structured_output=True,
        )(_invoke_echo)
        self._client = Client(self._server)

    async def __aenter__(self) -> Self:
        await self._client.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._client.__aexit__(exc_type, exc_value, traceback)

    async def list_tools(self) -> tuple[str, ...]:
        result = await self._client.list_tools()
        return tuple(tool.name for tool in result.tools)

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, Any],
    ) -> InvocationResult:
        result = await self._client.call_tool(name, dict(arguments))
        if result.is_error:
            return InvocationResult.failure(
                ErrorResponse.from_code(
                    ErrorCode.INVALID_INPUT,
                    request_id=self._context.request_id,
                )
            )
        return InvocationResult.success(result.structured_content)


def test_same_tool_passes_in_process_and_mcp_sdk_conformance() -> None:
    async def exercise() -> None:
        tool = definition()
        context = call_context()
        case = ConformanceCase(
            tool_name="example.echo",
            valid_arguments={"text": "hello"},
            expected_value={"text": "hello"},
            invalid_arguments={},
        )

        await assert_adapter_conforms(InProcessAdapter(tool, context), case)
        async with McpSdkAdapter(tool, context) as adapter:
            await assert_adapter_conforms(adapter, case)

    asyncio.run(exercise())
