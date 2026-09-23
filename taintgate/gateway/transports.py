"""Official SDK owns framing, request IDs, cancellation and transport parsing."""

from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client


class Upstream:
    @classmethod
    def http(cls, url: Any, headers: Any = None) -> Any:
        return cls(streamablehttp_client(url, headers=headers))

    @classmethod
    def stdio(cls, command: Any, args: Any = (), env: Any = None) -> Any:
        return cls(stdio_client(StdioServerParameters(command=command, args=list(args), env=env)))

    def __init__(self, transport: Any) -> None:
        self.transport = transport
        self.stack = AsyncExitStack()

    async def __aenter__(self) -> Any:
        try:
            streams = await self.stack.enter_async_context(self.transport)
            self.session = await self.stack.enter_async_context(
                ClientSession(streams[0], streams[1])
            )
            await self.session.initialize()
            return self
        except BaseException:
            await self.stack.aclose()
            raise

    async def __aexit__(self, *exc: Any) -> Any:
        await self.stack.aclose()

    async def metadata(self) -> Any:
        tools: dict[str, Any] = {}
        cursor: str | None = None
        while True:
            result = await self.session.list_tools(cursor=cursor)
            for tool in result.tools:
                if tool.name in tools:
                    raise ValueError("Duplicate upstream tool")
                tools[tool.name] = tool.model_dump(by_alias=True, exclude_none=True)
            cursor = result.nextCursor
            if not cursor:
                return tools

    async def call_tool(self, name: Any, arguments: Any) -> Any:
        return await self.session.call_tool(name, arguments)
