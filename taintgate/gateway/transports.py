"""Official SDK owns framing, request IDs, cancellation and transport parsing."""
from contextlib import AsyncExitStack
from mcp import ClientSession


class Upstream:
    def __init__(self, transport):
        self.transport = transport
        self.stack = AsyncExitStack()

    async def __aenter__(self):
        try:
            streams = await self.stack.enter_async_context(self.transport)
            self.session = await self.stack.enter_async_context(ClientSession(streams[0], streams[1]))
            await self.session.initialize()
            return self
        except BaseException:
            await self.stack.aclose()
            raise

    async def __aexit__(self, *exc):
        await self.stack.aclose()

    async def metadata(self):
        tools, cursor = {}, None
        while True:
            result = await self.session.list_tools(cursor=cursor)
            for tool in result.tools:
                if tool.name in tools:
                    raise ValueError("Duplicate upstream tool")
                tools[tool.name] = tool.model_dump(by_alias=True, exclude_none=True)
            cursor = result.nextCursor
            if not cursor:
                return tools

    async def call_tool(self, name, arguments):
        return await self.session.call_tool(name, arguments)
