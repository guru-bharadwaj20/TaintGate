"""Downstream MCP adapters use a host-owned context, never wire labels."""

import json
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount


def plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain(v) for v in value]
    return value


def build_server(gateway: Any, context_provider: Any) -> Any:
    server = Server("taintgate")

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def tools() -> Any:
        return [types.Tool(**metadata) for metadata in gateway.list_tools()]

    @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
    async def call(name: Any, arguments: Any) -> Any:
        response = await gateway.call(name, arguments or {}, context=context_provider())
        payload = response.as_dict()
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(plain(payload)))],
            isError=response.status != "allow",
        )

    return server


async def serve_stdio(gateway: Any, context_provider: Any) -> Any:
    server = build_server(gateway, context_provider)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def http_app(gateway: Any, context_provider: Any) -> Any:
    server = build_server(gateway, context_provider)
    manager = StreamableHTTPSessionManager(server, stateless=True, json_response=True)

    @asynccontextmanager
    async def lifespan(app: Any) -> Any:
        async with manager.run():
            yield

    async def handle(scope: Any, receive: Any, send: Any) -> Any:
        await manager.handle_request(scope, receive, send)

    return Starlette(routes=[Mount("/mcp", app=handle)], lifespan=lifespan)
