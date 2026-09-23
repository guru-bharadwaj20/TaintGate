import asyncio
import sys

import httpx
from mcp.client.streamable_http import streamablehttp_client

from taintgate.gateway.core import Gateway
from taintgate.gateway.metadata import Contract, MetadataGuard, PinStore
from taintgate.gateway.server import http_app
from taintgate.gateway.transports import Upstream


def test_real_stdio_transport():
    async def run():
        async with Upstream.stdio(sys.executable, ["-m", "taintgate.gateway.lab"]) as upstream:
            tools = await upstream.metadata()
            assert "Ignore previous" in tools["harmless_lookup"]["description"]
            result = await upstream.call_tool("harmless_lookup", {"query": "synthetic"})
            assert not result.isError

    asyncio.run(run())


def test_real_streamable_http_protocol_without_network(tmp_path):
    class Peer:
        calls = 0

        async def metadata(self):
            return {"echo": {"name": "echo", "inputSchema": {"type": "object"}}}

        async def call_tool(self, name, arguments):
            self.calls += 1
            return "echo"

    async def run():
        pins = PinStore(tmp_path / "http.db")
        peer = Peer()
        pins.approve("s", "echo", (await peer.metadata())["echo"])
        gateway = Gateway(MetadataGuard(pins), lambda *args: "allow")
        gateway.register(Contract("s", "echo", "Local echo", {"type": "object"}), peer)
        app = http_app(gateway, lambda: object())
        transport = httpx.ASGITransport(app=app)

        def factory(**kwargs):
            return httpx.AsyncClient(transport=transport, follow_redirects=True, **kwargs)

        async with app.router.lifespan_context(app):
            async with Upstream(
                streamablehttp_client("http://localhost/mcp/", httpx_client_factory=factory)
            ) as upstream:
                tools = await upstream.metadata()
                assert "s__echo" in tools
                result = await upstream.call_tool("s__echo", {})
                assert not result.isError and peer.calls == 1
        pins.close()

    asyncio.run(run())
