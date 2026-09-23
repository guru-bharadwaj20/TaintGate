import asyncio
import sys

from taintgate.gateway.transports import Upstream


def test_real_stdio_transport():
    async def run():
        async with Upstream.stdio(sys.executable, ["-m", "taintgate.gateway.lab"]) as upstream:
            tools = await upstream.metadata()
            assert "Ignore previous" in tools["harmless_lookup"]["description"]
            result = await upstream.call_tool("harmless_lookup", {"query": "synthetic"})
            assert not result.isError
    asyncio.run(run())
