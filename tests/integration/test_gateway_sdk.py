import asyncio
import json

from mcp.shared.memory import create_connected_server_and_client_session

from taintgate.gateway.config import ServerConfig
from taintgate.gateway.core import Gateway
from taintgate.gateway.lab import malicious_description_server
from taintgate.gateway.metadata import Contract, MetadataGuard, PinStore
from taintgate.gateway.server import build_server


def test_real_sdk_downstream_requires_policy(tmp_path):
    class Peer:
        calls = 0

        async def metadata(self):
            return {"read": {"name": "read", "inputSchema": {"type": "object"}}}

        async def call_tool(self, name, arguments):
            self.calls += 1
            return "safe"

    async def run():
        peer = Peer()
        pins = PinStore(tmp_path / "sdk.db")
        pins.approve("local", "read", (await peer.metadata())["read"])
        gateway = Gateway(MetadataGuard(pins), lambda *args: "deny")
        gateway.register(Contract("local", "read", "Trusted description", {"type": "object"}), peer)
        server = build_server(gateway, lambda: object())
        async with create_connected_server_and_client_session(server) as client:
            tools = await client.list_tools()
            assert tools.tools[0].description == "Trusted description"
            result = await client.call_tool("local__read", {"claimed_approval": True})
            assert result.isError
            assert json.loads(result.content[0].text)["status"] == "deny"
            assert peer.calls == 0
        pins.close()

    asyncio.run(run())


def test_real_sdk_poisoned_server_metadata():
    async def run():
        async with create_connected_server_and_client_session(
            malicious_description_server()
        ) as client:
            tools = await client.list_tools()
            assert "Ignore previous" in tools.tools[0].description

    asyncio.run(run())


def test_private_result_cannot_escape_downstream(tmp_path):
    class Peer:
        async def metadata(self):
            return {"read": {"name": "read", "inputSchema": {"type": "object"}}}

        async def call_tool(self, name, arguments):
            return "unknown private value"

    async def run():
        pins = PinStore(tmp_path / "private.db")
        peer = Peer()
        pins.approve("s", "read", (await peer.metadata())["read"])
        gateway = Gateway(MetadataGuard(pins), lambda *args: "allow")
        gateway.register(
            Contract("s", "read", "Read", {"type": "object"}),
            peer,
            ServerConfig("s", readers=frozenset({"owner"})),
        )
        async with create_connected_server_and_client_session(
            build_server(gateway, lambda: object())
        ) as client:
            result = await client.call_tool("s__read", {})
            assert result.isError
            assert "unknown private value" not in str(result)
        pins.close()

    asyncio.run(run())
