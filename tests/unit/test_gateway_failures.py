import asyncio
import pytest
from taintgate.gateway.core import Gateway
from taintgate.gateway.metadata import Contract, PinStore, MetadataGuard


class Peer:
    def __init__(self):
        self.calls = 0
        self.tools = {"echo": {"name": "echo", "description": "remote", "inputSchema": {"type": "object"}}}
        self.failure = False

    async def metadata(self):
        if self.failure:
            raise ConnectionError("private peer address")
        return self.tools

    async def call_tool(self, name, arguments):
        self.calls += 1
        return {"content": arguments}


def fixture(tmp_path, decision="allow"):
    pins = PinStore(tmp_path / "pins.db")
    peer = Peer()
    pins.approve("server", "echo", peer.tools["echo"])
    gateway = Gateway(MetadataGuard(pins), lambda ctx, name, args: decision)
    gateway.register(Contract("server", "echo", "Echo", {"type": "object"}), peer)
    return gateway, peer, pins


def test_disconnect_blocks_before_execution(tmp_path):
    gateway, peer, pins = fixture(tmp_path)
    peer.failure = True
    result = asyncio.run(gateway.call("server__echo", {}, context=object()))
    assert result.status == "deny" and peer.calls == 0
    assert "private" not in result.reason
    pins.close()


@pytest.mark.parametrize("decision", ["deny", "ask", None, True])
def test_policy_is_fail_closed(tmp_path, decision):
    gateway, peer, pins = fixture(tmp_path, decision)
    result = asyncio.run(gateway.call("server__echo", {}, context=object()))
    assert result.status in {"deny", "ask"} and peer.calls == 0
    pins.close()


def test_allowed_result_is_untrusted(tmp_path):
    gateway, peer, pins = fixture(tmp_path)
    result = asyncio.run(gateway.call("server__echo", {"x": "value"}, context=object()))
    assert result.status == "allow" and peer.calls == 1
    assert result.result.label.integrity.name == "UNTRUSTED"
    pins.close()
