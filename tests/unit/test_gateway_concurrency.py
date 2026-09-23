import asyncio

import pytest

from taintgate.gateway.config import ServerConfig
from taintgate.gateway.core import Gateway
from taintgate.gateway.metadata import Contract, MetadataGuard, PinStore


def test_config_readers_cannot_be_accidental_string():
    with pytest.raises(ValueError):
        ServerConfig.from_dict({"name": "s", "readers": "owner"})


def test_pending_bound_and_cancellation():
    class Peer:
        calls = 0

        async def metadata(self):
            await asyncio.sleep(60)
            return {}

        async def call_tool(self, name, arguments):
            self.calls += 1

    async def run():
        pins = PinStore(":memory:")
        peer = Peer()
        gateway = Gateway(MetadataGuard(pins), lambda *args: "allow", max_pending=1)
        gateway.register(Contract("s", "read", "Read", {"type": "object"}), peer)
        first = asyncio.create_task(gateway.call_with_id(1, "s__read", {}, context=object()))
        await asyncio.sleep(0)
        assert (await gateway.call_with_id(2, "s__read", {}, context=object())).status == "deny"
        assert gateway.cancel(1)
        with pytest.raises(asyncio.CancelledError):
            await first
        assert peer.calls == 0 and not gateway.pending and gateway.active == 0
        pins.close()

    asyncio.run(run())
