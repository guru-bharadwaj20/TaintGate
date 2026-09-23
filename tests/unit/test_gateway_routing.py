from taintgate.gateway.core import Gateway
from taintgate.gateway.metadata import Contract


def test_sessions_namespace_routing():
    gateway = Gateway(None)
    first, second = object(), object()
    gateway.register(Contract("first", "echo", "Echo", {}), first)
    gateway.register(Contract("second", "echo", "Echo", {}), second)
    assert gateway.servers["first"] is first
    assert gateway.servers["second"] is second
    assert set(gateway.contracts) == {"first__echo", "second__echo"}
