from taintgate.gateway.config import ServerConfig
from taintgate.gateway.core import Gateway


def test_result_sources_distinguish_payload_and_tool():
    gateway = Gateway(None)
    gateway.config["s"] = ServerConfig("s", readers=frozenset({"owner"}))
    first = gateway._label("s", "read", {"value": "first"})
    cached = gateway._label("s", "read", {"value": "first"})
    changed = gateway._label("s", "read", {"value": "changed"})
    other_tool = gateway._label("s", "other", {"value": "first"})
    assert first.sources == cached.sources
    assert len({first.sources, changed.sources, other_tool.sources}) == 3
    assert all(value.label.readers == {"owner"} for value in (first, cached, changed, other_tool))
