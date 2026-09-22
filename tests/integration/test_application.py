import asyncio

from taintgate.application import Invocation
from taintgate.demo import demo, make_demo
from taintgate.labels import Label, Labeled


def test_trusted_send_and_injected_email():
    result = asyncio.run(demo())
    assert result["trusted_status"] == "completed"
    assert result["attack_status"] == "tool_denied"
    assert len(result["recorded_sends"]) == 1
    assert result["audit_valid"]


def test_gateway_context_cannot_be_forged_or_arguments_swapped():
    app, _ = make_demo()
    assert app._gateway_authorize({}, "email__send", {}) == "deny"
    call = Invocation("email__send", {"to": Labeled("manager@example.org")}, Label())
    assert app._gateway_authorize(call, "email__send", {"to": "evil@example.net"}) == "deny"
    app.audit.close()
    app.gateway.guard.pins.close()
