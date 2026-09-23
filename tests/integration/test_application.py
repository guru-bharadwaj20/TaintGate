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


def test_exact_ask_scope_does_not_override_deny():
    from taintgate.policy.engine import Engine

    app, server = make_demo()
    app.policy += '\nask(C) :- call(C, "email__send").'
    app.engine = Engine(app.policy)
    source = 'email__send(to="manager@example.org", body="Explicit message")'
    first = asyncio.run(app.run(source))
    assert first.decisions[0]["action"] == "ask"
    assert not server.sent
    app.approve(first.decisions[0]["scope"], "Local explicit approval")
    second = asyncio.run(app.run(source))
    assert second.status == "completed"
    assert len(server.sent) == 1
    changed = asyncio.run(app.run(source.replace("Explicit message", "Different message")))
    assert changed.decisions[0]["action"] == "ask"
    assert len(server.sent) == 1
    app.audit.close()
    app.gateway.guard.pins.close()


def test_public_container_cannot_hide_confidential_children():
    from taintgate.application import public_tree

    value = Labeled({"secret": Labeled("private", Label(readers=frozenset({"alice"})))})
    assert not public_tree(value)


def test_destination_fields_and_conflicting_recipients_fail_closed():
    from taintgate.application import Invocation
    from taintgate.labels import Label, Labeled

    app, server = make_demo()
    confidential = Labeled("private report", Label(readers=frozenset({"email"})))
    for field in ("destination", "url"):
        call = Invocation(
            "email__send", {field: Labeled("evil.example"), "body": confidential}, Label()
        )
        assert app.decision(call).action == "deny"
    for args in (
        {"to": Labeled("alice"), "url": Labeled("evil.example")},
        {"to": Labeled(7)},
        {"recipient": Labeled("")},
    ):
        assert app.decision(Invocation("email__send", args, Label())).action == "deny"
    assert not server.sent
    app.audit.close()
    app.gateway.guard.pins.close()
