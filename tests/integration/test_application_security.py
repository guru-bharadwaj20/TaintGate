"""Regressions for host approval context and implicit confidentiality."""

import asyncio
import hashlib

from taintgate.application import Invocation
from taintgate.demo import make_demo
from taintgate.labels import Label, Labeled


def test_private_control_cannot_select_public_send():
    app, server = make_demo()
    try:
        call = Invocation(
            "email__send",
            {"to": Labeled("manager@example.org"), "body": Labeled("public constant")},
            Label(readers={"owner"}),
        )
        assert app.decision(call).action == "deny"
        assert server.sent == []
    finally:
        app.audit.close()
        app.gateway.guard.pins.close()


def test_concurrent_runs_preserve_their_plan_approval_binding():
    from taintgate.policy.engine import Engine

    app, _ = make_demo()
    plans = {
        body: f'email__send(to="manager@example.org", body="{body}")'
        for body in ["first", "second"]
    }
    expected = {body: hashlib.sha256(plan.encode()).hexdigest() for body, plan in plans.items()}
    observed = []
    original_scope = app.scope

    def scope(call):
        observed.append((call.arguments["body"].value, app.plan_digest))
        return original_scope(call)

    app.scope = scope
    app.policy += '\nask(C) :- call(C, "email__send").'
    app.engine = Engine(app.policy)

    async def run_both():
        return await asyncio.gather(*(app.run(plan) for plan in plans.values()))

    try:
        results = asyncio.run(run_both())
        assert all(result.status == "tool_denied" for result in results)
        assert observed
        assert all(digest == expected[body] for body, digest in observed)
        assert results[0].decisions[0]["scope"] != results[1].decisions[0]["scope"]
    finally:
        app.audit.close()
        app.gateway.guard.pins.close()
