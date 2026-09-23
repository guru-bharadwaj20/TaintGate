"""Bounded paired-world checks; no timing/termination equivalence claim."""

import pytest
from hypothesis import given, settings, strategies as st

from taintgate.interp import Interpreter, RuntimeFault, Tool
from taintgate.labels import Integrity, Label, Labeled


def execute(plan, value, *, strict=True):
    actions = []

    def authorize(name, args, pc):
        return pc.integrity == Integrity.TRUSTED and all(
            arg.label.integrity == Integrity.TRUSTED and arg.label.may_read("outside")
            for arg in args.values()
        )

    vm = Interpreter({"send": Tool(lambda x: actions.append(x), Label())}, authorize, strict=strict)
    try:
        vm.run(plan, {"untrusted": Labeled(value, Label(Integrity.UNTRUSTED))})
    except RuntimeFault:
        pass
    return actions


PLANS = st.sampled_from(
    [
        'if untrusted:\n send("constant")',
        "x = 0\nif untrusted:\n x = 1\nsend(x)",
        'x = untrusted and True\nsend("constant")',
        "send(untrusted)",
        'for x in [untrusted]:\n send("constant")',
    ]
)
WORLDS = st.tuples(st.booleans(), st.booleans())


@given(PLANS, WORLDS)
@settings(max_examples=60, derandomize=True)
def test_bounded_paired_world_generator(plan, worlds):
    # Both worlds agree on trusted code, tool configuration and policy.
    first, second = worlds
    assert execute(plan, first) == execute(plan, second)


@given(st.text(max_size=80), st.text(max_size=80))
@settings(max_examples=100, derandomize=True)
def test_strict_protected_actions_ignore_payload(first, second):
    for plan in [
        "send(untrusted)",
        "x = [untrusted]\nsend(x)",
        'x = {"message": untrusted}\nsend(x)',
        'if untrusted:\n send("constant")',
    ]:
        assert execute(plan, first) == execute(plan, second) == []


def test_permissive_counterexample():
    plan = 'x = 0\nif untrusted:\n x = 1\nsend(x)'
    assert execute(plan, False, strict=False) == [0]
    assert execute(plan, True, strict=False) == []


@given(PLANS, st.booleans())
@settings(max_examples=50, derandomize=True)
def test_static_predicts_concrete_protected_taint(plan, payload):
    from taintgate.static import AbstractValue, Analyzer
    result = Analyzer({"send": Label()}).analyze(
        plan, {"untrusted": AbstractValue(Label(Integrity.UNTRUSTED))})
    seen = []
    vm = Interpreter({"send": Tool(lambda x: None)},
                     lambda name, args, pc: seen.append(pc) or True)
    vm.run(plan, {"untrusted": Labeled(payload, Label(Integrity.UNTRUSTED))})
    if seen:
        assert result.calls
        assert all(call.potentially_unsafe for call in result.calls)
