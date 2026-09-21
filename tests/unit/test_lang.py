import pytest
from taintgate.lang import parse_plan, PlanError


@pytest.mark.parametrize('source', ['import os', 'while True: pass', 'def f(): pass', 'class C: pass', 'x = lambda: 1'])
def test_forbidden_execution(source):
    with pytest.raises(PlanError):
        parse_plan(source)


@pytest.mark.parametrize('source', ['try:\n x = 1\nexcept:\n x = 2', 'raise ValueError()', 'assert True'])
def test_forbidden_exceptions(source):
    with pytest.raises(PlanError):
        parse_plan(source)


def test_accepted():
    parse_plan('x = [1, 2]\nfor y in x:\n if y > 0:\n  send(f"value {y}")', {'send'})


@pytest.mark.parametrize('source', ['x.__class__', 'eval("1")', 'x[1:2]', '[x for x in y]', 'x.a()', 'a, b = [1,2]', '{**x}', 'f"{x!r}"', 'send(**x)'])
def test_rejection_boundaries(source):
    with pytest.raises(PlanError):
        parse_plan(source, {'send'})


def test_limits():
    with pytest.raises(PlanError):
        parse_plan('x = "abcd"', max_literal=2)
    with pytest.raises(PlanError):
        parse_plan('x = 1', max_bytes=2)
    with pytest.raises(PlanError):
        parse_plan('x = [[[[1]]]]', max_depth=3)
