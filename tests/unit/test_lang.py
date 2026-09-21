import pytest
from taintgate.lang import parse_plan, PlanError


@pytest.mark.parametrize('source', ['import os', 'while True: pass', 'def f(): pass', 'class C: pass', 'x = lambda: 1'])
def test_forbidden_execution(source):
    with pytest.raises(PlanError):
        parse_plan(source)
