import pytest

from taintgate.policy import Atom, PolicyError
from taintgate.policy.decisions import decide
from taintgate.policy.engine import NaiveEngine
from taintgate.policy.parser import parse


@pytest.mark.parametrize('text', [
    'allow(X).', 'allow(X) :- not deny(X).',
    'p(1). p(1,2).', 'p(f(1)).', 'p([1]).', 'not p(1).',
])
def test_invalid(text):
    with pytest.raises(PolicyError):
        parse(text)

def test_recursive_derivation():
    result = NaiveEngine('edge(1,2). edge(2,3). reach(X,Y) :- edge(X,Y). reach(X,Z) :- reach(X,Y), edge(Y,Z).').evaluate()
    assert Atom('reach', (1,3)) in result.facts

def test_default_deny():
    assert decide(NaiveEngine('allow("a").').evaluate(), 'b').action == 'deny'

def test_budget():
    with pytest.raises(PolicyError):
        NaiveEngine('p(1).', max_facts=0).evaluate()

def test_escaped_constants():
    assert parse('p("a\\n", -3).').facts[0].args == ('a\n', -3)
