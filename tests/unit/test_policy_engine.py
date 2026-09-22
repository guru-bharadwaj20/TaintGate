import pytest
from taintgate.policy import Atom, PolicyError
from taintgate.policy.engine import Engine
from taintgate.policy.decisions import decide, approval_facts
from taintgate.policy.defaults import policy_for_tools
from taintgate.policy.parser import parse
from taintgate.policy.strata import stratify

@pytest.mark.parametrize('extra,expected', [('', 'allow'), ('ask("x").','ask'), ('deny("x"). ask("x").','deny')])
def test_precedence(extra, expected):
    evaluation = Engine('allow("x"). '+extra).evaluate()
    decision = decide(evaluation, 'x')
    assert decision.action == expected
    assert decision.reasons[0]['rule'] == 'input fact'

def test_negation():
    evaluation = Engine('p(1). p(2). q(2). r(X) :- p(X), not q(X).').evaluate()
    assert Atom('r', (1,)) in evaluation.facts
    assert Atom('r', (2,)) not in evaluation.facts

def test_negative_cycle():
    with pytest.raises(PolicyError):
        stratify(parse('p(X) :- seed(X), not q(X). q(X) :- p(X).'))

def test_security_defaults():
    engine = Engine(policy_for_tools(['send']))
    for marker in ('untrusted_recipient', 'reader_denied', 'untrusted_control'):
        result = engine.evaluate([Atom('call', ('x','send')), Atom(marker, ('x',))])
        assert decide(result, 'x').action == 'deny'
    result = engine.evaluate([Atom('call', ('x','send')), *approval_facts('x','send',{'amount':2000})])
    assert decide(result, 'x').action == 'ask'

def test_bounded_explanation():
    result = Engine('p(1). q(X) :- p(X). r(X) :- q(X).').evaluate()
    assert result.explain(Atom('r',(1,)), max_depth=1)['supports'][0]['truncated']
