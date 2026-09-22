import pytest

from taintgate.policy import Atom, PolicyError
from taintgate.policy.decisions import approval_facts, decide
from taintgate.policy.defaults import policy_for_tools
from taintgate.policy.engine import Engine
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

@pytest.mark.parametrize('engine_type', [Engine, __import__('taintgate.policy.engine', fromlist=['NaiveEngine']).NaiveEngine])
def test_intermediate_join_budget(engine_type):
    with pytest.raises(PolicyError):
        engine_type('a(1). a(2). b(X,Y,Z) :- a(X), a(Y), a(Z).', max_work=3).evaluate()
    with pytest.raises(PolicyError):
        engine_type('a(1). b(X) :- a(X).', max_facts=1).evaluate()
    with pytest.raises(PolicyError):
        engine_type('', max_facts=0).evaluate([Atom('a', (1,))])


def test_real_enum_nested_labels_and_pc():
    from taintgate.labels import Integrity, Label, Labeled
    from taintgate.policy.decisions import call_facts
    nested = Labeled({'item': Labeled('secret', Label(Integrity.UNTRUSTED, frozenset({'alice'})))})
    facts = call_facts('x', 'send', {'to': nested}, destination='bob', pc=Label(Integrity.UNTRUSTED))
    assert Atom('untrusted_recipient', ('x',)) in facts
    assert Atom('reader_denied', ('x',)) in facts
    assert Atom('untrusted_control', ('x',)) in facts
    with pytest.raises(PolicyError):
        call_facts('x', 'send', {'to': 'raw'})
