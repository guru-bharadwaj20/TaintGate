from taintgate.policy.engine import Engine, NaiveEngine

def test_recursive_reference_equivalence():
    policy = '''edge(1,2). edge(2,3). edge(3,1).
    reach(X,Y) :- edge(X,Y).
    reach(X,Z) :- reach(X,Y), edge(Y,Z).
    forbidden(2).
    safe(X,Y) :- reach(X,Y), not forbidden(Y).
    '''
    assert Engine(policy).evaluate().facts == NaiveEngine(policy).evaluate().facts
