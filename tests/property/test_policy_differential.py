from taintgate.policy.engine import Engine, NaiveEngine

def test_recursive_reference_equivalence():
    policy = '''edge(1,2). edge(2,3). edge(3,1).
    reach(X,Y) :- edge(X,Y).
    reach(X,Z) :- reach(X,Y), edge(Y,Z).
    forbidden(2).
    safe(X,Y) :- reach(X,Y), not forbidden(Y).
    '''
    assert Engine(policy).evaluate().facts == NaiveEngine(policy).evaluate().facts

def test_random_stratified_reference_equivalence():
    import random
    for seed in range(100):
        rng = random.Random(seed)
        edges = [f'edge({x},{y}).' for x in range(6) for y in range(6) if rng.random() < .18]
        excluded = [f'excluded({x}).' for x in range(6) if rng.random() < .3]
        policy = '\n'.join(edges + excluded) + '''
        reach(X,Y) :- edge(X,Y).
        reach(X,Z) :- reach(X,Y), edge(Y,Z).
        eligible(X,Y) :- reach(X,Y), not excluded(Y).
        reversed(Y,X) :- eligible(X,Y).
        '''
        assert Engine(policy).evaluate().facts == NaiveEngine(policy).evaluate().facts, seed
