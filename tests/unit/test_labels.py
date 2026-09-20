
from itertools import product
from taintgate.labels import Integrity, Label

LABELS = [Label(i, r) for i, r in product(Integrity, [None, frozenset(), frozenset({'a'}), frozenset({'a', 'b'})])]


def test_commutative():
    for a, b in product(LABELS, repeat=2):
        assert a.join(b) == b.join(a)


def test_associative():
    for a, b, c in product(LABELS, repeat=3):
        assert a.join(b).join(c) == a.join(b.join(c))


def test_lattice_bounds():
    for a in LABELS:
        assert a.join(a) == a
    for a, b in product(LABELS, repeat=2):
        assert a.flows_to(a.join(b))
        assert b.flows_to(a.join(b))


def test_reader_edges():
    assert Label().may_read('anyone')
    assert not Label(readers=frozenset()).may_read('anyone')
    assert Label(readers={'a'}).join(Label(readers={'b'})).readers == frozenset()
    assert Label().join(Label(readers={'a'})).readers == frozenset({'a'})
