
from itertools import product
from taintgate.labels import Integrity, Label

LABELS = [Label(i, r) for i, r in product(Integrity, [None, frozenset(), frozenset({'a'}), frozenset({'a', 'b'})])]


def test_commutative():
    for a, b in product(LABELS, repeat=2):
        assert a.join(b) == b.join(a)


def test_associative():
    for a, b, c in product(LABELS, repeat=3):
        assert a.join(b).join(c) == a.join(b.join(c))
