from hypothesis import given, strategies as st

from taintgate.labels import Integrity, Label

READERS = st.one_of(st.none(), st.frozensets(st.sampled_from(['owner', 'audit', 'outside'])))
LABELS = st.builds(Label, st.sampled_from(list(Integrity)), READERS)


@given(LABELS, LABELS, LABELS)
def test_generated_lattice_laws(a, b, c):
    assert a.join(b) == b.join(a)
    assert a.join(b).join(c) == a.join(b.join(c))
    assert a.join(a) == a
    assert a.flows_to(a.join(b))
    assert b.flows_to(a.join(b))


@given(LABELS, LABELS)
def test_generated_mixing_never_adds_readers(a, b):
    joined = a.join(b)
    for principal in ['owner', 'audit', 'outside']:
        if joined.may_read(principal):
            assert a.may_read(principal)
            assert b.may_read(principal)
