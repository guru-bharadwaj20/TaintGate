import pytest

from taintgate.labels import Label, Labeled, Provenance


@pytest.mark.parametrize("readers", [{""}, {1}])
def test_invalid_principals_fail_closed(readers):
    with pytest.raises(ValueError):
        Label(readers=readers)


def test_host_objects_are_not_runtime_values():
    with pytest.raises(TypeError):
        Labeled(object())


def test_source_nodes_do_not_alias_mutable_parent_sets():
    parents = {"root"}
    node = Provenance("lookup", parents)
    identity = node.id
    parents.add("tampered")
    assert node.parents == frozenset({"root"})
    assert node.id == identity
    assert Provenance.union({"a"}, {"b"}) == frozenset({"a", "b"})


def test_invalid_provenance_has_no_identity():
    with pytest.raises(ValueError):
        Provenance("")
    with pytest.raises(ValueError):
        Provenance("lookup", {""})
