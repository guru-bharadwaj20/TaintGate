import pytest

from taintgate.gateway.metadata import Contract, canonical_metadata


def test_contract_identity_is_local():
    contract = Contract("mail", "read", "Read mail", {"type": "object"})
    assert contract.planner_metadata()["name"] == "mail__read"
    with pytest.raises(ValueError):
        Contract("mail__other", "../read", "", {})


def test_rfc8785_vectors():
    assert canonical_metadata({"z": -0.0, "a": 1e30}) == b'{"a":1e+30,"z":0}'
    assert canonical_metadata({"\u20ac": 2, "\r": 1}) == b'{"\\r":1,"\xe2\x82\xac":2}'
    with pytest.raises(ValueError):
        canonical_metadata({"x": float("nan")})
