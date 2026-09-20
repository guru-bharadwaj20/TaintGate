import pytest
from taintgate.gateway.metadata import Contract


def test_contract_identity_is_local():
    contract = Contract("mail", "read", "Read mail", {"type": "object"})
    assert contract.planner_metadata()["name"] == "mail__read"
    with pytest.raises(ValueError):
        Contract("mail__other", "../read", "", {})
