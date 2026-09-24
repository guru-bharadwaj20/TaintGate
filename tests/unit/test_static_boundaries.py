import pytest

from taintgate.labels import Label
from taintgate.static import AbstractValue, Analyzer, describe_argument


def test_reader_universe_rejects_unconfigured_principal():
    with pytest.raises(ValueError, match="principal universe"):
        Analyzer(principals={"owner"}).analyze(
            "x = secret", {"secret": AbstractValue(Label(readers={"unknown"}))}
        )
    with pytest.raises(ValueError, match="principal universe"):
        Analyzer({"read": Label(readers={"unknown"})}, {"owner"}).analyze("x = read()")
    with pytest.raises(ValueError, match="Invalid principal"):
        Analyzer(principals={""})


def test_preflight_string_methods_and_missing_names_stay_conservative():
    result = Analyzer().analyze("x = missing.lower()")
    assert result.environment["x"].label.readers == frozenset()


def test_unknown_preflight_arguments_never_claim_a_runtime_value():
    known = describe_argument(AbstractValue(known="approved", resolved=True))
    unknown = describe_argument(AbstractValue(Label(readers={"owner"})))
    assert known == {"resolved": True, "value": "approved"}
    assert unknown["resolved"] is False
    assert "value" not in unknown
    assert unknown["readers"] == ["owner"]
