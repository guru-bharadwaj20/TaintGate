import pytest

from taintgate.lang import PlanError, parse_plan


@pytest.mark.parametrize(
    "source",
    [
        'x = b"bytes"',
        "x = {1,2}",
        "x = [*items]",
        "_private = 1",
        'x = getattr(record, "secret")',
        "for x in []:\n y = 1\nelse:\n y = 2",
        "for x,y in []:\n z = x",
        'x = f"{value:2}"',
        "x = send().method()",
        "x = (",
    ],
)
def test_additional_language_boundaries(source):
    with pytest.raises(PlanError):
        parse_plan(source, {"send"})


def test_non_ascii_source_bound_is_measured_in_bytes():
    with pytest.raises(PlanError, match="byte limit"):
        parse_plan('x = "éé"', max_bytes=9)


def test_call_return_value_cannot_be_invoked():
    with pytest.raises(PlanError, match="Indirect calls"):
        parse_plan("send()[0]()", {"send"})
