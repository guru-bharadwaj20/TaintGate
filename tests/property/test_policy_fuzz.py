from hypothesis import given, settings
from hypothesis import strategies as st

from taintgate.policy import PolicyError
from taintgate.policy.parser import parse


@given(st.text(max_size=300))
@settings(max_examples=200, deadline=None)
def test_policy_parser_arbitrary_input(text):
    try:
        result = parse(text)
    except PolicyError:
        return
    assert len(result.facts) + len(result.rules) <= 2000
