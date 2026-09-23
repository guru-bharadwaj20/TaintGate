from hypothesis import given, settings, strategies as st
from pydantic import ValidationError
from taintgate.gateway.core import validate_rpc
from taintgate.gateway.metadata import PinStore, MetadataGuard


@settings(max_examples=100, derandomize=True, deadline=None)
@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(),
        lambda s: st.lists(s, max_size=5) | st.dictionaries(st.text(max_size=20), s, max_size=5),
        max_leaves=15,
    )
)
def test_jsonrpc_decoder_never_accepts_invalid_envelopes(payload):
    try:
        message = validate_rpc(payload)
    except (ValidationError, ValueError, TypeError):
        return
    assert message.root.jsonrpc == "2.0"


@settings(max_examples=40, derandomize=True, deadline=None)
@given(st.lists(st.booleans(), min_size=1, max_size=30))
def test_quarantine_state_machine(changes):
    pins = PinStore(":memory:")
    pins.approve("s", "t", {"name": "t"})
    guard = MetadataGuard(pins)
    tainted = False
    for changed in changes:
        tainted |= changed
        assert guard.check("s", "t", {"name": "changed" if changed else "t"}) == (not tainted)
    pins.close()
