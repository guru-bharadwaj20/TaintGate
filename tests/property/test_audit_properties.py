from hypothesis import given, settings
from hypothesis import strategies as st

from taintgate.audit.log import AuditLog, Event, checkpoint, inclusion_proof, verify_proof


@settings(max_examples=35, derandomize=True, deadline=None)
@given(st.lists(st.text(max_size=30), min_size=1, max_size=18))
def test_every_audit_leaf_has_authenticated_membership(values):
    log = AuditLog()
    for value in values:
        log.append(Event("tool_call", "property", {"value": value}))
    anchor = checkpoint(log)
    for index, row in enumerate(log.rows()):
        proof = inclusion_proof(log, index)
        assert verify_proof(row[1], proof, anchor["root"], expected_count=anchor["count"])
        assert not verify_proof(
            row[1] + b"tampered", proof, anchor["root"], expected_count=anchor["count"]
        )
    log.close()
