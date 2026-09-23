import pytest

from taintgate.audit.log import AuditLog, Event, checkpoint, inclusion_proof, verify_proof


@pytest.mark.parametrize("payload", [123, "corrupted TEXT payload", None])
def test_corrupt_row_verification_fails_closed(payload):
    log = AuditLog()
    log.append(Event("run_start", "run", {}))
    if payload is None:
        log.connection.execute("UPDATE events SET digest='not-a-digest'")
    else:
        log.connection.execute("UPDATE events SET event=?", (payload,))
    log.connection.commit()
    assert not log.verify()
    log.close()


@pytest.mark.parametrize("siblings", ["", {}, 0, None])
def test_proof_structure_is_strict(siblings):
    log = AuditLog()
    log.append(Event("run_start", "run", {}))
    proof = inclusion_proof(log, 0)
    proof["siblings"] = siblings
    assert not verify_proof(log.rows()[0][1], proof, checkpoint(log)["root"])
    log.close()


def test_malformed_proof_fields_fail_closed():
    for proof in (
        {},
        {"index": False, "count": 1, "siblings": []},
        {"index": -1, "count": 1, "siblings": []},
        {"index": 0, "count": 0, "siblings": []},
        {"index": 0, "count": 2, "siblings": ["zz"]},
    ):
        assert not verify_proof(b"event", proof, "0" * 64)


def test_duplicate_last_root_requires_anchored_count():
    log = AuditLog()
    for i in range(3):
        log.append(Event("tool_call", "run", {"index": i}))
    anchor = checkpoint(log)
    proof = inclusion_proof(log, 2)
    proof["count"] = 4
    # Duplicate-last trees permit ambiguous root-only membership counts.
    assert verify_proof(log.rows()[2][1], proof, anchor["root"])
    assert not verify_proof(log.rows()[2][1], proof, anchor["root"], expected_count=3)
    log.close()
