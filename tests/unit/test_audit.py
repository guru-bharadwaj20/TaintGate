import pytest

from taintgate.audit.log import (
    AuditLog,
    Event,
    checkpoint,
    inclusion_proof,
    verify_checkpoint,
    verify_proof,
)


def seeded():
    log = AuditLog()
    for i in range(5):
        log.append(Event("tool_call", "run", {"index": i}))
    return log


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE events SET event=x'00' WHERE seq=2",
        "DELETE FROM events WHERE seq=3",
        "UPDATE events SET seq=20 WHERE seq=1",
    ],
)
def test_mutation(mutation):
    log = seeded()
    assert log.verify()
    log.connection.execute(mutation)
    assert not log.verify()
    log.close()


def test_proofs():
    log = seeded()
    root = checkpoint(log)["root"]
    for i, row in enumerate(log.rows()):
        proof = inclusion_proof(log, i)
        assert verify_proof(row[1], proof, root)
        assert not verify_proof(b"edited", proof, root)
    log.close()


def test_truncation_requires_anchor():
    log = seeded()
    anchor = checkpoint(log)
    log.connection.execute("DELETE FROM events WHERE seq=5")
    assert log.verify()
    assert not verify_checkpoint(log, anchor)
    log.close()
