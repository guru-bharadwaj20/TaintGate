# Audit log

Log sensitive values through `redact` rather than storing raw payloads. Hashes
are commitments, not encryption; guessable low-entropy values may still be
recovered through dictionary attacks. Store audit files with host access control.

Export `checkpoint(log)` to independently protected storage after a run.
A checkpoint held beside the database under the same attacker permissions is
not a trusted anchor. `verify_checkpoint` compares count, root and chain head.
Odd Merkle levels duplicate the final node. Empty trees have a distinct hash.

## Limits and recovery

An unanchored hash chain detects local edits and interior deletion, but a fully
rewritten history or suffix deletion can verify successfully. Check an external
trusted checkpoint to detect those changes. Inclusion proofs authenticate an
entry only against a trusted root; accepting a root supplied by the attacker
provides no assurance. Back up the database and the independently held anchors.
Verify before restoring service; do not silently create a new anchor for a
corrupt history. SQLite transactions serialize appends, but a compromised host
can bypass application-level append-only conventions.

```sh
taintgate audit checkpoint audit.sqlite > trusted-checkpoint.json
taintgate audit verify audit.sqlite --anchor trusted-checkpoint.json
taintgate audit prove audit.sqlite --index 0
```

## Operational recovery checklist

Stop new execution while inspecting corruption. Make an offline copy of the
SQLite database and preserve its independently held checkpoint. Run the verify
CLI against that checkpoint before and after restoring a known-good backup.
An inclusion proof may authenticate an individual preserved entry, but does not
establish that missing newer events never existed. Retain checkpoint count and
head together with the root. Rotate storage only at a documented checkpoint
boundary, preserving old anchors and logs; never silently reset the chain.

When authenticating an entry index and tree size, pass the independently anchored
count as `verify_proof(payload, proof, root, expected_count=count)`. A duplicate-last
Merkle root alone does not distinguish certain odd-size trees from trees with a
duplicated final leaf. Root-only proofs authenticate membership, not tree size.
