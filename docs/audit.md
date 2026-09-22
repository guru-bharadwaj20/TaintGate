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
