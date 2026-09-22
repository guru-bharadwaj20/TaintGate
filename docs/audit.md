# Audit log

Log sensitive values through `redact` rather than storing raw payloads. Hashes
are commitments, not encryption; guessable low-entropy values may still be
recovered through dictionary attacks. Store audit files with host access control.

Export `checkpoint(log)` to independently protected storage after a run.
A checkpoint held beside the database under the same attacker permissions is
not a trusted anchor. `verify_checkpoint` compares count, root and chain head.
Odd Merkle levels duplicate the final node. Empty trees have a distinct hash.
