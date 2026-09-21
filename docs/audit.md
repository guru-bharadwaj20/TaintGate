# Audit log

Log sensitive values through `redact` rather than storing raw payloads. Hashes
are commitments, not encryption; guessable low-entropy values may still be
recovered through dictionary attacks. Store audit files with host access control.
