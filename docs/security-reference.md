# Security reference

Read the [threat model](threat-model.md) before configuring tools. The [policy
language](policy.md) defines safe function-free rules, stratification, default
deny and deny-over-ask-over-allow precedence. Only host-approved tool identifiers
receive explicit allow rules. Runtime labels are required; missing or malformed
label metadata is rejected.

A private program counter can leak a bit even if call arguments are public.
Check its confidentiality against the sink principal as well as its integrity.
Explicit approvals can authorize matching ask decisions; they cannot override
confidentiality or secret denials. Recheck policy and tool pins at runtime.

The security claims are policy-relative and exclude compromised hosts, malicious
users and timing side channels. Property tests provide bounded experimental
evidence. Read [static-checker limits](static.md) and [test scope](security-testing.md).
