# Security evidence and action equivalence

Paired worlds use identical trusted plans, policy, tools and labels, varying only
untrusted payloads. Protected action traces record successful tool identity,
recipient and arguments after authorization. Denied calls are absent. Explicit
user approvals change the authorized world and are excluded from equivalence.

These bounded tests demonstrate regressions and sampled invariants; they are
not a universal noninterference proof. Timing, termination, allocation behavior
and failures remain observable. Strict mode conservatively denies later actions
after reading untrusted inputs, which improves protection at a utility cost.
