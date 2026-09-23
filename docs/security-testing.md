# Security evidence and action equivalence

Paired worlds use identical trusted plans, policy, tools and labels, varying only
untrusted payloads. Protected action traces record successful tool identity,
recipient and arguments after authorization. Denied calls are absent. Explicit
user approvals change the authorized world and are excluded from equivalence.

These bounded tests demonstrate regressions and sampled invariants; they are
not a universal noninterference proof. Timing, termination, allocation behavior
and failures remain observable. Strict mode conservatively denies later actions
after reading untrusted inputs, which improves protection at a utility cost.

## Reproduction and crash retention

The default Hypothesis profile is `ci`: deterministic generation, 100 examples,
no timing deadline or mutable example database. `TAINTGATE_HYPOTHESIS_PROFILE=local`
enables a persistent local database and 200 examples. Hypothesis shrinks failing
examples automatically; retain the minimized case in a regression fixture.

Run `python scripts/fuzz_ast.py --seed 20261002 --cases 1000` for deterministic
parser smoke fuzzing. An unexpected exception writes JSON source, seed and case
index to `artifacts/fuzz/ast-crash.json`; replay with
`python scripts/fuzz_ast.py --replay artifacts/fuzz/ast-crash.json`.
Artifacts are ignored by Git. Review them for sensitive content before sharing.
No crash artifact is claimed when a run succeeds. This bounded smoke harness
complements property tests; it does not replace coverage-guided fuzzing.
