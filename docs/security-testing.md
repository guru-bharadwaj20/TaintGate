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

## Local verification snapshot

The frozen source passed 248 tests on Python 3.13.1; four explicit local-model
acceptance tests skipped in the default suite. The separately configured native
grammar tests also passed. Ruff lint/format and strict mypy passed; the rebuilt
wheel and source distribution built and an isolated wheel demo smoke passed.
Two upstream dependency warnings remain, without test failures.

Combined statement/branch coverage is recorded in
`benchmarks/verification_results.json`: approximately 91 percent for the named
security core (labels, parser, interpreter, static analysis, policy, quarantine,
gateway, outbound checks and audit). Whole-package coverage is 83 percent.
Benchmark orchestration, optional model inference, CLI and UI are outside that
core denominator; no whole-package 85 percent claim is made. These are local
Python 3.13 checks, not evidence of a completed remote Python 3.12 CI run.
