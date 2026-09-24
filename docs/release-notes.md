# TaintGate 0.1.0 release notes

TaintGate is a CPU-only information-flow firewall for LLM agents: a labelled
TaintScript interpreter, a stratified Datalog policy engine, quarantined
grammar-constrained extraction, an MCP gateway with metadata pinning, outbound
DLP and a hash-chained audit log.

## Verified for this release

- `ruff check .`, `ruff format --check`, strict `mypy` (59 source files) and
  `pytest` (250 passed; 4 real-GGUF grammar tests skipped by default and run
  separately against the pinned Qwen model: 4 passed).
- `python -m build` produces `taintgate-0.1.0-py3-none-any.whl` and
  `taintgate-0.1.0.tar.gz`.
- GitHub Actions: Python 3.12 and 3.13 checks plus the CPU-only Docker job,
  which runs the isolated demo with networking disabled and asserts the
  trusted task completes, the injected send is denied and the audit verifies.

## Measured AgentDojo comparison

Complete pinned AgentDojo v1 `important_instructions` comparison on CPU with
Qwen2.5-0.5B-Instruct Q4_K_M: six configurations x (97 clean + 629 attacked)
= 4,356 graded runs, zero errors. Every configuration, including the
undefended agent, measured 4/97 clean utility, 36/629 utility under attack and
0/629 attack success. The passing tasks are exactly those an agent making no
calls also passes, so this model sets a utility floor and the comparison does
not distinguish the defenses. It is not evidence that TaintGate reduces attack
success. Details, per-host timings and raw records: `docs/results.md`,
`benchmarks/agentdojo_full_results.json`.

## Known limitations

- Permissive mode omits strict control-flow protection.
- Grammar constraints, description scans and DLP are limited mechanisms;
  typed strings can still carry malicious text.
- Metadata pinning cannot prove a remote server's behaviour.
- The Prompt Guard 2 synthetic smoke missed one of two injected fixtures at
  the fixed 0.5 threshold (score 0.494065); four fixtures are not an accuracy
  estimate.
- Model weights (Qwen, Prompt Guard 2) are not redistributed; see
  `docs/licenses.md`.
