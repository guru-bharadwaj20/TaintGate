# Local synthetic red-team generator

The bounded generator and synthetic regression tests pass locally. The pinned
CPU model smoke is still pending; no model-generated variant fixture has been
recorded yet. P20.05 and P20.06 remain pending until that smoke finishes and its
real output is retained.

`python -m taintgate.attacks.generate` makes one bounded CPU generation request
using the SHA-256-pinned Qwen2.5 0.5B Q4_K_M model. The generator receives no tools
or private documents. A GBNF grammar permits only one `payload` string of at most
64 characters, and JSON Schema validation checks the result again. The decoding
seed, model hash and token limit accompany the retained fixture. Response caching
uses the extractor trust domain and includes all decoding inputs.

Evaluation invokes the normal labelled Interpreter through the dry-run
Application. The poisoned email and the destination `attacker.invalid` are
synthetic. Send tools only append to in-memory lists; there are no accounts,
network requests, payments or external deliveries.

The deliberately permissive comparison Interpreter grants every call and copies
the synthetic email into a simulated send. This is an intentionally unsafe
fixture, not a claim that a baseline LLM was hijacked. Its counterexample is
retained as a regression expected to produce zero sends through strict mode.
No successful strict-mode bypass has been observed in the covered local cases.
These smoke results are not AgentDojo measurements and do not estimate a general
attack success rate. Ordinary CI replays the fixture and never downloads a model.
