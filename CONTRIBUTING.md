# Contributing to TaintGate

This file is the implementation roadmap and contribution tracker. The supplied project idea is design input; a row is complete only when its deliverable exists and has been checked. The repository is currently in the documentation stage.

## Status and completion rules

| Indicator | Meaning |
| :---: | --- |
| ❌ | Pending, in progress, or awaiting verification |
| ✅ | Completed and checked; evidence is recorded in the corresponding commit |

Each subtask has a stable ID. Replace ❌ with ✅ only after completing that exact task and its relevant checks. Include the status update in the implementation commit. Split a row further when it contains independently reviewable work; preserve existing IDs. Do not mark a whole phase complete because one component works. Optional work remains pending until implemented.

## Required commit workflow

**Commit every minor change.** Keep each commit focused on one small, reviewable change. Do not bundle unrelated edits, commit secrets or model weights, or commit another contributor's work inadvertently.

Use this identity for every project commit:

```text
Author/committer name: guru-bharadwaj20
Author/committer email: gururb20@gmail.com
```

Set the identity locally in this repository:

```sh
git config --local user.name "guru-bharadwaj20"
git config --local user.email "gururb20@gmail.com"
```

For each minor change: inspect the diff, run relevant checks, update its task status when complete, stage only its files, and commit. Use messages such as `docs: define threat boundaries (P02.01)` or `feat(labels): implement join (P04.06)`. Verify the author and committer before pushing. A commit records a change; it does not replace validation.

## Design constraints

- Keep untrusted data and raw tool metadata out of the trusted planner.
- Enforce labels and policies in deterministic code before every tool call.
- Keep quarantined extraction tool-free and validate typed output again.
- Include control dependencies in strict mode; document weaker guarantees in permissive mode.
- Bind approvals to concrete scopes and continue checking runtime arguments.
- Treat grammar constraints, description scans and DLP as limited mechanisms; typed strings can still contain malicious text.
- State security guarantees relative to explicit policies, trusted configuration and the threat model. Tests provide evidence, not a general mathematical proof.
- Preserve CPU-only operation and report measured utility and security results.

## Phase overview

The suggested schedule is 16 weeks for four contributors. Phases overlap where dependencies permit; weeks are planning targets, not completion evidence.

| Phase | Scope | Suggested window | Subtasks |
| --- | --- | --- | ---: |
| P01 | Repository and contribution workflow | Week 1 | 15 |
| P02 | Threat model and architecture | Weeks 1-2 | 18 |
| P03 | CPU model setup and trusted planner | Weeks 1-2; 9-10 | 16 |
| P04 | Integrity, confidentiality and provenance | Weeks 3-5 | 16 |
| P05 | TaintScript parser and language boundary | Weeks 3-5 | 16 |
| P06 | Labelled interpreter and explicit flows | Weeks 3-5 | 18 |
| P07 | Implicit flows and runtime limits | Weeks 6-8 | 16 |
| P08 | JSON Schema to GBNF and quarantined extraction | Weeks 6-8 | 20 |
| P09 | Datalog parser and reference evaluator | Weeks 3-5 | 15 |
| P10 | Stratification, semi-naive evaluation and explanations | Weeks 6-8 | 17 |
| P11 | MCP gateway transports and isolation | Weeks 3-5; 9-10 | 17 |
| P12 | Tool metadata approval and change detection | Weeks 6-8 | 16 |
| P13 | Static checking and approval scopes | Weeks 11-12 | 16 |
| P14 | Outbound filtering and secret detection | Weeks 9-10 | 15 |
| P15 | Tamper-evident audit storage | Weeks 9-10 | 16 |
| P16 | Integration, UI and attack laboratory | Weeks 11-12 | 15 |
| P17 | Security properties, regression testing and fuzzing | Weeks 11-14 | 19 |
| P18 | AgentDojo evaluation and reproducibility | Weeks 13-14 | 20 |
| P19 | Documentation, demonstration and release | Weeks 15-16 | 19 |
| P20 | Optional extensions | After core release | 6 |

## P01 - Repository and contribution workflow

Suggested window: Week 1.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P01.01 | Review the supplied project idea and linked prior work |
| ✅ | P01.02 | Create this phase-by-phase contribution checklist |
| ✅ | P01.03 | Write the short project README |
| ✅ | P01.04 | Add the MIT license |
| ✅ | P01.05 | Record the required commit identity and small-commit rule |
| ✅ | P01.06 | Choose the Python 3.12 dependency and packaging workflow |
| ✅ | P01.07 | Create pyproject.toml with package metadata |
| ✅ | P01.08 | Create the taintgate package and module directories |
| ✅ | P01.09 | Create unit, property, fuzz and attack test directories |
| ✅ | P01.10 | Configure formatting and linting |
| ✅ | P01.11 | Configure strict mypy checks |
| ✅ | P01.12 | Configure pytest and coverage reporting |
| ✅ | P01.13 | Add a gitignore for models, secrets, caches and run artifacts |
| ✅ | P01.14 | Add CI for linting, typing and tests |
| ✅ | P01.15 | Document a reproducible CPU-only development setup |

## P02 - Threat model and architecture

Suggested window: Weeks 1-2.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P02.01 | Document trusted user input and trusted configuration |
| ✅ | P02.02 | Document untrusted tool outputs and server metadata |
| ✅ | P02.03 | Describe A1 unauthorised action attacks |
| ✅ | P02.04 | Describe A2 argument hijacking attacks |
| ✅ | P02.05 | Describe A3 exfiltration attacks |
| ✅ | P02.06 | Describe A4 tool poisoning attacks |
| ✅ | P02.07 | Describe A5 post-approval tool changes |
| ✅ | P02.08 | Describe A6 cross-server tool shadowing |
| ✅ | P02.09 | Describe A7 secret leakage attacks |
| ✅ | P02.10 | Record excluded host, weights and timing attacks |
| ✅ | P02.11 | Draw the planner, checker, interpreter and gateway boundaries |
| ✅ | P02.12 | Specify what planner inputs may contain |
| ✅ | P02.13 | Define strict and permissive modes and their different guarantees |
| ✅ | P02.14 | Define observable actions and approved exceptions for noninterference |
| ✅ | P02.15 | Distinguish allowed data-dependent reads from protected side effects |
| ✅ | P02.16 | Specify fail-closed behaviour and the trusted computing base |
| ✅ | P02.17 | Document extensions over CaMeL and FIDES without novelty claims |
| ✅ | P02.18 | Assign module interfaces and ownership for a team of four |

## P03 - CPU model setup and trusted planner

Suggested window: Weeks 1-2; 9-10.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P03.01 | Choose and pin the CPU inference backend version |
| ✅ | P03.02 | Select a quantised planner model and record its license |
| ✅ | P03.03 | Select a quantised extraction model and record its license |
| ✅ | P03.04 | Record model hashes, quantisation and CPU settings |
| ❌ | P03.05 | Measure RAM use and short-request CPU latency |
| ❌ | P03.06 | Define a backend interface for inference |
| ❌ | P03.07 | Implement an offline inference smoke test |
| ❌ | P03.08 | Build planner prompts from trusted inputs only |
| ❌ | P03.09 | Expose only locally approved tool signatures to the planner |
| ❌ | P03.10 | Constrain planner output to the plan language |
| ❌ | P03.11 | Implement bounded planner retries |
| ❌ | P03.12 | Generate trusted parse-error summaries without input excerpts |
| ❌ | P03.13 | Generate trusted unknown-tool summaries without tool output |
| ❌ | P03.14 | Test that tool results never enter planner context |
| ❌ | P03.15 | Define cache keys including model, prompt and decoding settings |
| ❌ | P03.16 | Implement isolated response caching without crossing trust boundaries |

## P04 - Integrity, confidentiality and provenance

Suggested window: Weeks 3-5.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P04.01 | Define trusted and untrusted integrity ordering |
| ✅ | P04.02 | Define principals and explicit public-reader semantics |
| ✅ | P04.03 | Define confidentiality ordering with reversed set inclusion |
| ✅ | P04.04 | Specify public ALL as the identity of reader intersection |
| ✅ | P04.05 | Implement immutable labels |
| ✅ | P04.06 | Implement the product-lattice join |
| ✅ | P04.07 | Implement ordering and compatibility checks |
| ✅ | P04.08 | Implement stable provenance node identifiers |
| ✅ | P04.09 | Implement provenance edges and source union |
| ✅ | P04.10 | Test join commutativity |
| ✅ | P04.11 | Test join associativity |
| ✅ | P04.12 | Test join idempotence and upper-bound laws |
| ✅ | P04.13 | Test public, empty-reader and mixed-principal cases |
| ✅ | P04.14 | Specify endorsement authorization |
| ✅ | P04.15 | Specify declassification authorization |
| ✅ | P04.16 | Require scoped approvals and audit events for label relaxation |

## P05 - TaintScript parser and language boundary

Suggested window: Weeks 3-5.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P05.01 | Publish a supported syntax and operation table |
| ✅ | P05.02 | Parse plans without using eval or exec |
| ✅ | P05.03 | Implement an explicit AST node allowlist |
| ✅ | P05.04 | Validate assignments and literal expressions |
| ✅ | P05.05 | Validate lists and dictionaries |
| ✅ | P05.06 | Validate if and else statements |
| ✅ | P05.07 | Validate bounded for loops over supported containers |
| ✅ | P05.08 | Validate registered calls and quarantined extraction calls |
| ✅ | P05.09 | Validate comparisons and boolean operators |
| ✅ | P05.10 | Validate indexing and approved field access |
| ✅ | P05.11 | Validate f-strings and approved string methods |
| ✅ | P05.12 | Reject imports, while, functions, classes and lambdas |
| ✅ | P05.13 | Reject dunder access and introspection paths |
| ✅ | P05.14 | Reject try blocks and unsupported exception constructs |
| ✅ | P05.15 | Bound plan size, nesting and literal size |
| ✅ | P05.16 | Test accepted syntax and every rejection category |

## P06 - Labelled interpreter and explicit flows

Suggested window: Weeks 3-5.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P06.01 | Implement immutable labelled runtime values |
| ✅ | P06.02 | Implement the labelled environment and variable lookup |
| ✅ | P06.03 | Implement assignment with label preservation |
| ✅ | P06.04 | Implement arithmetic with joined operand labels |
| ✅ | P06.05 | Implement comparisons with joined operand labels |
| ✅ | P06.06 | Implement boolean short-circuit evaluation |
| ✅ | P06.07 | Implement labelled string methods and f-strings |
| ✅ | P06.08 | Implement list elements and container shape labels |
| ✅ | P06.09 | Implement dictionary entry and shape labels |
| ✅ | P06.10 | Propagate container, element and index labels on lookup |
| ✅ | P06.11 | Propagate only shape labels through length operations |
| ✅ | P06.12 | Implement approved field lookup without arbitrary host access |
| ✅ | P06.13 | Prevent alias mutation from bypassing label tracking |
| ✅ | P06.14 | Implement a registered-tool interface |
| ✅ | P06.15 | Label tool results before exposing them to plans |
| ✅ | P06.16 | Implement quarantined extraction as a runtime primitive |
| ✅ | P06.17 | Record operation provenance and execution traces |
| ✅ | P06.18 | Compare pure supported expressions with CPython in an isolated test oracle |

## P07 - Implicit flows and runtime limits

Suggested window: Weeks 6-8.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P07.01 | Implement the program-counter label |
| ✅ | P07.02 | Raise the counter label on branch conditions |
| ✅ | P07.03 | Restore counter context after branch execution |
| ✅ | P07.04 | Track control dependencies on assignments |
| ✅ | P07.05 | Raise the counter label on loop selection and iteration |
| ✅ | P07.06 | Include counter labels in every protected tool-call decision |
| ✅ | P07.07 | Implement strict mode as the default security mode |
| ✅ | P07.08 | Implement and clearly label permissive mode limitations |
| ✅ | P07.09 | Track tainted short-circuit control dependencies |
| ✅ | P07.10 | Specify loop termination and exception observables |
| ✅ | P07.11 | Implement interpreter fuel accounting |
| ✅ | P07.12 | Bound iterations, recursion-free operations and result sizes |
| ✅ | P07.13 | Convert runtime failures into correctly labelled errors |
| ✅ | P07.14 | Prevent error traces from exposing secrets to the planner |
| ✅ | P07.15 | Test constant-argument calls under tainted conditions |
| ✅ | P07.16 | Test nested branches, loops and early failures |

## P08 - JSON Schema to GBNF and quarantined extraction

Suggested window: Weeks 6-8.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P08.01 | Define the supported JSON Schema dialect and rejection rules |
| ✅ | P08.02 | Normalize Pydantic schemas and supported references |
| ✅ | P08.03 | Compile required object fields |
| ✅ | P08.04 | Compile optional fields and additional-property constraints |
| ✅ | P08.05 | Compile arrays and supported length bounds |
| ✅ | P08.06 | Compile enum and constant values |
| ✅ | P08.07 | Compile nullable values and supported unions |
| ✅ | P08.08 | Compile escaped JSON strings |
| ✅ | P08.09 | Compile numeric, integer and boolean values |
| ✅ | P08.10 | Handle supported email, date and datetime formats |
| ✅ | P08.11 | Bound schema depth and grammar size |
| ✅ | P08.12 | Reject unsupported or recursive schema features safely |
| ❌ | P08.13 | Test grammar acceptance and rejection with the pinned backend |
| ✅ | P08.14 | Run the quarantined model without tool access |
| ✅ | P08.15 | Validate decoded JSON again with Pydantic |
| ✅ | P08.16 | Apply semantic validation that grammars cannot enforce |
| ✅ | P08.17 | Support an explicit insufficient-information result |
| ✅ | P08.18 | Label all extracted fields with input provenance and untrusted integrity |
| ✅ | P08.19 | Reject trailing text, tool-call objects and malformed responses |
| ✅ | P08.20 | Test injected instructions remaining inert field data |

## P09 - Datalog parser and reference evaluator

Suggested window: Weeks 3-5.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P09.01 | Define policy syntax and built-in predicate types |
| ✅ | P09.02 | Parse facts and rule heads |
| ✅ | P09.03 | Parse positive and negated rule bodies |
| ✅ | P09.04 | Parse string and integer constants |
| ✅ | P09.05 | Validate predicate arity consistently |
| ✅ | P09.06 | Enforce safe variables in heads and negation |
| ✅ | P09.07 | Reject unsupported function symbols and unbounded terms |
| ✅ | P09.08 | Define per-call policy facts from labels and provenance |
| ✅ | P09.09 | Implement relation storage and fact deduplication |
| ✅ | P09.10 | Implement variable binding and relational joins |
| ✅ | P09.11 | Implement a naive bottom-up reference evaluator |
| ✅ | P09.12 | Define default-deny and explicit allow rules |
| ✅ | P09.13 | Define deny-over-ask-over-allow precedence |
| ✅ | P09.14 | Bound policy size and evaluation resources |
| ✅ | P09.15 | Test parsing, unsafe rules and simple derivations |

## P10 - Stratification, semi-naive evaluation and explanations

Suggested window: Weeks 6-8.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P10.01 | Build signed predicate dependency graphs |
| ✅ | P10.02 | Implement strongly connected components |
| ✅ | P10.03 | Reject cycles containing negative dependencies |
| ✅ | P10.04 | Compute and order valid strata |
| ✅ | P10.05 | Evaluate negation only against completed lower strata |
| ✅ | P10.06 | Implement delta fact sets for recursive evaluation |
| ✅ | P10.07 | Implement semi-naive rule variants for recursive joins |
| ✅ | P10.08 | Add relation argument indexes |
| ✅ | P10.09 | Track the rule and supporting facts for each derivation |
| ✅ | P10.10 | Generate bounded explanation trees with cycle handling |
| ✅ | P10.11 | Implement recipient-integrity rules |
| ✅ | P10.12 | Implement confidentiality reader checks |
| ✅ | P10.13 | Implement amount and destructive-action approval rules |
| ✅ | P10.14 | Test overlapping allow, ask and deny derivations |
| ✅ | P10.15 | Compare optimized results with the naive evaluator |
| ✅ | P10.16 | Generate small random stratified policies for differential tests |
| ✅ | P10.17 | Measure policy evaluation cost on growing provenance graphs |

## P11 - MCP gateway transports and isolation

Suggested window: Weeks 3-5; 9-10.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P11.01 | Pin an MCP SDK version and supported protocol revision |
| ✅ | P11.02 | Implement the gateway server interface |
| ✅ | P11.03 | Implement upstream MCP client connections |
| ✅ | P11.04 | Implement stdio transport integration |
| ✅ | P11.05 | Implement Streamable HTTP transport integration |
| ✅ | P11.06 | Remap request identifiers across multiple servers |
| ✅ | P11.07 | Namespace tools by approved server identity |
| ✅ | P11.08 | Reject namespace collisions and cross-server shadowing |
| ✅ | P11.09 | Validate JSON-RPC messages and tool arguments |
| ✅ | P11.10 | Implement cancellation propagation |
| ✅ | P11.11 | Implement upstream timeouts and disconnect handling |
| ✅ | P11.12 | Implement bounded queues and back-pressure |
| ✅ | P11.13 | Load per-server trust and reader configuration |
| ✅ | P11.14 | Label every tool result including errors and structured content |
| ✅ | P11.15 | Enforce policy on every tools/call entry point |
| ✅ | P11.16 | Return structured denial and approval-required responses |
| ✅ | P11.17 | Test transport failures without accidental tool execution |

## P12 - Tool metadata approval and change detection

Suggested window: Weeks 6-8.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P12.01 | Define trusted local tool contracts independent of raw descriptions |
| ✅ | P12.02 | Canonicalize approved names, descriptions and input schemas |
| ✅ | P12.03 | Verify RFC 8785 canonicalization test vectors |
| ✅ | P12.04 | Hash metadata using SHA-256 |
| ✅ | P12.05 | Persist approval pins by server and tool identity |
| ✅ | P12.06 | Compare current metadata with approved hashes |
| ✅ | P12.07 | Detect tool list and schema changes |
| ✅ | P12.08 | Quarantine tools that change after approval |
| ✅ | P12.09 | Display a bounded metadata diff for reapproval |
| ✅ | P12.10 | Scan model-directed imperatives and concealment requests |
| ✅ | P12.11 | Scan references to unrelated tools and servers |
| ✅ | P12.12 | Scan invisible Unicode and excessive description length |
| ✅ | P12.13 | Keep unapproved raw metadata outside planner context |
| ✅ | P12.14 | Treat description scanning as an extra layer rather than a guarantee |
| ✅ | P12.15 | Close approval-to-execution metadata race windows |
| ✅ | P12.16 | Test poisoning, rug pulls and shadowing regressions |

## P13 - Static checking and approval scopes

Suggested window: Weeks 11-12.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P13.01 | Define abstract values for labels, shape and provenance |
| ✅ | P13.02 | Use a finite configured principal universe for analysis |
| ✅ | P13.03 | Implement abstract environments and assignments |
| ✅ | P13.04 | Implement abstract expression transfer functions |
| ✅ | P13.05 | Model tool outputs from server trust configuration |
| ✅ | P13.06 | Model quarantined extraction conservatively |
| ✅ | P13.07 | Merge abstract states at branch joins |
| ✅ | P13.08 | Track abstract program-counter labels |
| ✅ | P13.09 | Compute loop fixed points with documented termination assumptions |
| ✅ | P13.10 | Collect potentially unsafe call sites |
| ✅ | P13.11 | Describe unresolved arguments without pretending to know runtime values |
| ✅ | P13.12 | Create plan-, tool-, policy- and recipient-bound approval scopes |
| ✅ | P13.13 | Invalidate approvals after relevant configuration or plan changes |
| ✅ | P13.14 | Enforce runtime checks even after static approval |
| ✅ | P13.15 | Test that runtime-flagged calls are conservatively predicted |
| ✅ | P13.16 | Document dynamic cases that still require approval |

## P14 - Outbound filtering and secret detection

Suggested window: Weeks 9-10.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P14.01 | Define outbound sinks including final rendered responses |
| ✅ | P14.02 | Implement labelled markdown parsing |
| ✅ | P14.03 | Inspect image, link and autolink destinations |
| ✅ | P14.04 | Normalize URL schemes, hosts and encodings |
| ✅ | P14.05 | Enforce destination domain allowlists |
| ✅ | P14.06 | Reject confidential data in outbound URL components |
| ✅ | P14.07 | Define safe rendering behaviour for stripped destinations |
| ✅ | P14.08 | Implement common API-key pattern detectors |
| ✅ | P14.09 | Implement configurable entropy checks |
| ✅ | P14.10 | Implement Luhn and contextual card detection |
| ✅ | P14.11 | Implement PAN and Aadhaar format checks with documented limits |
| ✅ | P14.12 | Create synthetic canary tokens for private test fixtures |
| ✅ | P14.13 | Check outbound arguments and final outputs for canaries |
| ✅ | P14.14 | Test encoded secrets and markdown exfiltration examples |
| ✅ | P14.15 | Measure scanner false positives and record limitations |

## P15 - Tamper-evident audit storage

Suggested window: Weeks 9-10.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P15.01 | Define canonical audit event schemas |
| ✅ | P15.02 | Record plan identifiers and execution boundaries |
| ✅ | P15.03 | Record labelled tool-call decisions and explanations |
| ✅ | P15.04 | Record approval, endorsement and declassification events |
| ✅ | P15.05 | Redact sensitive payloads while preserving verification |
| ✅ | P15.06 | Implement SQLite append-only event writes |
| ✅ | P15.07 | Link entries with previous-entry SHA-256 hashes |
| ✅ | P15.08 | Implement Merkle leaf and internal-node domain separation |
| ✅ | P15.09 | Implement deterministic odd-leaf handling |
| ✅ | P15.10 | Build checkpoint roots and trusted external anchors |
| ✅ | P15.11 | Implement inclusion proof generation |
| ✅ | P15.12 | Implement inclusion proof verification |
| ✅ | P15.13 | Implement audit verify and prove commands |
| ✅ | P15.14 | Test edited, reordered and deleted entries |
| ✅ | P15.15 | Test truncated logs against anchored checkpoints |
| ✅ | P15.16 | Document that an unanchored log cannot detect a fully rewritten history |

## P16 - Integration, UI and attack laboratory

Suggested window: Weeks 11-12.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P16.01 | Integrate planner, checker, interpreter, policy and gateway |
| ✅ | P16.02 | Build a safe dry-run mode with mocked tools |
| ❌ | P16.03 | Implement FastAPI run and approval endpoints |
| ❌ | P16.04 | Build a minimal run timeline |
| ❌ | P16.05 | Render provenance as a data-flow graph |
| ❌ | P16.06 | Show human-readable policy derivation explanations |
| ❌ | P16.07 | Show tool metadata change diffs |
| ❌ | P16.08 | Show scoped approval consequences |
| ❌ | P16.09 | Escape untrusted text and disable unsafe rendering |
| ❌ | P16.10 | Build a malicious tool-description server |
| ❌ | P16.11 | Build a server that changes approved metadata |
| ❌ | P16.12 | Build a poisoned-email and invoice-exfiltration server |
| ❌ | P16.13 | Provide isolated fixtures without real accounts or transactions |
| ❌ | P16.14 | Record each covered attack blocked in strict mode |
| ❌ | P16.15 | Demonstrate success and failure paths with cached CPU responses |

## P17 - Security properties, regression testing and fuzzing

Suggested window: Weeks 11-14.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ✅ | P17.01 | Generate bounded plans and paired trusted-equivalent worlds |
| ✅ | P17.02 | Define action equivalence with labels, sinks and approval exceptions |
| ✅ | P17.03 | Test strict-mode noninterference for protected side effects |
| ❌ | P17.04 | Test permissive-mode limitations with explicit counterexamples |
| ❌ | P17.05 | Shrink failing generated examples into regression fixtures |
| ❌ | P17.06 | Check static analysis against concrete execution |
| ❌ | P17.07 | Test A1 unauthorized action regressions |
| ❌ | P17.08 | Test A2 argument hijacking regressions |
| ❌ | P17.09 | Test A3 outbound exfiltration regressions |
| ❌ | P17.10 | Test A4 tool poisoning regressions |
| ❌ | P17.11 | Test A5 metadata rug-pull regressions |
| ❌ | P17.12 | Test A6 namespace shadowing regressions |
| ❌ | P17.13 | Test A7 secret leakage regressions |
| ❌ | P17.14 | Fuzz the AST parser and policy parser |
| ❌ | P17.15 | Fuzz JSON-RPC decoding and gateway state transitions |
| ❌ | P17.16 | Fuzz schema compilation and label propagation |
| ❌ | P17.17 | Set deterministic seeds and retain fuzz crash artifacts |
| ❌ | P17.18 | Measure core coverage and address meaningful gaps toward 85 percent |
| ❌ | P17.19 | Run the full required CI checks without model downloads |

## P18 - AgentDojo evaluation and reproducibility

Suggested window: Weeks 13-14.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ❌ | P18.01 | Pin AgentDojo revision and verify task and attack-case counts |
| ❌ | P18.02 | Implement the benchmark tool and label adapter |
| ❌ | P18.03 | Choose and publish a fixed development subset |
| ❌ | P18.04 | Implement the plain-agent baseline |
| ❌ | P18.05 | Implement spotlighting and sandwich prompt baselines |
| ❌ | P18.06 | Verify a supported Prompt Guard 2 CPU inference path |
| ❌ | P18.07 | Implement the detector baseline with fixed thresholds |
| ❌ | P18.08 | Implement permissive Taintgate benchmark configuration |
| ❌ | P18.09 | Implement strict Taintgate benchmark configuration |
| ❌ | P18.10 | Keep models, task subsets and budgets comparable |
| ❌ | P18.11 | Implement versioned response-cache manifests |
| ❌ | P18.12 | Track clean-task utility |
| ❌ | P18.13 | Track utility under attack |
| ❌ | P18.14 | Track attack success with threat-model coverage annotations |
| ❌ | P18.15 | Track approvals per run and per task |
| ❌ | P18.16 | Measure median and tail deterministic tool-call overhead |
| ❌ | P18.17 | Record CPU, memory, versions, seeds and wall-clock cost |
| ❌ | P18.18 | Support resumable overnight benchmark runs |
| ❌ | P18.19 | Run complete comparisons and preserve raw outcomes |
| ❌ | P18.20 | Publish measured results without filling gaps with estimates |

## P19 - Documentation, demonstration and release

Suggested window: Weeks 15-16.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ❌ | P19.01 | Expand README with setup and architecture after implementation |
| ❌ | P19.02 | Publish threat model and policy semantics |
| ❌ | P19.03 | Publish TaintScript language reference |
| ❌ | P19.04 | Publish label, endorsement and declassification reference |
| ❌ | P19.05 | Document the static checker and soundness test limits |
| ❌ | P19.06 | Document tool onboarding and approval pin management |
| ❌ | P19.07 | Document audit checkpoint storage and recovery |
| ❌ | P19.08 | Document CPU models, memory and expected runtime |
| ❌ | P19.09 | Publish benchmark configurations and result tables |
| ❌ | P19.10 | Explain differences and extensions over prior work |
| ❌ | P19.11 | Prepare the three-minute attack-and-defense demo |
| ❌ | P19.12 | Demonstrate tool-change quarantine and audit tampering |
| ❌ | P19.13 | Record a demo video using synthetic data |
| ❌ | P19.14 | Write resume bullets using measured numbers only |
| ❌ | P19.15 | Prepare answers to design and security interview questions |
| ❌ | P19.16 | Build and validate the Python distribution |
| ❌ | P19.17 | Build and test a CPU-only Docker image |
| ❌ | P19.18 | Check dependency and model redistribution licenses |
| ❌ | P19.19 | Tag a release after required checks pass |

## P20 - Optional extensions

Suggested window: After core release.

| Status | ID | Subtask / completion deliverable |
| :---: | --- | --- |
| ❌ | P20.01 | Prototype policy syntax highlighting and diagnostics |
| ❌ | P20.02 | Suggest policies from approved traces with manual review |
| ❌ | P20.03 | Benchmark a Rust policy engine before replacing Python |
| ❌ | P20.04 | Design browser DOM-origin labels and an adapter |
| ❌ | P20.05 | Generate local red-team variants in an isolated lab |
| ❌ | P20.06 | Turn successful red-team variants into regression tests |

## Prior work and source material

TaintGate plans to implement and extend the information-flow designs in CaMeL and FIDES. The policy engine, static checker, MCP integration, audit proofs and test harness are planned engineering deliverables, not completed features.

- [CaMeL reading copy](https://css.csail.mit.edu/6.858/2026/readings/camel.pdf)
- [FIDES - Microsoft Research](https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/)
- [FIDES paper, version 2](https://arxiv.org/pdf/2505.23643v2)
- [LlamaFirewall paper](https://arxiv.org/abs/2505.03574v1)
- [Introducing MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan)
- [Supplied MCP-Scan documentation URL](https://explorer.invariantlabs.ai/docs/mcp-scan) - redirects to the Explorer repository; verify the current documentation before implementation.
- [AgentDojo repository](https://github.com/ethz-spylab/agentdojo)

The supplied `Taintgate Project Idea.md` is the planning reference. Pin implementation dependencies and benchmark revisions before relying on model availability, protocol details or dataset counts.
