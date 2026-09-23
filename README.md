# TaintGate

An information-flow firewall for LLM agents. It tracks data provenance, integrity
and confidentiality and checks tool calls in deterministic code to contain
indirect prompt injection from emails, documents, web pages and tool results.

A trusted-input planner writes restricted TaintScript. A custom interpreter
propagates labels and control dependencies, a stratified Datalog engine returns
allow/deny/ask, and an MCP gateway checks approved tool metadata before execution.
A tool-free extraction model returns schema-constrained data with inherited labels.

## Try the isolated demo

Requires Python 3.12 or newer. No GPU or model download is needed for this demo.

```sh
python -m venv .venv
# Activate the environment, then:
python -m pip install -e '.[dev,mcp,ui]'
taintgate demo
taintgate ui
```

The UI binds to `127.0.0.1:8000`. Enter the session token printed in your terminal.
Its tools record synthetic sends; they do not contact real email accounts.
The demo allows a trusted send and blocks a poisoned-email recipient.

## Implemented components

| Component | Purpose |
| --- | --- |
| Restricted AST interpreter | Explicit labels, container shape labels, program-counter tracking and bounded execution |
| Integrity/confidentiality lattice | Immutable labels, provenance and scoped audited relaxation |
| Datalog engine | Safe rules, SCC stratification, indexed semi-naive evaluation and explanations |
| Quarantine compiler | Bounded JSON Schema to GBNF with independent validation |
| Static checker | Conservative preflight analysis; runtime mediation remains mandatory |
| MCP gateway | SDK stdio/HTTP, namespacing, metadata pins and fail-closed calls |
| Outbound checks | Reader constraints, secret/canary detection and safe markdown rendering |
| Audit log | SQLite hash chain, anchored Merkle roots and inclusion proofs |

## Validation and limits

```sh
python -m pytest
python -m mypy
python -m ruff check .
```

See [the threat model](docs/threat-model.md), [CPU model setup and measurements](docs/models.md),
[policy reference](docs/policy.md), [security tests](docs/security-testing.md) and
[audit anchoring requirements](docs/audit.md). A real quantised model CPU smoke
is recorded; full comparative benchmark results must be measured before claims
about attack success or task utility. Permissive mode omits strict control-flow
protection. Remote metadata pinning cannot prove a malicious server's behavior.

The core design implements and extends [CaMeL](https://css.csail.mit.edu/6.858/2026/readings/camel.pdf)
and [FIDES](https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/).

[CONTRIBUTING.md](CONTRIBUTING.md) tracks each phase and subtask. Every minor change
is committed as `guru-bharadwaj20 <gururb20@gmail.com>` and pushed immediately.
Licensed under [MIT](LICENSE).
