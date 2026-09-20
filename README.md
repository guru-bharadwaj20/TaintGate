# TaintGate

An information-flow firewall for LLM agents, designed to stop indirect prompt injection from turning untrusted emails, web pages and tool results into unauthorized actions or data leaks.

A planner sees only trusted input and produces a restricted program. A labelled interpreter tracks data provenance, integrity and confidentiality; a deterministic policy engine checks each tool call and returns **allow**, **deny** or **ask**. A tool-free quarantined model extracts typed data from untrusted text.

The planned implementation runs with local quantised models on CPU and includes an MCP gateway, static analysis and a tamper-evident audit log. **Status: planning and initial documentation; these components are not implemented yet.**

The core design builds on [CaMeL](https://css.csail.mit.edu/6.858/2026/readings/camel.pdf) and [FIDES](https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the phase checklist and required small-commit workflow. Licensed under [MIT](LICENSE).
