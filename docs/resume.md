# Resume wording backed by current evidence

- Built a custom labelled interpreter, product lattice and stratified Datalog
  policy engine for an LLM-agent information-flow firewall; added strict control
  tracking, conservative preflight checks and explainable per-call decisions.
- Implemented JSON Schema to GBNF compilation and independent typed validation;
  tested acceptance and rejection against the real llama.cpp grammar backend.
- Integrated MCP stdio and Streamable HTTP using the official SDK, with local
  tool contracts, namespace isolation and canonical metadata approval pins.
- Ran a hash-verified Qwen0.5B Q4_K_M model entirely on CPU; measured a 4.184349s
  short response and 550.4MB peak working set in a single local smoke run.
- Implemented hash-chained SQLite audit events and Merkle inclusion proofs;
  regressions detect edits and suffix deletion against a trusted checkpoint.

- Ran a complete AgentDojo v1 comparison on CPU (4,356 graded runs across six
  configurations, zero errors) with resumable, hash-pinned checkpoints across two hosts.

The comparison measured 4/97 clean utility and 0/629 attack success for every
configuration, including the undefended agent. Do not claim reduced attack success:
the 0.5B planner's utility floor leaves the defenses indistinguishable.
