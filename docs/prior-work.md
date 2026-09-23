# Prior work and engineering scope

The planner/extractor split and labelled execution reproduce the CaMeL design.
FIDES motivates explicit integrity and confidentiality tracking. The repository
adds a custom Datalog policy implementation with derivations, conservative
preflight analysis, MCP transport integration, metadata pins, outbound checks,
anchored audit proofs and executable security regressions.

- [CaMeL reading copy](https://css.csail.mit.edu/6.858/2026/readings/camel.pdf)
- [FIDES research page](https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/)
- [FIDES v2](https://arxiv.org/pdf/2505.23643v2)
- [LlamaFirewall](https://arxiv.org/abs/2505.03574v1)
- [MCP-Scan introduction](https://invariantlabs.ai/blog/introducing-mcp-scan)

Prompt Guard is a detector baseline, not the trusted enforcement layer. Tool
scanners are supplemental checks rather than semantic proof of benign tools.
This is an engineering implementation and extension, not a claim that the core
information-flow approach is new. Compare measured outcomes with matched
benchmark versions and budgets; do not copy prior papers' numbers as ours.
