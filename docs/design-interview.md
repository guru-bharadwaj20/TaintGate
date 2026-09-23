# Design review and interview questions

| Question | Answer and boundary |
| --- | --- |
| Is this a new security architecture? | No. It implements and extends ideas from CaMeL and FIDES; the repository's deterministic interpreter, policy and gateway are the engineering contribution. |
| Why separate the planner from untrusted text? | A planner that receives poisoned tool output may change the action program. The planner sees trusted requests; quarantined extraction returns validated data. |
| Why can a small CPU model work? | Model quality affects accepted plans and task success. Authorization is determined by code and configuration, rather than model judgment. Model isolation and correct labels remain assumptions. |
| What is an implicit flow? | A poisoned condition can select a constant-argument call. The counter label reaches the policy even when no argument contains poisoned bytes. |
| Why intersect readers? | Mixing two values must preserve both owners' restrictions. Union would allow readers who were authorized for only one input. |
| Why keep strict labels after a branch? | An untaken assignment or earlier error can affect later calls. Sticky dependencies conservatively reduce this influence while reducing utility. |
| Is strict mode universally noninterfering? | No universal proof is claimed. Bounded tests cover mediated actions; timing, termination and host resources are excluded. |
| Why a custom restricted interpreter? | General Python exposes imports, reflection, mutation and host objects. A small allowlisted language makes the enforcement surface reviewable. |
| Does JSON Schema make extraction trustworthy? | It constrains shape and types. Extracted values retain untrusted integrity and input confidentiality. |
| Does static approval replace runtime authorization? | No. Runtime values and current gateway/policy state are checked on every protected call. |
| What breaks approval reuse? | Changes in plan text, tool configuration, policy configuration or recipients change the approval-scope identity. Applications must authenticate approval decisions. |
| What does a Merkle root prove? | Integrity relative to a trusted checkpoint, not that the recorded policy was correct or that no earlier log history was omitted. |
| What measurements can be put on a resume? | Only reproducible measured task success, attack success, latency, coverage and overhead. Unrun external benchmarks remain pending. |

For a review, walk through one poisoned condition, show its source label, show
the counter label at the proposed call, and show the deterministic policy
decision and audit evidence. Then run the matching regression test. Explain
which assumptions the demonstration exercises and which remain outside it.

The research bibliography in the project documentation provides original
sources. Avoid describing a bounded regression suite as a proof or a local
fixture as a completed AgentDojo evaluation.
