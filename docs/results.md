# Results and reproduction

These measurements are local engineering evidence, not AgentDojo utility or
attack-success claims. Benchmark task revisions and configurations are pinned
in `config/agentdojo.json`; raw comparative results must be retained per run.

| Local measurement | Observed result | Evidence |
| --- | --- | --- |
| Qwen0.5B Q4_K_M CPU model load | 15.022882 seconds | benchmarks/cpu_results.json |
| Short CPU response | 4.184349 seconds, `Ready.` | benchmarks/cpu_results.json |
| Peak working set | 550,400,000 bytes | benchmarks/cpu_results.json |
| 100-edge policy closure, reference | 33.900429 seconds, 5,150 facts | benchmarks/policy_results.json |
| Same closure, semi-naive | 0.680439 seconds, 5,150 facts | benchmarks/policy_results.json |

Policy measurements are single-run exploratory timings with concurrent workers.
Use repeated isolated trials before publishing a speedup claim. The synthetic
demo records an allowed send, blocked injected recipient, changed-metadata
quarantine and anchored tamper detection in `benchmarks/demo_results.json`.

| AgentDojo configuration | Utility / ASR |
| --- | --- |
| Plain agent | Await actual run output |
| Spotlighting / sandwich | Await actual run output |
| Prompt Guard 2 | Publisher-approved weights unavailable without authenticated access |
| TaintGate permissive | Await actual run output |
| TaintGate strict | Await actual run output |

Never replace a missing result with zero, a previous paper's number or an
estimate. Report completed tasks, attack cases, model hash and budgets beside
any measured rate. Full published comparisons remain pending until executed.
