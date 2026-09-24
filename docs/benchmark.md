# Benchmark protocol

The pinned AgentDojo source revision is `089ed468cf3ed0322acc66b0211f26d9d90dbf60`.
The benchmark version is `v1`, deliberately preserving the original task set.
Development selection is frozen in `config/benchmark_subset.json` before inference.
All pipelines use the same CPU model and call budget. Taintgate approvals are
recorded and denied in unattended runs. Models and caches remain separate trust
domains; mock tests are never reported as real task performance.

Prompt Guard 2 actual CPU inference is pending: the publisher's configuration URL
returned HTTP 401 on 2026-10-02 without credentials. The repository requires an
account with publisher access and acceptance of the Llama license. The local-only
adapter can load user-provided authorized weights; no detector results are
reported while those weights are absent. Access evidence is stored in
`benchmarks/prompt_guard_access.json`.

Sources: https://github.com/ethz-spylab/agentdojo and
https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M

The original `v1` registry was also loaded from the unchanged pinned source:
workspace 40 user tasks and 6 injection goals, travel 20 and 7, banking 16 and 9,
Slack 21 and 5. Their within-suite Cartesian product totals 629 cases.

Run an actual development comparison with:

```powershell
python -m taintgate.bench.runner artifacts/models/qwen2.5-0.5b-instruct-q4_k_m.gguf --output artifacts/bench/results.json --upstream-source artifacts/agentdojo
```

The optional source loader skips only the upstream convenience package initializer
that eagerly imports unused provider SDKs. It executes the original TaskSuite,
FunctionsRuntime, task environment, grading and attack submodules unchanged.
Every outcome uses the upstream utility and attacker-goal checks; the second
boolean returned by TaskSuite is attacker success and is not inverted.

Add `--full` for all original v1 user tasks and injection pairs. Results checkpoint
atomically after each run, including host metadata, approvals, elapsed wall time
and measured deterministic call overhead. Restarting with a different model,
subset, budget or implementation source hash is rejected. All configurations share
four inference requests and 1,024 requested output tokens per run. Unattended
approval requests stop the action. Prompt Guard weights remain unavailable, so
full detector comparisons are pending and no missing results are estimated.
