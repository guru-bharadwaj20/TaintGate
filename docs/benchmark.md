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
