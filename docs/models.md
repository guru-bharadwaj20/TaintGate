# CPU models

The optional backend is pinned to `llama-cpp-python==0.3.36` and loads local GGUF
files with `n_gpu_layers=0`. Model files stay outside Git. Inference is never
needed for the deterministic policy tests.

Backend source: https://github.com/abetlen/llama-cpp-python

The initial planner is Qwen2.5-0.5B-Instruct Q4_K_M, Apache-2.0 licensed. It is
small enough for CPU experiments; task utility must be measured rather than
assumed. Source: https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF

The quarantined extraction worker uses the same Qwen artifact in a separate
request and trust domain. Reusing weights does not reuse planner context.
Extraction must apply the generated grammar and independent schema validation.
