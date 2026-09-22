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

Measured real local CPU smoke (`benchmarks/cpu_results.json`): Qwen0.5B Q4_K_M,
two threads, context 2048, zero GPU layers. One run loaded in 15.022882 seconds,
returned `Ready.` in 4.184349 seconds and peaked at 550,400,000 bytes working set.
Concurrent project workers affect these single-run timings; no task utility or
attack resistance follows from this smoke test. The downloaded GGUF hash matched
the publisher's pinned LFS SHA-256.
