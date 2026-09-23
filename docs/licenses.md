# Dependency and model notices

TaintGate source is MIT licensed. Dependencies and model weights retain their
own licenses. `benchmarks/dependency_licenses.json` records installed versions
and declared license metadata; inspect the corresponding distribution's LICENSE
files before redistribution. No model weights or upstream benchmark archive are
included in this repository or Python wheel.

| Artifact | Declared license / handling |
| --- | --- |
| Qwen2.5-0.5B-Instruct Q4_K_M | Apache-2.0, publisher revision and hash pinned in config/models.json |
| llama-cpp-python | MIT, native dependency notices remain applicable |
| MCP Python SDK | MIT |
| rfc8785 | Apache-2.0 |
| FastAPI, Uvicorn, jsonschema | See installed MIT/BSD notices in the inventory |
| Prompt Guard 2 | Publisher-gated model; obtain approved access and read its terms before use |
| AgentDojo | Pinned upstream source; its notices and dataset terms remain applicable |
| Video tooling | Pillow/imageio-ffmpeg are development tools; no encoder binary is bundled |

The optional container installs upstream distributions rather than relicensing
or stripping their metadata. A release distributor must preserve notices of
bundled native libraries. Core paper PDFs are linked, not redistributed.
