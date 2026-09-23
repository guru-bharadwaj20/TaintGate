# Development

Use Python 3.12 or newer and a project-local virtual environment. Package metadata
uses PEP 621 and setuptools. Runtime components must work without model downloads;
model inference and MCP integrations are optional dependency groups. Development
checks use pytest, Hypothesis, Ruff and strict mypy. Install with
`python -m pip install -e ".[dev,mcp,ui]"` inside the virtual environment.

Each completed subtask receives its own commit. `scripts/commit_task.py` serializes
parallel contributors' Git index writes and updates exactly one checklist row.
Pass the task ID, a commit message and only the files belonging to that change.
Run relevant checks before using it. Never delete a busy commit lock without
checking whether its owner is active.

## Reproduce local checks

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev,mcp,ui]"
.venv\Scripts\python -m ruff check .
.venv\Scripts\python -m mypy
.venv\Scripts\python -m pytest --cov=taintgate
```

On Unix, use `.venv/bin/python`. CI checks Python 3.12 and 3.13. Model weights
are never needed for ordinary tests. Install the `models` extra separately
only when running a real GGUF model; CPU mode must use `n_gpu_layers=0`.
This machine has Python 3.13.1; Python 3.12 compatibility is checked by CI.

Optional extras: `.[bench,models]` pins the upstream AgentDojo revision;
`.[demo-video]` installs the recording script dependencies. Model installation
may require the documented official CPU wheel source. Prompt Guard weights
require publisher-approved access; never commit credentials or model files.
`python -m build --no-isolation --outdir artifacts/dist-final` uses already
installed build tools when network isolation prevents fetching dependencies.
