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
