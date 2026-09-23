"""Load unchanged pinned AgentDojo graders without eager unused provider SDKs."""

import sys
from importlib import import_module
from pathlib import Path
from types import ModuleType


def load_source(source: Path) -> None:
    root = source.resolve() / "src"
    pipeline = root / "agentdojo" / "agent_pipeline"
    if (
        not (pipeline / "base_pipeline_element.py").is_file()
        or not (root / "agentdojo" / "task_suite" / "task_suite.py").is_file()
    ):
        raise ValueError("Expected verified AgentDojo source checkout")
    sys.path.insert(0, str(root))
    package = import_module("agentdojo")
    provider_package = ModuleType("agentdojo.agent_pipeline")
    provider_package.__path__ = [str(pipeline)]
    # Individual submodules still execute the original source. Only convenience
    # exports in this package initializer eagerly requiring unused SDKs are skipped.
    sys.modules["agentdojo.agent_pipeline"] = provider_package
    setattr(package, "agent_pipeline", provider_package)
