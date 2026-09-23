import pytest

from taintgate.bench.adapter import ToolAdapter
from taintgate.bench.metrics import approvals, overhead
from taintgate.bench.runner import save_atomic
from taintgate.labels import Labeled


def test_label_adapter_recursively_unwraps():
    assert ToolAdapter.plain(Labeled({"x": Labeled([Labeled(1)])})) == {"x": [1]}


def test_atomic_checkpoint_and_real_metric_samples(tmp_path):
    import json

    path = tmp_path / "result.json"
    save_atomic(path, {"records": [1]})
    save_atomic(path, {"records": [1, 2]})
    assert json.loads(path.read_text()) == {"records": [1, 2]}
    rows = [
        {"suite": "s", "task": "t", "approvals": 1, "overheads_seconds": [0.01, 0.02]},
        {"suite": "s", "task": "t", "approvals": 2, "overheads_seconds": [0.03]},
    ]
    assert approvals(rows) == {"total": 3, "by_task": {"s:t": 3}, "per_run": 1.5}
    assert overhead(rows) == {"samples": 3, "median_seconds": 0.02, "p95_seconds": 0.03}


@pytest.mark.integration
def test_adapter_real_agentdojo_runtime():
    pytest.importorskip("agentdojo")
    from agentdojo.functions_runtime import FunctionsRuntime, make_function

    def greeting(name: str) -> str:
        """Get a greeting.

        :param name: Person to greet.
        """
        return "hello " + name

    runtime = FunctionsRuntime([make_function(greeting)])
    adapter = ToolAdapter(runtime, None)
    assert adapter.invoke("greeting", {"name": "reader"}) == "hello reader"
    assert adapter.calls[0].function == "greeting"
    assert adapter.tools()["greeting"].result_label.integrity.name == "UNTRUSTED"
