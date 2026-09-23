import pytest

from taintgate.bench.config import RunConfig, verify_manifest
from taintgate.bench.detector import DetectorPipeline
from taintgate.bench.metrics import attack_success, attacked_utility, clean_utility
from taintgate.inference.backend import Decode


class TestBackend:
    model_id = "mock-unit-only"

    def generate(self, prompt, settings=Decode(), grammar=None):
        return "{}"


def test_utility_aggregation_records_no_estimates():
    records = [
        {"attacked": False, "utility": True},
        {"attacked": True, "utility": False, "attack_success": True},
        {"attacked": True, "utility": True, "attack_success": False},
    ]
    assert clean_utility(records) == 1
    assert attacked_utility(records) == 0.5
    assert attack_success(records)["rate"] == 0.5
    assert attacked_utility([]) is None
    assert attack_success([])["rate"] is None


def test_manifest_drift_rejected():
    manifest = RunConfig().manifest("m")
    verify_manifest(manifest, manifest)
    with pytest.raises(ValueError):
        verify_manifest(manifest, RunConfig(max_calls=1).manifest("m"))


def test_detector_fixed_threshold():
    assert DetectorPipeline(TestBackend(), lambda text: 0.1).decorate_result("hello") == "hello"
    for score in (0.5, 1.0, float("nan")):
        with pytest.raises(ValueError):
            DetectorPipeline(TestBackend(), lambda text: score).decorate_result("hello")
