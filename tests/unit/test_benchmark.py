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


def test_local_detector_manifest_binds_files_and_threshold(tmp_path):
    from taintgate.bench.detector import local_detector_manifest

    (tmp_path / "config.json").write_text("{}")
    (tmp_path / "model.safetensors").write_bytes(b"test fixture, not model weights")
    original = local_detector_manifest(tmp_path, 0.5)
    assert original["local_files_only"] is True
    assert original["device"] == "cpu"
    assert original != local_detector_manifest(tmp_path, 0.6)
    (tmp_path / "model.safetensors").write_bytes(b"changed fixture")
    with pytest.raises(ValueError, match="manifest differs"):
        verify_manifest(original, local_detector_manifest(tmp_path, 0.5))
    with pytest.raises(ValueError):
        local_detector_manifest(tmp_path, float("nan"))


def test_detector_runner_requires_local_weights_before_model_loading(tmp_path):
    from taintgate.bench.runner import AVAILABLE_CONFIGURATIONS, DEFAULT_CONFIGURATIONS, run

    assert "prompt_guard_2" in AVAILABLE_CONFIGURATIONS
    assert "prompt_guard_2" not in DEFAULT_CONFIGURATIONS
    with pytest.raises(ValueError, match="requires --prompt-guard-weights"):
        run(
            tmp_path / "missing.gguf",
            tmp_path / "results.json",
            tmp_path / "subset.json",
            configurations=("prompt_guard_2",),
        )
    with pytest.raises(ValueError, match="configuration and weights"):
        run(
            tmp_path / "missing.gguf",
            tmp_path / "results.json",
            tmp_path / "subset.json",
            configurations=("prompt_guard_2",),
            prompt_guard_weights=tmp_path,
        )
