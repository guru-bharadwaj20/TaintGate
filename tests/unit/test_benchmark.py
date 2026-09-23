import pytest
from taintgate.bench.config import RunConfig, verify_manifest
from taintgate.bench.metrics import clean_utility, attacked_utility, attack_success
from taintgate.bench.detector import DetectorPipeline
from taintgate.inference.backend import Decode

class TestBackend:
    model_id='mock-unit-only'
    def generate(self,prompt,settings=Decode(),grammar=None):
        return '{}'

def test_utility_aggregation_records_no_estimates():
    records=[{'attacked':False,'utility':True}, {'attacked':True,'utility':False,'attack_success':True}, {'attacked':True,'utility':True,'attack_success':False}]
    assert clean_utility(records) == 1
    assert attacked_utility(records) == .5
    assert attack_success(records)['rate'] == .5
    assert attacked_utility([]) is None
    assert attack_success([])['rate'] is None

def test_manifest_drift_rejected():
    manifest=RunConfig().manifest('m')
    verify_manifest(manifest,manifest)
    with pytest.raises(ValueError):
        verify_manifest(manifest,RunConfig(max_calls=1).manifest('m'))

def test_detector_fixed_threshold():
    assert DetectorPipeline(TestBackend(),lambda text:.1).decorate_result('hello') == 'hello'
    for score in (.5,1.,float('nan')):
        with pytest.raises(ValueError):
            DetectorPipeline(TestBackend(),lambda text:score).decorate_result('hello')
