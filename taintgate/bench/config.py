"""Fixed run budgets and cache manifests for reproducible comparisons."""
from dataclasses import asdict, dataclass
from typing import Any
from taintgate.inference.backend import Decode

@dataclass(frozen=True)
class RunConfig:
    revision: str = '089ed468cf3ed0322acc66b0211f26d9d90dbf60'
    version: str = 'v1'
    seed: int = 20
    max_calls: int = 4
    decoding: Decode = Decode()
    human_approval: str = 'record ask and stop; no automatic approval'

    def manifest(self, model_hash: str) -> dict[str,Any]:
        return {'format':1,'model_sha256':model_hash,'run':asdict(self)}

def verify_manifest(expected: dict[str, Any], existing: dict[str, Any]) -> None:
    if expected != existing:
        raise ValueError('Benchmark cache manifest differs from configured run')
