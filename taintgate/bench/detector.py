"""Optional Prompt Guard 2 CPU scorer; gated weights are never downloaded implicitly."""
from collections.abc import Callable
from pathlib import Path
from typing import Any

from taintgate.inference.backend import Backend

from .baselines import PlainPipeline


class PromptGuardCPU:
    def __init__(self, local_weights: Path) -> None:
        import importlib
        transformers = importlib.import_module('transformers')
        self.torch: Any = importlib.import_module('torch')
        self.tokenizer: Any = transformers.AutoTokenizer.from_pretrained(str(local_weights),local_files_only=True)
        self.model: Any = transformers.AutoModelForSequenceClassification.from_pretrained(str(local_weights),local_files_only=True).to('cpu').eval()

    def __call__(self, text: str) -> float:
        inputs = self.tokenizer(text,return_tensors='pt',truncation=True,max_length=512)
        with self.torch.no_grad():
            logits = self.model(**inputs).logits
            score: float = float(self.torch.softmax(logits,dim=-1)[0,1].item())
        return score

class DetectorPipeline(PlainPipeline):
    name = 'prompt_guard_2'
    def __init__(self, backend: Backend, scorer: Callable[[str],float], threshold: float = .5, max_calls: int = 4) -> None:
        import math
        if not math.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError('Invalid fixed detector threshold')
        super().__init__(backend,max_calls)
        self.scorer,self.threshold = scorer,threshold

    def decorate_result(self, text: str) -> str:
        import math
        score = self.scorer(text)
        if not math.isfinite(score) or not 0 <= score <= 1 or score >= self.threshold:
            raise ValueError('Detector rejected untrusted tool result')
        return text
