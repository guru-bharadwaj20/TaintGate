"""Optional Prompt Guard 2 CPU scorer; gated weights are never downloaded implicitly."""

import hashlib
import math
from collections.abc import Callable
from pathlib import Path
from typing import Any

from taintgate.inference.backend import Backend

from .baselines import PlainPipeline


class PromptGuardCPU:
    def __init__(self, local_weights: Path) -> None:
        import importlib

        transformers = importlib.import_module("transformers")
        self.torch: Any = importlib.import_module("torch")
        self.tokenizer: Any = transformers.AutoTokenizer.from_pretrained(
            str(local_weights), local_files_only=True
        )
        self.model: Any = (
            transformers.AutoModelForSequenceClassification.from_pretrained(
                str(local_weights), local_files_only=True
            )
            .to("cpu")
            .eval()
        )

    def __call__(self, text: str) -> float:
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with self.torch.no_grad():
            logits = self.model(**inputs).logits
            score: float = float(self.torch.softmax(logits, dim=-1)[0, 1].item())
        return score


class DetectorPipeline(PlainPipeline):
    name = "prompt_guard_2"

    def __init__(
        self,
        backend: Backend,
        scorer: Callable[[str], float],
        threshold: float = 0.5,
        max_calls: int = 4,
    ) -> None:
        import math

        if not math.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ValueError("Invalid fixed detector threshold")
        super().__init__(backend, max_calls)
        self.scorer, self.threshold = scorer, threshold

    def decorate_result(self, text: str) -> str:
        import math

        score = self.scorer(text)
        if not math.isfinite(score) or not 0 <= score <= 1 or score >= self.threshold:
            raise ValueError("Detector rejected untrusted tool result")
        return text


def local_detector_manifest(local_weights: Path, threshold: float) -> dict[str, Any]:
    """Bind a local-only detector to every file and its fixed decision threshold."""
    if not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Invalid fixed detector threshold")
    if not local_weights.is_dir():
        raise ValueError("Prompt Guard requires an existing local weights directory")
    files: dict[str, str] = {}
    for path in sorted(local_weights.rglob("*")):
        if path.is_symlink():
            raise ValueError("Detector weights must not contain symlinks")
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            files[path.relative_to(local_weights).as_posix()] = digest.hexdigest()
    if "config.json" not in files or not any(
        name.endswith((".safetensors", ".bin")) for name in files
    ):
        raise ValueError("Local detector configuration and weights are required")
    return {
        "model": "Prompt Guard 2",
        "device": "cpu",
        "threshold": threshold,
        "local_files_only": True,
        "files_sha256": files,
    }
