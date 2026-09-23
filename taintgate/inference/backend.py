"""Optional CPU inference and injectable backend interface."""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class Decode:
    max_tokens: int = 256
    temperature: float = 0.0
    seed: int = 20

    def __post_init__(self) -> None:
        import math

        if type(self.max_tokens) is not int or not 1 <= self.max_tokens <= 4096:
            raise ValueError("Token limit out of bounds")
        if not math.isfinite(self.temperature) or not 0 <= self.temperature <= 2:
            raise ValueError("Temperature out of bounds")
        if type(self.seed) is not int or not -1 <= self.seed < 2**32:
            raise ValueError("Seed out of bounds")


class Backend(Protocol):
    model_id: str

    def generate(
        self, prompt: str, settings: Decode = Decode(), grammar: str | None = None
    ) -> str: ...


class LlamaCppBackend:
    def __init__(self, path: Path, sha256: str, n_ctx: int = 2048, n_threads: int = 2) -> None:
        if hashlib.file_digest(path.open("rb"), "sha256").hexdigest() != sha256:
            raise ValueError("Model hash mismatch")
        from llama_cpp import Llama

        self.model_id = sha256
        self._model: Any = Llama(
            model_path=str(path), n_gpu_layers=0, n_ctx=n_ctx, n_threads=n_threads, verbose=False
        )

    def generate(self, prompt: str, settings: Decode = Decode(), grammar: str | None = None) -> str:
        from llama_cpp.llama_grammar import LlamaGrammar

        compiled = LlamaGrammar.from_string(grammar, verbose=False) if grammar else None
        result = self._model(
            prompt,
            max_tokens=settings.max_tokens,
            temperature=settings.temperature,
            seed=settings.seed,
            grammar=compiled,
            echo=False,
        )
        text: object = result["choices"][0]["text"]
        if not isinstance(text, str):
            raise ValueError("Invalid model response")
        return text


class BudgetBackend:
    """Shared budget accounts for planner, extraction, and baseline requests."""

    def __init__(
        self,
        backend: Backend,
        max_requests: int = 4,
        max_tokens: int = 1024,
        *,
        _budget: list[int] | None = None,
    ) -> None:
        self.backend, self.model_id = backend, backend.model_id
        self._budget = [max_requests, max_tokens] if _budget is None else _budget

    def generate(self, prompt: str, settings: Decode = Decode(), grammar: str | None = None) -> str:
        if self._budget[0] <= 0 or settings.max_tokens > self._budget[1]:
            raise ValueError("Inference budget exhausted")
        self._budget[0] -= 1
        self._budget[1] -= settings.max_tokens
        return self.backend.generate(prompt, settings, grammar)

    def for_domain(self, domain: str) -> "BudgetBackend":
        from .cache import CachedBackend

        backend = (
            CachedBackend(self.backend.backend, self.backend.directory.parent, domain)
            if isinstance(self.backend, CachedBackend)
            else self.backend
        )
        return BudgetBackend(backend, _budget=self._budget)
