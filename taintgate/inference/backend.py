"""Optional CPU inference and injectable backend interface."""
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
import hashlib

@dataclass(frozen=True)
class Decode:
    max_tokens: int = 256
    temperature: float = 0.0
    seed: int = 20

class Backend(Protocol):
    model_id: str
    def generate(self, prompt: str, settings: Decode = Decode(), grammar: str | None = None) -> str: ...

class LlamaCppBackend:
    def __init__(self, path: Path, sha256: str, n_ctx: int = 2048, n_threads: int = 2) -> None:
        if hashlib.file_digest(path.open('rb'), 'sha256').hexdigest() != sha256:
            raise ValueError('Model hash mismatch')
        from llama_cpp import Llama
        self.model_id = sha256
        self._model: Any = Llama(model_path=str(path), n_gpu_layers=0, n_ctx=n_ctx, n_threads=n_threads, verbose=False)

    def generate(self, prompt: str, settings: Decode = Decode(), grammar: str | None = None) -> str:
        from llama_cpp import LlamaGrammar
        compiled = LlamaGrammar.from_string(grammar, verbose=False) if grammar else None
        result = self._model(prompt, max_tokens=settings.max_tokens, temperature=settings.temperature,
                             seed=settings.seed, grammar=compiled, echo=False)
        text: object = result['choices'][0]['text']
        if not isinstance(text, str):
            raise ValueError('Invalid model response')
        return text
