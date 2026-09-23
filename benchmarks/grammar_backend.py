"""Test actual llama.cpp grammar masking using a pinned local vocabulary."""

import ctypes
import math
from pathlib import Path
from typing import Any


class GrammarRecognizer:
    def __init__(self, path: Path) -> None:
        from llama_cpp import Llama

        self.model: Any = Llama(
            model_path=str(path), vocab_only=True, n_gpu_layers=0, verbose=False
        )

    def accepts(self, grammar: str, text: str) -> bool:
        import llama_cpp as cpp

        vocab = cpp.llama_model_get_vocab(self.model._model.model)
        sampler = cpp.llama_sampler_init_grammar(vocab, grammar.encode(), b"root")
        if not sampler:
            raise ValueError("Backend rejected grammar")
        try:
            tokens = self.model.tokenize(text.encode(), add_bos=False, special=False) + [
                self.model.token_eos()
            ]
            for token in tokens:
                item = cpp.llama_token_data(token, 0.0, 0.0)
                candidates = cpp.llama_token_data_array(ctypes.pointer(item), 1, -1, False)
                cpp.llama_sampler_apply(sampler, ctypes.byref(candidates))
                if not math.isfinite(item.logit):
                    return False
                cpp.llama_sampler_accept(sampler, token)
            return True
        finally:
            cpp.llama_sampler_free(sampler)
