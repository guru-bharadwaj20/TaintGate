from pathlib import Path
﻿"""Response cache identity includes trust domain and every decoding input."""
import hashlib
import json
from dataclasses import asdict

from .backend import Backend, Decode


def cache_key(model_id: str, prompt: str, settings: Decode, grammar: str | None, domain: str) -> str:
    if domain not in ('planner', 'extractor', 'baseline'):
        raise ValueError('Unknown cache trust domain')
    canonical = json.dumps({'format':1,'model':model_id,'prompt':prompt,
                            'settings':asdict(settings),'grammar':grammar,'domain':domain},
                           sort_keys=True,separators=(',',':'))
    return hashlib.sha256(canonical.encode()).hexdigest()


class CachedBackend:
    def __init__(self, backend: 'Backend', directory: Path, domain: str) -> None:
        if domain not in ('planner', 'extractor', 'baseline'):
            raise ValueError('Unknown cache trust domain')
        self.backend, self.directory, self.domain = backend, directory / domain, domain
        self.model_id = backend.model_id
        self.directory.mkdir(parents=True, exist_ok=True)

    def generate(self, prompt: str, settings: Decode = Decode(), grammar: str | None = None) -> str:
        key = cache_key(self.model_id, prompt, settings, grammar, self.domain)
        path = self.directory / (key + '.json')
        if path.exists():
            item = json.loads(path.read_text())
            if item.get('key') != key or not isinstance(item.get('text'), str):
                raise ValueError('Invalid cache entry')
            return str(item['text'])
        response = self.backend.generate(prompt, settings, grammar)
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', dir=self.directory, delete=False, encoding='utf-8') as temp:
            json.dump({'key':key,'text':response}, temp)
        Path(temp.name).replace(path)
        return response
