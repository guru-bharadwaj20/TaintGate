"""Response cache identity includes trust domain and every decoding input."""
import hashlib
import json
from dataclasses import asdict
from .backend import Decode

def cache_key(model_id: str, prompt: str, settings: Decode, grammar: str | None, domain: str) -> str:
    if domain not in ('planner', 'extractor', 'baseline'):
        raise ValueError('Unknown cache trust domain')
    canonical = json.dumps({'format':1,'model':model_id,'prompt':prompt,
                            'settings':asdict(settings),'grammar':grammar,'domain':domain},
                           sort_keys=True,separators=(',',':'))
    return hashlib.sha256(canonical.encode()).hexdigest()
