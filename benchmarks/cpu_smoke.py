"""Explicit opt-in real CPU smoke, without network requests."""
import argparse
import json
import time
from pathlib import Path
from taintgate.inference.backend import Decode, LlamaCppBackend

def peak_ram() -> int | None:
    import sys
    if sys.platform != 'win32':
        return None
    import ctypes
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                    ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                    ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                    ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                    ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    kernel = ctypes.WinDLL('kernel32')
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    api = ctypes.WinDLL('psapi').GetProcessMemoryInfo
    api.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    if not api(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        return None
    return int(counters.PeakWorkingSetSize)

def smoke(path: Path, manifest: Path) -> dict[str, object]:
    config = json.loads(manifest.read_text(encoding='utf-8-sig'))
    started = time.perf_counter()
    backend = LlamaCppBackend(path, config['sha256'])
    load_seconds = time.perf_counter() - started
    started = time.perf_counter()
    output = backend.generate('<|im_start|>user\nReply with the word ready.<|im_end|>\n<|im_start|>assistant\n', Decode(max_tokens=16))
    latency = time.perf_counter() - started
    if not output.strip():
        raise RuntimeError('Empty CPU inference response')
    return {'model_sha256': backend.model_id, 'backend':config['backend'],
            'load_seconds':round(load_seconds,6), 'request_seconds':round(latency,6),
            'output':output, 'peak_working_set_bytes':peak_ram(), 'cpu_only':True, 'threads':2, 'context':2048}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('model', type=Path)
    parser.add_argument('--manifest', type=Path, default=Path('config/models.json'))
    args = parser.parse_args()
    print(json.dumps(smoke(args.model, args.manifest), indent=2))
