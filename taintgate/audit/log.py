"""Canonical hash-chained SQLite events and anchored Merkle proofs."""
from __future__ import annotations
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EVENT_KINDS = frozenset({"plan", "run_start", "run_end", "tool_call", "policy", "approval", "endorsement", "declassification"})

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

@dataclass(frozen=True)
class Event:
    kind: str
    run_id: str
    payload: dict[str, Any]

    def __post_init__(self) -> None:
        if self.kind not in EVENT_KINDS or not self.run_id:
            raise ValueError("Invalid audit event")
        canonical(self.payload)
