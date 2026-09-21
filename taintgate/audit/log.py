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

def plan_event(run_id: str, source: str) -> Event:
    return Event("plan", run_id, {"plan_hash": hashlib.sha256(source.encode()).hexdigest()})

def boundary_event(run_id: str, *, finished: bool = False) -> Event:
    return Event("run_end" if finished else "run_start", run_id, {})

def decision_event(run_id: str, tool: str, action: str, reasons: list[str], label: dict[str, Any]) -> Event:
    if action not in {"allow", "deny", "ask"}:
        raise ValueError("Invalid audit decision")
    return Event("policy", run_id, {"tool": tool, "action": action, "reasons": reasons, "label": label})

def approval_event(run_id: str, scope: str, reason: str, kind: str = "approval") -> Event:
    if not scope or not reason or kind not in {"approval", "endorsement", "declassification"}:
        raise ValueError("Approval requires scope and reason")
    return Event(kind, run_id, {"scope": scope, "reason": reason})

def redact(value: Any) -> dict[str, str]:
    return {"redacted_sha256": hashlib.sha256(canonical(value)).hexdigest()}
