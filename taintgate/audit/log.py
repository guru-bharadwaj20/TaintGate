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

class AuditLog:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self.connection = sqlite3.connect(str(path))
        self.connection.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, event BLOB NOT NULL, prev TEXT NOT NULL, digest TEXT NOT NULL)")
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def rows(self) -> list[tuple[int, bytes, str, str]]:
        return list(self.connection.execute("SELECT seq,event,prev,digest FROM events ORDER BY seq"))

    def append(self, event: Event) -> str:
        payload = canonical({"kind": event.kind, "run_id": event.run_id, "payload": event.payload})
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            last = self.connection.execute("SELECT seq,digest FROM events ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (last[0]+1, last[1]) if last else (1, "0"*64)
            digest = hashlib.sha256(bytes.fromhex(prev) + payload).hexdigest()
            self.connection.execute("INSERT INTO events VALUES (?,?,?,?)", (seq, payload, prev, digest))
            self.connection.commit()
            return digest
        except BaseException:
            self.connection.rollback()
            raise

    def verify(self) -> bool:
        previous = "0"*64
        for expected, (seq, payload, prev, digest) in enumerate(self.rows(), 1):
            if seq != expected or prev != previous:
                return False
            if hashlib.sha256(bytes.fromhex(previous) + payload).hexdigest() != digest:
                return False
            previous = digest
        return True


def leaf_hash(payload: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + payload).digest()

def parent_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()

def merkle_levels(payloads: list[bytes]) -> list[list[bytes]]:
    if not payloads:
        return [[hashlib.sha256(b"\x02").digest()]]
    levels = [[leaf_hash(p) for p in payloads]]
    while len(levels[-1]) > 1:
        current = levels[-1]
        levels.append([parent_hash(current[i], current[i+1] if i+1<len(current) else current[i]) for i in range(0,len(current),2)])
    return levels

def checkpoint(log: AuditLog) -> dict[str, Any]:
    rows = log.rows()
    return {"count": len(rows), "root": merkle_levels([r[1] for r in rows])[-1][0].hex(), "head": rows[-1][3] if rows else "0"*64}

def verify_checkpoint(log: AuditLog, anchor: dict[str, Any]) -> bool:
    return log.verify() and checkpoint(log) == anchor
