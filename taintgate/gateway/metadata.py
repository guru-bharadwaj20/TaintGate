"""Trusted contracts never inherit remote prose."""

import difflib
import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

import rfc8785


def canonical_metadata(metadata: dict[str, Any]) -> bytes:
    """Bind all metadata, including annotations and output schemas."""
    if not isinstance(metadata, dict):
        raise ValueError("Metadata must be an object")
    return rfc8785.dumps(metadata)


def metadata_hash(metadata: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_metadata(metadata)).hexdigest()


class PinStore:
    """Only the trusted host should invoke approve; never expose it as a tool."""

    def __init__(self, path: Any) -> None:
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS pins (server TEXT, tool TEXT, digest TEXT, metadata TEXT, PRIMARY KEY(server,tool))"
        )
        self.db.commit()

    def approve(self, server: Any, tool: Any, metadata: Any) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO pins VALUES (?,?,?,?)",
            (server, tool, metadata_hash(metadata), canonical_metadata(metadata).decode()),
        )
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def matches(self, server: Any, tool: Any, metadata: Any) -> Any:
        row = self.db.execute(
            "SELECT digest FROM pins WHERE server=? AND tool=?", (server, tool)
        ).fetchone()
        return row is not None and row[0] == metadata_hash(metadata)

    def changed_tools(self, server: Any, current: Any) -> Any:
        approved = {
            row[0] for row in self.db.execute("SELECT tool FROM pins WHERE server=?", (server,))
        }
        changed = approved.symmetric_difference(current)
        changed.update(
            (name for name, metadata in current.items() if not self.matches(server, name, metadata))
        )
        return frozenset(changed)

    def diff(self, server: Any, tool: Any, metadata: Any, limit: Any = 2000) -> Any:
        if not 1 <= limit <= 10000:
            raise ValueError("Diff limit outside safe range")
        row = self.db.execute(
            "SELECT metadata FROM pins WHERE server=? AND tool=?", (server, tool)
        ).fetchone()
        before = json.dumps(json.loads(row[0]) if row else {}, sort_keys=True, indent=2)
        after = json.dumps(metadata, sort_keys=True, indent=2)
        diff = "\n".join(
            difflib.unified_diff(
                before.splitlines(), after.splitlines(), fromfile="approved", tofile="current"
            )
        )
        return diff[:limit]


class MetadataGuard:
    def __init__(self, pins: Any) -> None:
        self.pins = pins
        self.quarantined: set[tuple[str, str]] = set()

    def check(self, server: Any, tool: Any, metadata: Any) -> Any:
        identity = (server, tool)
        if not self.pins.matches(server, tool, metadata):
            self.quarantined.add(identity)
        return identity not in self.quarantined

    def reapprove(self, server: Any, tool: Any, metadata: Any) -> None:
        self.pins.approve(server, tool, metadata)
        self.quarantined.discard((server, tool))

    def planner_view(self, contracts: Any, current: Any) -> Any:
        return [
            contract.planner_metadata()
            for contract in contracts
            if (contract.server, contract.tool) in current
            and self.check(contract.server, contract.tool, current[contract.server, contract.tool])
        ]


@dataclass(frozen=True)
class Contract:
    server: str
    tool: str
    description: str
    input_schema: dict[str, Any]

    def __post_init__(self) -> None:
        for value in (self.server, self.tool):
            if not re.fullmatch("[A-Za-z][A-Za-z0-9_-]{0,63}", value):
                raise ValueError("Invalid local identity")
        if not isinstance(self.description, str) or not isinstance(self.input_schema, dict):
            raise ValueError("Invalid trusted contract")

    @property
    def name(self) -> Any:
        return f"{self.server}__{self.tool}"

    def planner_metadata(self) -> Any:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }
