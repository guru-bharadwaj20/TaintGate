"""Trusted contracts never inherit remote prose."""
from dataclasses import dataclass
import re
import rfc8785
import hashlib


def canonical_metadata(metadata: dict) -> bytes:
    """Bind all metadata, including annotations and output schemas."""
    if not isinstance(metadata, dict):
        raise ValueError("Metadata must be an object")
    return rfc8785.dumps(metadata)


def metadata_hash(metadata: dict) -> str:
    return hashlib.sha256(canonical_metadata(metadata)).hexdigest()


@dataclass(frozen=True)
class Contract:
    server: str
    tool: str
    description: str
    input_schema: dict

    def __post_init__(self):
        for value in (self.server, self.tool):
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", value):
                raise ValueError("Invalid local identity")
        if not isinstance(self.description, str) or not isinstance(self.input_schema, dict):
            raise ValueError("Invalid trusted contract")

    @property
    def name(self):
        return f"{self.server}__{self.tool}"

    def planner_metadata(self):
        return {"name": self.name, "description": self.description,
                "inputSchema": self.input_schema}
