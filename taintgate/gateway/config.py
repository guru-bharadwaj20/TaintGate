"""Local host configuration; never populated from tool metadata."""

from dataclasses import dataclass
from typing import Any

from taintgate.labels import Integrity, Label


@dataclass(frozen=True)
class ServerConfig:
    name: str
    trusted: bool = False
    readers: frozenset[str] | None = None

    @property
    def result_label(self) -> Any:
        return Label(Integrity.TRUSTED if self.trusted else Integrity.UNTRUSTED, self.readers)

    @classmethod
    def from_dict(cls, value: Any) -> Any:
        if set(value) - {"name", "trusted", "readers"}:
            raise ValueError("Unknown server configuration field")
        if type(value.get("trusted", False)) is not bool:
            raise ValueError("trusted must be boolean")
        if not isinstance(value.get("name"), str) or not value["name"]:
            raise ValueError("Missing server name")
        readers = value.get("readers")
        return cls(
            value["name"],
            value.get("trusted", False),
            None if readers is None else frozenset(readers),
        )
