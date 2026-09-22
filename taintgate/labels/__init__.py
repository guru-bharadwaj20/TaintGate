"""Information-flow labels: trusted <= untrusted."""
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Integrity(IntEnum):
    TRUSTED = 0
    UNTRUSTED = 1



@dataclass(frozen=True)
class Label:
    integrity: Integrity = Integrity.TRUSTED
    readers: frozenset[str] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, 'integrity', Integrity(self.integrity))
        if self.readers is not None:
            readers = frozenset(self.readers)
            if any(not isinstance(p, str) or not p for p in readers):
                raise ValueError('Principals must be nonempty strings')
            object.__setattr__(self, 'readers', readers)

    def join(self, other: 'Label') -> 'Label':
        readers = (other.readers if self.readers is None else
                   self.readers if other.readers is None else
                   self.readers & other.readers)
        return Label(max(self.integrity, other.integrity), readers)

    def flows_to(self, other: 'Label') -> bool:
        readers_ok = (self.readers is None or
                      (other.readers is not None and self.readers >= other.readers))
        return self.integrity <= other.integrity and readers_ok

    def may_read(self, principal: str) -> bool:
        return self.readers is None or principal in self.readers



def provenance_id(operation: str, parents: Iterable[str] = ()) -> str:
    payload = json.dumps([operation, sorted(set(parents))], separators=(',', ':'))
    return hashlib.sha256(payload.encode()).hexdigest()

@dataclass(frozen=True)
class Provenance:
    operation: str
    parents: frozenset[str] = frozenset()

    @property
    def id(self) -> str:
        return provenance_id(self.operation, self.parents)

    @staticmethod
    def union(*sources: Iterable[str]) -> frozenset[str]:
        return frozenset().union(*sources)

@dataclass(frozen=True)
class Labeled:
    value: Any
    label: Label = Label()
    sources: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        from types import MappingProxyType
        object.__setattr__(self, 'sources', frozenset(self.sources))
        def freeze(value: Any) -> Any:
            if isinstance(value, (list, tuple)):
                return tuple(freeze(v) for v in value)
            if isinstance(value, Mapping):
                return MappingProxyType({k: freeze(v) for k, v in value.items()})
            if type(value) in (str, bool, int, float, type(None)) or isinstance(value, Labeled):
                return value
            raise TypeError('Unsupported runtime value')
        object.__setattr__(self, 'value', freeze(self.value))
