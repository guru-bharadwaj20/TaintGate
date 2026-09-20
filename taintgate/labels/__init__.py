"""Information-flow labels: trusted <= untrusted."""
from enum import IntEnum


class Integrity(IntEnum):
    TRUSTED = 0
    UNTRUSTED = 1

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Label:
    integrity: Integrity = Integrity.TRUSTED
    readers: frozenset[str] | None = None

    def __post_init__(self):
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
