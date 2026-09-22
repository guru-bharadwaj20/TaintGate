"""Conservative preflight analysis; never replaces runtime mediation."""
import ast
import hashlib
import json
from dataclasses import dataclass, field
from taintgate.labels import Label, Integrity
from taintgate.lang import parse_plan


@dataclass(frozen=True)
class AbstractValue:
    label: Label = Label()
    shape: Label = Label()
    sources: frozenset[str] = frozenset()
    known: object = None
    resolved: bool = False

    def join(self, other):
        same = self.resolved and other.resolved and self.known == other.known
        return AbstractValue(self.label.join(other.label), self.shape.join(other.shape),
                             self.sources | other.sources, self.known if same else None, same)
