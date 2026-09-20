"""Bounded, function-free Datalog policies.

Syntax: facts and rules end in periods; variables begin uppercase. Bodies use
commas and ``not`` for negation. Constants are quoted strings or integers.
Decision predicates take one call identifier: allow/1, ask/1, deny/1.
"""
from dataclasses import dataclass
from typing import Union

@dataclass(frozen=True)
class Var:
    name: str

Term = Union[Var, str, int]

@dataclass(frozen=True)
class Atom:
    predicate: str
    args: tuple[Term, ...]
    negated: bool = False

@dataclass(frozen=True)
class Rule:
    head: Atom
    body: tuple[Atom, ...]

@dataclass(frozen=True)
class Program:
    facts: tuple[Atom, ...] = ()
    rules: tuple[Rule, ...] = ()

class PolicyError(ValueError):
    pass

BUILTIN_ARITIES = {'allow': 1, 'ask': 1, 'deny': 1, 'call': 2,
                   'untrusted_recipient': 1, 'reader_denied': 1,
                   'approval_required': 1, 'source': 2}
