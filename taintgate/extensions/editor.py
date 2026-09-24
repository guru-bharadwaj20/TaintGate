"""Editor diagnostics prototype, suitable for an IDE or web editor adapter."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass

from taintgate.lang import PlanError, parse_plan
from taintgate.policy import PolicyError
from taintgate.policy.parser import parse


@dataclass(frozen=True)
class Diagnostic:
    line: int
    column: int
    message: str
    severity: str = "error"


def diagnostics(source: str, registered_calls: Iterable[str] = ()) -> tuple[Diagnostic, ...]:
    """Check syntax then the same allowlist as execution; never runs a plan."""
    try:
        ast.parse(source)
    except SyntaxError as error:
        return (Diagnostic(error.lineno or 1, error.offset or 1, "Invalid plan syntax"),)
    except (ValueError, RecursionError):
        return (Diagnostic(1, 1, "Invalid or excessively nested plan"),)
    try:
        parse_plan(source, registered_calls)
    except PlanError as error:
        return (Diagnostic(1, 1, str(error)),)
    return ()


@dataclass(frozen=True)
class Highlight:
    start: int
    end: int
    kind: str


_POLICY_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|-?\d+|[A-Za-z_][A-Za-z_0-9]*|:-|[(),.]')


def policy_highlights(source: str) -> tuple[Highlight, ...]:
    """Return non-executable lexical spans for a policy editor."""
    spans = []
    for token in _POLICY_TOKEN.finditer(source[:100000]):
        text = token.group()
        kind = (
            "string"
            if text.startswith('"')
            else "number"
            if text.lstrip("-").isdigit()
            else "keyword"
            if text == "not"
            else "variable"
            if text[0].isupper()
            else "predicate"
            if text[0].isalpha()
            else "punctuation"
        )
        spans.append(Highlight(token.start(), token.end(), kind))
    return tuple(spans)


def policy_diagnostics(source: str) -> tuple[Diagnostic, ...]:
    try:
        parse(source)
    except PolicyError as error:
        return (Diagnostic(1, 1, str(error)),)
    return ()
