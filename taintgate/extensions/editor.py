"""Editor diagnostics prototype, suitable for an IDE or web editor adapter."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass

from taintgate.lang import PlanError, parse_plan


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
