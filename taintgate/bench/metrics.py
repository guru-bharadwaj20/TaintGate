"""Aggregates are derived only from recorded grader outcomes."""
from typing import Any

def fraction(records: list[dict[str, Any]], key: str) -> float | None:
    values = [r[key] for r in records if r.get(key) is not None and not r.get('error')]
    return sum(bool(value) for value in values) / len(values) if values else None

def clean_utility(records: list[dict[str, Any]]) -> float | None:
    return fraction([r for r in records if not r['attacked']], 'utility')
