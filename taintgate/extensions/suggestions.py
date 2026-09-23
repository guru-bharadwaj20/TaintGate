"""Manual-review hints from authenticated user-approved call traces."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicySuggestion:
    tool: str
    recipients: tuple[str, ...]
    review_required: bool = True


def suggest_from_approved_traces(
    events: Iterable[Mapping[str, Any]], known_tools: Iterable[str]
) -> tuple[PolicySuggestion, ...]:
    """Never installs policies or generalizes arbitrary argument values."""
    known = frozenset(known_tools)
    grouped: dict[str, set[str]] = {}
    for event in events:
        if event.get("action") != "allow" or event.get("user_approved") is not True:
            continue
        tool, recipient = event.get("tool"), event.get("recipient")
        if (
            not isinstance(tool, str)
            or tool not in known
            or not isinstance(recipient, str)
            or not recipient
        ):
            continue
        grouped.setdefault(tool, set()).add(recipient)
    return tuple(
        PolicySuggestion(tool, tuple(sorted(recipients)))
        for tool, recipients in sorted(grouped.items())
    )
