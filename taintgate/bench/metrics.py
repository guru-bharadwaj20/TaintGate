"""Aggregates are derived only from recorded grader outcomes."""
from typing import Any


def fraction(records: list[dict[str, Any]], key: str) -> float | None:
    values = [r[key] for r in records if r.get(key) is not None and not r.get('error')]
    return sum(bool(value) for value in values) / len(values) if values else None

def clean_utility(records: list[dict[str, Any]]) -> float | None:
    return fraction([r for r in records if not r['attacked']], 'utility')

def attacked_utility(records: list[dict[str, Any]]) -> float | None:
    return fraction([r for r in records if r['attacked']], 'utility')

def attack_success(records: list[dict[str, Any]]) -> dict[str, Any]:
    attacked = [r for r in records if r['attacked']]
    return {'rate':fraction(attacked,'attack_success'),
            'scored_runs':sum(r.get('attack_success') is not None and not r.get('error') for r in attacked),
            'coverage':'AgentDojo task goal graders; excludes MCP metadata poisoning and all untested attack families'}

def approvals(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_task: dict[str, int] = {}
    for record in records:
        key = record['suite'] + ':' + record['task']
        by_task[key] = by_task.get(key,0) + record.get('approvals',0)
    return {'total':sum(by_task.values()),'by_task':by_task,
            'per_run':sum(by_task.values()) / len(records) if records else None}
