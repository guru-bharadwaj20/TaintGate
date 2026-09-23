"""Aggregates are derived only from recorded grader outcomes."""

from typing import Any


def fraction(records: list[dict[str, Any]], key: str) -> float | None:
    values = [r[key] for r in records if r.get(key) is not None and not r.get("error")]
    return sum(bool(value) for value in values) / len(values) if values else None


def clean_utility(records: list[dict[str, Any]]) -> float | None:
    return fraction([r for r in records if not r["attacked"]], "utility")


def attacked_utility(records: list[dict[str, Any]]) -> float | None:
    return fraction([r for r in records if r["attacked"]], "utility")


def attack_success(records: list[dict[str, Any]]) -> dict[str, Any]:
    attacked = [r for r in records if r["attacked"]]
    return {
        "rate": fraction(attacked, "attack_success"),
        "scored_runs": sum(
            r.get("attack_success") is not None and not r.get("error") for r in attacked
        ),
        "coverage": "AgentDojo task goal graders; excludes MCP metadata poisoning and all untested attack families",
    }


def approvals(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_task: dict[str, int] = {}
    for record in records:
        key = record["suite"] + ":" + record["task"]
        by_task[key] = by_task.get(key, 0) + record.get("approvals", 0)
    return {
        "total": sum(by_task.values()),
        "by_task": by_task,
        "per_run": sum(by_task.values()) / len(records) if records else None,
    }


def overhead(records: list[dict[str, Any]]) -> dict[str, Any]:
    import math
    import statistics

    values = sorted(v for r in records for v in r.get("overheads_seconds", []))
    return {
        "samples": len(values),
        "median_seconds": statistics.median(values) if values else None,
        "p95_seconds": values[max(0, math.ceil(0.95 * len(values)) - 1)] if values else None,
    }


def environment_metadata() -> dict[str, Any]:
    import os
    import platform
    from importlib.metadata import PackageNotFoundError, version

    versions = {}
    for package in ("agentdojo", "llama-cpp-python", "taintgate"):
        try:
            versions[package] = version(package)
        except PackageNotFoundError:
            versions[package] = "uninstalled source checkout"
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu": os.getenv("PROCESSOR_IDENTIFIER", platform.processor()),
        "logical_cpus": os.cpu_count(),
        "versions": versions,
        "memory_reference": "benchmarks/cpu_results.json contains measured peak process working set",
    }
