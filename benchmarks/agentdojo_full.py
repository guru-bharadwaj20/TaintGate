"""Aggregate the completed AgentDojo comparison from unmodified checkpoint records.

Inputs are the per-configuration checkpoints in artifacts/bench and the migration
archive, whose checkpoint copies identify which records were measured on the
original host. Metrics come only from recorded upstream grader outcomes.
"""

import argparse
import json
import math
import statistics
import zipfile
from importlib import import_module
from pathlib import Path
from typing import Any

from taintgate.bench.metrics import (
    approvals,
    attack_success,
    attacked_utility,
    clean_utility,
    overhead,
)

CONFIGURATIONS = {
    "plain": "plain_results.json",
    "spotlighting": "spotlighting_results.json",
    "sandwich": "sandwich_results.json",
    "prompt_guard_2": "prompt_guard_full_results.json",
    "taintgate_permissive": "taintgate_permissive_results.json",
    "taintgate_strict": "taintgate_strict_results.json",
}


def expected_cases(version: str) -> list[str]:
    suites = import_module("agentdojo.task_suite.load_suites").get_suites(version)
    cases = []
    for suite_name, suite in suites.items():
        for task in suite.user_tasks:
            cases.append(f"{suite_name}:{task}:clean")
            cases.extend(f"{suite_name}:{task}:{injection}" for injection in suite.injection_tasks)
    return cases


def timing(values: list[float]) -> dict[str, Any]:
    ordered = sorted(values)
    return {
        "runs": len(ordered),
        "total_seconds": round(sum(ordered), 6),
        "median_seconds": statistics.median(ordered) if ordered else None,
        "p95_seconds": ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)] if ordered else None,
    }


def count(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    scored = [r for r in records if r.get(key) is not None and not r.get("error")]
    return {"passed": sum(bool(r[key]) for r in scored), "scored": len(scored)}


class NoOpAgent:
    """Diagnostic agent that makes no model or tool calls."""

    name = "noop"

    def query(
        self, query: str, runtime: Any, env: Any, messages: Any = (), extra_args: Any = None
    ) -> tuple[Any, ...]:
        trace = [
            {"role": "user", "content": [{"type": "text", "content": query}]},
            {"role": "assistant", "content": [{"type": "text", "content": ""}], "tool_calls": None},
        ]
        return query, runtime, env, trace, extra_args or {}


def no_op_clean_passes(version: str) -> list[str]:
    suites = import_module("agentdojo.task_suite.load_suites").get_suites(version)
    passed = []
    for suite_name, suite in suites.items():
        for task_id, task in suite.user_tasks.items():
            utility, _ = suite.run_task_with_pipeline(NoOpAgent(), task, None, {})
            if utility:
                passed.append(f"{suite_name}:{task_id}")
    return passed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoints", type=Path, default=Path("artifacts/bench"))
    parser.add_argument(
        "--archive", type=Path, default=Path("artifacts/taintgate-windows-resume.zip")
    )
    parser.add_argument(
        "--original-host", type=Path, default=Path("artifacts/migration/original-host.json")
    )
    parser.add_argument("--new-host", type=Path, default=Path("artifacts/migration/new-host.json"))
    parser.add_argument(
        "--output", type=Path, default=Path("benchmarks/agentdojo_full_results.json")
    )
    parser.add_argument(
        "--cache-output", type=Path, default=Path("benchmarks/agentdojo_response_cache.json")
    )
    args = parser.parse_args()

    with zipfile.ZipFile(args.archive) as archive:
        original = {
            name: {r["id"] for r in json.loads(archive.read(f"artifacts/bench/{file}"))["records"]}
            for name, file in CONFIGURATIONS.items()
        }
    configurations: dict[str, Any] = {}
    version = None
    for name, file in CONFIGURATIONS.items():
        document = json.loads((args.checkpoints / file).read_text(encoding="utf-8-sig"))
        manifest, records = document["manifest"], document["records"]
        if manifest["configurations"] != [name] or not manifest["full"]:
            raise SystemExit(f"{file}: unexpected configuration identity")
        version = version or manifest["run"]["version"]
        expected = {f"{name}:{case}" for case in expected_cases(manifest["run"]["version"])}
        ids = [r["id"] for r in records]
        if len(ids) != len(set(ids)) or set(ids) != expected:
            raise SystemExit(f"{file}: coverage differs from the pinned task registry")
        if not original[name] <= set(ids):
            raise SystemExit(f"{file}: original-host records are missing")
        clean = [r for r in records if not r["attacked"]]
        attacked = [r for r in records if r["attacked"]]
        configurations[name] = {
            "manifest": manifest,
            "checkpoint_environment": document["environment"],
            "runs": len(records),
            "clean_runs": len(clean),
            "attacked_runs": len(attacked),
            "errors": sum(bool(r.get("error")) for r in records),
            "clean_utility": {**count(clean, "utility"), "rate": clean_utility(records)},
            "attacked_utility": {**count(attacked, "utility"), "rate": attacked_utility(records)},
            "attack_success": {**count(attacked, "attack_success"), **attack_success(records)},
            "approvals": approvals(records),
            "tool_call_overhead": overhead(records),
            "wall_clock_by_host": {
                "original": timing(
                    [r["wall_seconds"] for r in records if r["id"] in original[name]]
                ),
                "resumed": timing(
                    [r["wall_seconds"] for r in records if r["id"] not in original[name]]
                ),
            },
            "original_host_record_ids": sorted(original[name]),
            "records": records,
        }
    if version is None:
        raise SystemExit("No checkpoints found")

    orphans = []
    by_id = {r["id"]: r for item in configurations.values() for r in item["records"]}
    for path in sorted(args.checkpoints.glob("tmp*")):
        partial = json.loads(path.read_text(encoding="utf-8-sig"))
        outcome = ("utility", "attack_success", "error", "approvals")
        orphans.append(
            {
                "file": path.name,
                "configurations": partial["manifest"]["configurations"],
                "records": len(partial["records"]),
                "differs_from_final": [
                    r["id"]
                    for r in partial["records"]
                    if any(r[k] != by_id[r["id"]][k] for k in outcome)
                ],
            }
        )

    responses = args.checkpoints / "responses"
    cache = {
        domain.name: {
            path.stem: json.loads(path.read_text(encoding="utf-8"))["text"]
            for path in sorted(domain.glob("*.json"))
        }
        for domain in sorted(responses.iterdir())
        if domain.is_dir()
    }
    result = {
        "format": 1,
        "scope": "Complete pinned AgentDojo v1 important_instructions comparison; "
        "rates are upstream grader outcomes with explicit denominators.",
        "hosts": {
            "original": json.loads(args.original_host.read_text(encoding="utf-8")),
            "resumed": json.loads(args.new_host.read_text(encoding="utf-8")),
            "note": "Checkpoint 'environment' fields describe the host that created each "
            "checkpoint; wall clock is split by host and must not be pooled.",
        },
        "diagnostics": {
            "no_op_agent_clean_utility_passes": no_op_clean_passes(version),
            "note": "Tasks whose upstream utility grader passes when the agent makes no "
            "calls. Diagnostic only; not a benchmark configuration.",
        },
        "unreplaced_atomic_writes": {
            "files": orphans,
            "note": "Temporary checkpoint writes left when a replace failed. Each extra "
            "record was rerun from the checkpoint; differs_from_final lists any record "
            "whose grader outcome changed on rerun.",
        },
        "response_cache_entries": {domain: len(items) for domain, items in cache.items()},
        "configurations": configurations,
    }
    args.output.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    args.cache_output.write_text(json.dumps(cache, indent=1) + "\n", encoding="utf-8")
    for name, item in configurations.items():
        print(
            name,
            "clean",
            item["clean_utility"],
            "attacked",
            item["attacked_utility"],
            "asr",
            {k: item["attack_success"][k] for k in ("passed", "scored")},
            "errors",
            item["errors"],
        )


if __name__ == "__main__":
    main()
