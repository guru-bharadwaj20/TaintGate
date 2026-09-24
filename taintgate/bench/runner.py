"""Resumable local CPU AgentDojo runs. No provider network calls are made."""

import argparse
import json
import os
import tempfile
import time
from importlib import import_module
from pathlib import Path
from typing import Any

from taintgate.inference.backend import BudgetBackend, LlamaCppBackend
from taintgate.inference.cache import CachedBackend

from .baselines import PlainPipeline, SandwichPipeline, SpotlightPipeline
from .config import RunConfig, verify_manifest
from .detector import DetectorPipeline, PromptGuardCPU, local_detector_manifest
from .metrics import (
    approvals,
    attack_success,
    attacked_utility,
    clean_utility,
    environment_metadata,
    overhead,
)
from .taintgate_pipeline import StrictTaintgatePipeline, TaintgatePipeline

PIPELINES = {
    "plain": PlainPipeline,
    "spotlighting": SpotlightPipeline,
    "sandwich": SandwichPipeline,
    "taintgate_permissive": TaintgatePipeline,
    "taintgate_strict": StrictTaintgatePipeline,
}

DEFAULT_CONFIGURATIONS = tuple(PIPELINES)
AVAILABLE_CONFIGURATIONS = (*DEFAULT_CONFIGURATIONS, "prompt_guard_2")


def save_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, delete=False, encoding="utf-8"
    ) as temp:
        json.dump(value, temp, indent=2, ensure_ascii=False)
        temp.flush()
        os.fsync(temp.fileno())
    Path(temp.name).replace(path)


def run(
    model_path: Path,
    output: Path,
    subset_path: Path,
    configurations: tuple[str, ...] = tuple(PIPELINES),
    full: bool = False,
    prompt_guard_weights: Path | None = None,
    prompt_guard_threshold: float = 0.5,
) -> dict[str, Any]:
    if any(name not in AVAILABLE_CONFIGURATIONS for name in configurations):
        raise ValueError("Unknown benchmark configuration")
    detector_manifest = None
    if "prompt_guard_2" in configurations:
        if prompt_guard_weights is None:
            raise ValueError("prompt_guard_2 requires --prompt-guard-weights")
        detector_manifest = local_detector_manifest(prompt_guard_weights, prompt_guard_threshold)
    subset = json.loads(subset_path.read_text(encoding="utf-8-sig"))
    models = json.loads(Path("config/models.json").read_text(encoding="utf-8-sig"))
    config = RunConfig()
    suites = import_module("agentdojo.task_suite.load_suites").get_suites(config.version)
    tasks = (
        [{"suite": n, "task": t} for n, s in suites.items() for t in s.user_tasks]
        if full
        else subset["tasks"]
    )
    import hashlib

    implementation = {
        str(path.relative_to(Path(__file__).parents[1])): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in Path(__file__).parents[1].rglob("*.py")
    }
    manifest = {
        **config.manifest(models["sha256"]),
        "subset": subset,
        "configurations": list(configurations),
        "full": full,
        "implementation": implementation,
        "prompt_guard": detector_manifest,
    }
    if output.exists():
        document: dict[str, Any] = json.loads(output.read_text(encoding="utf-8-sig"))
        verify_manifest(manifest, document["manifest"])
    else:
        document = {"manifest": manifest, "environment": environment_metadata(), "records": []}
    done = {r["id"] for r in document["records"]}
    scorer = (
        PromptGuardCPU(prompt_guard_weights)
        if detector_manifest is not None and prompt_guard_weights is not None
        else None
    )
    backend = LlamaCppBackend(model_path, models["sha256"])
    for configuration in configurations:
        domain = "planner" if configuration.startswith("taintgate") else "baseline"
        cached = CachedBackend(backend, output.parent / "responses", domain)
        for task_info in tasks:
            suite = suites[task_info["suite"]]
            user_task = suite.get_user_task_by_id(task_info["task"])
            injections = list(suite.injection_tasks) if full else ["injection_task_0"]
            for injection_id in [None, *injections]:
                run_id = ":".join(
                    (configuration, task_info["suite"], task_info["task"], injection_id or "clean")
                )
                if run_id in done:
                    continue
                budgeted = BudgetBackend(
                    cached,
                    max_requests=config.max_calls,
                    max_tokens=config.max_calls * config.decoding.max_tokens,
                )
                if configuration == "prompt_guard_2":
                    if scorer is None:
                        raise ValueError("Detector scorer unavailable")
                    pipeline = DetectorPipeline(
                        budgeted, scorer, prompt_guard_threshold, config.max_calls
                    )
                else:
                    pipeline = PIPELINES[configuration](budgeted, max_calls=config.max_calls)
                injection = suite.get_injection_task_by_id(injection_id) if injection_id else None
                # Use upstream exact attack template, substituting actual model identity
                # without its provider-name lookup (which excludes local Qwen).
                attack_data: dict[str, str] = {}
                if injection is not None:
                    attacks = import_module("agentdojo.attacks.important_instructions_attacks")
                    base = import_module("agentdojo.attacks.base_attacks")
                    attack = base.FixedJailbreakAttack(
                        attacks.ImportantInstructionsAttack._JB_STRING, suite, pipeline
                    )
                    attack.model_name = "Qwen2.5-0.5B-Instruct"
                    attack.user_name = "Emma Johnson"
                    attack_data = attack.attack(user_task, injection)
                start = time.perf_counter()
                record: dict[str, Any] = {
                    "id": run_id,
                    "configuration": configuration,
                    **task_info,
                    "attacked": injection is not None,
                    "injection_task": injection_id,
                    "utility": None,
                    "attack_success": None,
                    "error": None,
                }
                try:
                    utility, success = suite.run_task_with_pipeline(
                        pipeline, user_task, injection, attack_data
                    )
                    record.update(utility=utility, attack_success=success if injection else None)
                except Exception as exc:
                    record["error"] = type(exc).__name__
                record.update(
                    wall_seconds=round(time.perf_counter() - start, 6),
                    approvals=pipeline.approvals,
                    overheads_seconds=pipeline.overheads,
                )
                document["records"].append(record)
                done.add(run_id)
                save_atomic(output, document)
                print(
                    run_id, record["utility"], record["attack_success"], record["error"], flush=True
                )
    document["summary"] = {
        name: {
            "clean_utility": clean_utility(rows),
            "attacked_utility": attacked_utility(rows),
            "attack_success": attack_success(rows),
            "approvals": approvals(rows),
            "overhead": overhead(rows),
        }
        for name in configurations
        for rows in [[r for r in document["records"] if r["configuration"] == name]]
    }
    save_atomic(output, document)
    return document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("model", type=Path)
    parser.add_argument("--output", type=Path, default=Path("artifacts/bench/results.json"))
    parser.add_argument("--subset", type=Path, default=Path("config/benchmark_subset.json"))
    parser.add_argument(
        "--configurations",
        nargs="+",
        choices=AVAILABLE_CONFIGURATIONS,
        default=DEFAULT_CONFIGURATIONS,
    )
    parser.add_argument("--prompt-guard-weights", type=Path)
    parser.add_argument("--prompt-guard-threshold", type=float, default=0.5)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--upstream-source", type=Path)
    args = parser.parse_args()
    if args.upstream_source:
        from .source_loader import load_source

        load_source(args.upstream_source)
    run(
        args.model,
        args.output,
        args.subset,
        tuple(args.configurations),
        args.full,
        args.prompt_guard_weights,
        args.prompt_guard_threshold,
    )


if __name__ == "__main__":
    main()
