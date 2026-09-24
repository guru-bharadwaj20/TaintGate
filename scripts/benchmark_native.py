"""Compare a specialized positive recursive rule with a matching Python oracle."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from statistics import median

from taintgate.policy import Atom
from taintgate.policy.engine import Engine


def python_closure(size: int) -> set[tuple[int, int]]:
    edges = [(i, i + 1) for i in range(size - 1)]
    index: dict[int, list[int]] = {}
    for source, target in edges:
        index.setdefault(source, []).append(target)
    known = set(edges)
    delta = known.copy()
    while delta:
        delta = {
            (source, target) for source, middle in delta for target in index.get(middle, [])
        } - known
        known.update(delta)
    return known


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--size", type=int, default=100)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--output", type=Path, default=Path("artifacts/native/benchmark.json"))
    args = parser.parse_args()
    if not 2 <= args.size <= 2000:
        parser.error("size must be 2..2000")
    if not 1 <= args.repeat <= 20:
        parser.error("repeat must be 1..20")
    reference_times, policy_times, native_times = [], [], []
    engine = Engine("reach(X,Y) :- edge(X,Y). reach(X,Z) :- reach(X,Y), edge(Y,Z).")
    facts = [Atom("edge", (i, i + 1)) for i in range(args.size - 1)]
    for _ in range(args.repeat):
        started = time.perf_counter_ns()
        reference = python_closure(args.size)
        reference_times.append(time.perf_counter_ns() - started)
        started = time.perf_counter_ns()
        evaluation = engine.evaluate(facts)
        policy_times.append(time.perf_counter_ns() - started)
        if {fact.args for fact in evaluation.facts if fact.predicate == "reach"} != reference:
            raise SystemExit("Python policy engine differs from reference")
        native = json.loads(
            subprocess.run(
                [str(args.binary.resolve()), str(args.size)],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout
        )
        if native["facts"] != len(reference):
            raise SystemExit("Native result differs from Python reference")
        native_times.append(native["elapsed_ns"])
    result = {
        "size": args.size,
        "facts": len(reference),
        "repeat": args.repeat,
        "python_reference_elapsed_ns": median(reference_times),
        "python_policy_elapsed_ns": median(policy_times),
        "native_elapsed_ns": median(native_times),
        "scope": "positive reachability rule only",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
