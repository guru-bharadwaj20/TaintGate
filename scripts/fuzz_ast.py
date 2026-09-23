"""Seeded parser smoke fuzzing with JSON crash artifacts and explicit replay."""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from taintgate.lang import PlanError, parse_plan


def run_case(source: str) -> None:
    try:
        parse_plan(source, {'send', 'read'})
    except PlanError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--seed', type=int, default=20261002)
    parser.add_argument('--cases', type=int, default=1000)
    parser.add_argument('--output', type=Path, default=Path('artifacts/fuzz/ast-crash.json'))
    parser.add_argument('--replay', type=Path)
    args = parser.parse_args()
    if args.replay:
        run_case(json.loads(args.replay.read_text(encoding='utf-8'))['source'])
        return
    rng = random.Random(args.seed)
    alphabet = 'abc0123[]{}():=+-*/\n \'"_.'
    for index in range(args.cases):
        source = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(200)))
        try:
            run_case(source)
        except Exception as error:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps({'seed': args.seed, 'case': index,
                                               'source': source, 'error': type(error).__name__}),
                                   encoding='utf-8')
            raise SystemExit(f'Unexpected parser failure retained at {args.output}') from None
    print(f'AST smoke fuzz: {args.cases} cases, seed {args.seed}, no unexpected failures')


if __name__ == '__main__':
    main()
