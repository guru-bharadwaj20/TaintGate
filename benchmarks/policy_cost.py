"""Run: python -m benchmarks.policy_cost; reports actual local timings."""
import json
import platform
import time
from taintgate.policy import Atom
from taintgate.policy.engine import Engine, NaiveEngine

def measure():
    rows = []
    policy = 'ancestry(X,Y) :- source(X,Y). ancestry(X,Z) :- ancestry(X,Y), source(Y,Z).'
    for size in (10, 25, 50, 100):
        facts = [Atom('source', (str(i), str(i+1))) for i in range(size)]
        for cls in (NaiveEngine, Engine):
            start = time.perf_counter()
            result = cls(policy, max_facts=20000, max_work=10000000).evaluate(facts)
            elapsed = time.perf_counter() - start
            rows.append({'edges': size, 'engine': cls.__name__, 'seconds': round(elapsed, 6), 'derived_and_input_facts': len(result.facts)})
    return {'python': platform.python_version(), 'platform': platform.platform(), 'results': rows}

if __name__ == '__main__':
    print(json.dumps(measure(), indent=2))
