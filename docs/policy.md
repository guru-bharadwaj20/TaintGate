# Policy language

Policies use finite, function-free Datalog. Predicate arguments are strings,
integers, or uppercase variables. Facts and rules terminate with a period:

```text
call("c1", "send_email").
allow(C) :- call(C, "read_file").
```

Built-in decision predicates are `allow/1`, `ask/1`, and `deny/1`.
Labels and provenance are lowered to per-call facts by the gateway.

## Evaluation and explanations

`Engine(program).evaluate(facts)` uses signed dependencies, SCC cycle rejection,
ordered strata and semi-naive delta rule variants. Argument indexes reduce joins
with bound variables. `NaiveEngine` is an independent fixed-point reference.
Negation checks completed lower strata; negative cycles and unsafe variables fail.
`decide(result, call_id)` uses deny, ask, allow precedence and defaults to deny.
`result.explain(fact)` bounds depth and nodes and detects cycles.

## Measured policy cost

`python -m benchmarks.policy_cost` measures transitive provenance chains. The
committed local run used Python 3.13.1 on Windows, with other project workers
running concurrently. It is a single exploratory run, not a reproducible speed
claim or AgentDojo result. The 100-edge chain produced 5,150 total facts: reference
33.900429 seconds, semi-naive 0.680439 seconds. Raw timings for 10, 25, 50 and 100
edges are in `benchmarks/policy_results.json`.
