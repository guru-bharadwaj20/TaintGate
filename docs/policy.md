# Policy language

Policies use finite, function-free Datalog. Predicate arguments are strings,
integers, or uppercase variables. Facts and rules terminate with a period:

```text
call("c1", "send_email").
allow(C) :- call(C, "read_file").
```

Built-in decision predicates are `allow/1`, `ask/1`, and `deny/1`.
Labels and provenance are lowered to per-call facts by the gateway.
