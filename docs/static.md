# Static preflight

The analyzer joins both branches and iterates loops to a fixed point over a
finite principal universe, integrity order and source set. Unknown values and
missing branch assignments are conservative. It reports every tool call and
marks tainted, confidential or unresolved sites as potentially unsafe.

Approval scopes bind exact plan text, canonical tool configuration, policy
configuration and recipient sets. They are descriptors, not authorization tokens;
the application must authenticate and persist the user's decision. Changes
invalidate equality. The runtime always performs policy checks independently.

Dynamic extraction results, tool-selected recipients and unresolved arguments
may require runtime approval. Static analysis never claims a concrete value
for an unknown argument and does not prove side-channel noninterference.

## Soundness boundary

The concrete interpreter and analyzer both propagate operand labels and strict
control labels. Analysis visits both outcomes of a branch and all syntactic
boolean operands, so it can overestimate a concrete execution. Missing names
and assignments on only one path become untrusted with no readers. Container
operations aggregate abstract labels conservatively; the analysis does not
model exact element indices or recipient strings obtained from extraction.

The fixed-point domain has finite configured readers and sources drawn from
the plan's registered tools. A join removes disagreement about known values,
degrades integrity and intersects readers. The configured convergence bound
depends on principal count and syntactic program size. Nonconvergence fails
preflight instead of authorizing an optimistic result.

| Case | Preflight result |
| --- | --- |
| literal trusted argument | known value, still runtime checked |
| untrusted branch controls constant action | tainted call site |
| recipient extracted from tool output | unresolved, approval may be needed |
| tool/policy/plan changes | different approval-scope digest |
| runtime exception or resource exhaustion | abort; static analysis is not a liveness guarantee |

The regression suite compares selected runtime-tainted sites to preflight
results. This provides bounded evidence of conservative prediction, not a
formal soundness proof for every accepted program. Approval scope equality
must be paired with authenticated user decisions, freshness and sink checks
by the application; equality alone never grants permission.
