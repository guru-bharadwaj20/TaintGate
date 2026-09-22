# Quarantined extraction

The compiler accepts a bounded subset of JSON Schema Draft 2020-12: objects,
arrays, strings, numbers, integers, booleans, null, enum, const, local definitions
and anyOf unions. Unsupported assertion keywords fail closed. Objects use a
canonical schema-property order. Arbitrary additional properties are rejected.
GBNF constraints govern syntax; semantic validators remain mandatory and typed
strings never gain integrity. No tools are exposed to the extraction backend.

Email, date and date-time formats are checked by the post-decoding format
validator. GBNF restricts their JSON representation but does not establish
semantic correctness. Numeric ranges and Unicode string lengths also need
post-validation: escaped surrogate pairs differ from grammar token counts.
