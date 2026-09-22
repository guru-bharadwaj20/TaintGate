# Quarantined extraction

The compiler accepts a bounded subset of JSON Schema Draft 2020-12: objects,
arrays, strings, numbers, integers, booleans, null, enum, const, local definitions
and anyOf unions. Unsupported assertion keywords fail closed. Objects use a
canonical schema-property order. Arbitrary additional properties are rejected.
GBNF constraints govern syntax; semantic validators remain mandatory and typed
strings never gain integrity. No tools are exposed to the extraction backend.
