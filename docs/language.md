# TaintScript

| Construct | Supported boundary |
| --- | --- |
| Values | strings, booleans, integers, floats, None |
| Containers | immutable labelled lists and dictionaries |
| Statements | single-name assignment, if/else, bounded for, expression calls |
| Expressions | arithmetic, comparison, boolean, index, f-string |
| Calls | registered tools, extract, len, selected string methods |

Imports, functions, classes, mutation, comprehensions, exceptions, reflection,
and arbitrary host-object attributes are excluded.

## Control-flow modes

Strict mode is the default. Every protected call receives a program-counter
label. Control dependencies remain sticky after a branch, including untaken
branches, because termination and errors can affect whether later calls occur.
This conservatively reduces task success. Runtime authorization still applies.
