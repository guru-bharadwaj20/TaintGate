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

`strict=False` is an experimental permissive mode: branch-local counter labels
still apply, but persistent control labels do not. It cannot protect untaken
assignments or later actions against termination-sensitive influence and must
not be presented as a security-equivalent alternative.

Loop selection and termination depend on container shape; each iteration and
body has the shape counter label. Any expression may fail after reading data,
so strict mode also retains evaluated operand labels. Errors stop execution;
no later action is attempted. This is conservative action mediation, not a
proof that timing, termination or host resource usage are unobservable.
