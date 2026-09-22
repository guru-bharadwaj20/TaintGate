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

## Concrete syntax examples

```python
messages = read_mail()
for message in messages:
    fields = extract(message, {"type": "object", "properties": {"subject": {"type": "string"}}})
    if fields.subject == "meeting":
        archive(message)
```

This is syntactically valid when `read_mail` and `archive` are registered. It
does not imply authorization: untrusted selection labels reach `archive`, and
the policy may deny it. `extract` returns schema-validated data, never a call.

| Expression | Semantics |
| --- | --- |
| `a + b`, `a * b`, `a / b` | joined labels; normal scalar arithmetic |
| `a < b < c` | left-to-right, short-circuit comparison |
| `a and b`, `a or b` | short-circuit; all evaluated labels join |
| `items[index]` | container, index and selected element labels join |
| `record.field` | dictionary field lookup only |
| `len(items)` | container shape label, not every element label |
| `f"subject: {value}"` | interpolation with operand labels |
| `text.lower()` | approved string methods only |

Tuple literals, set literals, slices, comprehensions, starred arguments, format
specifiers, f-string conversions, augmented assignments, breaks and returns are
unsupported. A loop requires one name and a supported string/list/dictionary
container; the runtime enforces its iteration limit. No recursion is possible.

The defaults are 64 KiB source, 40 AST levels, 8 KiB scalar literals, 10,000
runtime fuel units, 1,000 iterations per loop and 65,536 units per result. These
are deterministic guardrails, not a host CPU or memory isolation mechanism.

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
