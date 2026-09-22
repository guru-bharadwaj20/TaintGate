# Label model

Integrity is ordered `TRUSTED <= UNTRUSTED`; combining data never improves
integrity. Principals are nonempty strings. `readers=None` means every principal
may read; an empty reader set means nobody may read. These are distinct values.

Confidentiality is ordered by reversed set inclusion: fewer permitted readers
means more restricted information. Public is the identity for intersection.

A label flows to another when its readers contain all target readers. Public
is below every finite reader set; the empty set is the confidentiality top.

For reader intersection, `ALL ∩ R = R` and `R ∩ ALL = R`; represent ALL
as None instead of enumerating an incomplete principal universe.

Endorsement requires explicit user authority over a named source and action,
bound to the current plan and policy. A model cannot endorse its own output.

Declassification requires the data owner’s authorization for the specific
recipient, operation and data provenance. Public release must be explicit.

A relaxation implementation must verify a scoped approval before changing
labels and append the previous label, new label, approval identity and source
identifiers to the audit log. This package deliberately exposes no automatic
label-relaxation operation.

## API and worked joins

| Operation | Result |
| --- | --- |
| `Label()` | trusted, public |
| `Label(UNTRUSTED, {"owner"})` | untrusted, owner-readable |
| public trusted joined with owner-only untrusted | untrusted, owner-only |
| readers `{owner, audit}` joined with `{owner}` | readers `{owner}` |
| readers `{owner}` joined with `{outside}` | empty reader set |
| `a.flows_to(b)` | integrity is no stronger and source readers include destination readers |
| `a.may_read(p)` | true for public or an explicitly permitted principal |

`Labeled(value, label, sources)` freezes dictionaries and lists to prevent alias
mutation. A literal container has a shape label, with each evaluated element
retaining its own label. Indexing joins shape, index and selected element labels.
A tool sink receives the recursive join of all element labels, so wrapping a
secret in a public-shaped list cannot make it public. `len` reads shape only;
strict mode may nevertheless retain earlier element-evaluation dependencies.

Provenance IDs are SHA-256 hashes of an operation name and sorted unique parent
IDs. The interpreter exposes operation edges and label metadata in its trace,
without raw data. Caller-provided source IDs should represent authenticated
source records; a provenance ID alone is not an authentication or trust claim.

The finite examples in unit tests exhaustively check commutativity,
associativity, idempotence and upper bounds over both integrity values and four
reader sets. They verify this implementation's representative lattice cases;
they are not a mechanized proof over all possible principal sets.
