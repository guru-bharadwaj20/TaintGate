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
