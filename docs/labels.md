# Label model

Integrity is ordered `TRUSTED <= UNTRUSTED`; combining data never improves
integrity. Principals are nonempty strings. `readers=None` means every principal
may read; an empty reader set means nobody may read. These are distinct values.

Confidentiality is ordered by reversed set inclusion: fewer permitted readers
means more restricted information. Public is the identity for intersection.
