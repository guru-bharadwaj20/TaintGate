# Manual policy suggestion prototype

`suggest_from_approved_traces` groups recipients for known tools only when the
trusted audit consumer marks a successful action `user_approved=True`. The
result is a manual-review hint, not an installed Datalog rule or approval.
Ordinary allow decisions, denied actions and unknown tools do not generate
hints. The adapter never extracts message bodies or secret argument values.

Authenticate the audit source before passing events. A boolean field supplied
by untrusted tool output is not evidence of user approval. Review the exact
recipient and tool scope, then use the normal policy change workflow. Avoid
generalizing a single approved action into a blanket authorization.
