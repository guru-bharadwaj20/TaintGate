# Optional prototypes

`taintgate.extensions.editor.diagnostics` reports syntax and allowlist errors
without executing a plan. It is an editor-facing API, not an installed IDE
extension or language server. Execution and preflight still perform independent
validation; a clean editor diagnostic does not authorize any tool call.

`policy_highlights` additionally provides lexical spans for Datalog variables,
predicates, strings, numbers and punctuation. `policy_diagnostics` invokes the
same bounded policy parser used by the engine. The prototype reports unsupported
syntax; it does not grant approvals or modify the active policy.
