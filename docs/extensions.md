# Optional prototypes

`taintgate.extensions.editor.diagnostics` reports syntax and allowlist errors
without executing a plan. It is an editor-facing API, not an installed IDE
extension or language server. Execution and preflight still perform independent
validation; a clean editor diagnostic does not authorize any tool call.
