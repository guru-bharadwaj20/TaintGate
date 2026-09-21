
## Trusted inputs

The user request and locally administered policy, tool contracts, server configuration and approval records are trusted. The TaintGate process and host must preserve their integrity. Planner output remains syntactically and operationally restricted; a trusted view does not imply an infallible planner.

## Untrusted inputs

Tool results, documents, email, web content, extraction output and remote tool descriptions are untrusted. Apply configured confidentiality to structured content and errors as well as plain text. No remote description establishes its own trust.

## A1: unauthorized actions

A poisoned email asks an agent to delete a file or transfer money. The runtime can call only registered tools; protected side effects require explicit policy allow and trusted control dependencies in strict mode.
