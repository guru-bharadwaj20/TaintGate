
## Trusted inputs

The user request and locally administered policy, tool contracts, server configuration and approval records are trusted. The TaintGate process and host must preserve their integrity. Planner output remains syntactically and operationally restricted; a trusted view does not imply an infallible planner.

## Untrusted inputs

Tool results, documents, email, web content, extraction output and remote tool descriptions are untrusted. Apply configured confidentiality to structured content and errors as well as plain text. No remote description establishes its own trust.

## A1: unauthorized actions

A poisoned email asks an agent to delete a file or transfer money. The runtime can call only registered tools; protected side effects require explicit policy allow and trusted control dependencies in strict mode.

## A2: argument hijacking

A document substitutes an attacker email address for a user-selected recipient. Recipients derived from untrusted inputs require endorsement or a narrowly scoped approval; strings extracted under a schema remain untrusted.

## A3: exfiltration

A private invoice is sent through an email body, URL query, markdown image or final response. Reader constraints apply at sinks, and outbound rendering must not fetch attacker-controlled resources.

## A4: tool poisoning

A tool description instructs the model to disclose secrets or use another tool. Only trusted local contracts enter planner prompts; remote description scanning is supplemental and cannot prove benign intent.

## A5: metadata changes

A server changes its schema or description after approval. Canonical metadata hashes bind approval to a version; a mismatch quarantines the tool and requires a new approval.

## A6: shadowing

A server impersonates another server tool or instructs the model how to use it. Namespaces and approved local signatures keep tool identity separate from server-authored prose.
