# Isolated gateway attack lab

All fixtures use synthetic content, in-memory delivery records and `.invalid`
destinations. No real credentials, accounts, invoices or payment actions occur.

| Strict-mode regression | Expected blocked behaviour | Executable evidence |
|---|---|---|
| A4: poisoned tool description | Remote instructions excluded from planner contract | `test_a4_poisoning_never_enters_contract` |
| A5: metadata rug pull | Changed schemas/annotations blocked; quarantine latches | `test_a5_schema_rug_pull`, `test_rug_pull_stays_quarantined` |
| A6: server/tool shadowing | Registration rejects reused identities | `test_a6_namespace_shadowing` |
| A7: private data export | Reader restriction blocks even an unknown secret | `test_a7_label_blocks_unknown_secret_even_without_pattern` |
| Forged wire approval | Host policy denial prevents upstream execution | `test_real_sdk_downstream_requires_policy` |
| Peer disconnect at recheck | Denial occurs before any upstream execution | `test_disconnect_blocks_before_execution` |

The focused gateway/DLP unit and attack suite recorded **22 passing tests**.
SDK session integration recorded **2 passing tests**, with a harmless upstream
Pydantic settings warning. These are local regression results, not AgentDojo
attack-success-rate measurements or a proof for arbitrary MCP implementations.
Run `python -m pytest tests/attacks tests/integration/test_gateway_sdk.py` to
refresh the evidence. The stdio fixture starts via
`python -m taintgate.gateway.lab`; it advertises poisoned prose deliberately.

Metadata pins cannot guarantee a malicious remote server's actual semantics.
Execution-side effects require trusted implementations and capability isolation.
