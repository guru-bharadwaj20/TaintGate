# Three-minute demonstration

Use synthetic fixtures and a fresh environment. No real email, account, money or
private file is used. Run `taintgate demo` for the reproducible CLI scenario.

| Time | Action | Evidence |
| --- | --- | --- |
| 0:00–0:30 | Explain the trusted planner and untrusted email boundary | Threat-model diagram |
| 0:30–1:00 | Show the poisoned email's attacker-selected recipient | Synthetic attack fixture |
| 1:00–1:40 | Run the demo: a trusted send succeeds and the poisoned recipient fails | Decisions and one recorded send |
| 1:40–2:10 | Start `taintgate ui`, enter the printed local token and run the same plan | Timeline, labels and derivation explanation |
| 2:10–2:35 | Run the rug-pull regression tests and show metadata quarantine | Changed approval hash and diff |
| 2:35–3:00 | Demonstrate edited audit data and anchored truncation | Verification fails |

The plain-agent attack lab demonstrates what an unguarded tool call permits;
it is not a substitute for AgentDojo measurements. Present benchmark success
rates only after the actual comparative evaluation.
