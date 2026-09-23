# Three-minute demonstration

Use synthetic fixtures and a fresh environment. No real email, account, money or
private file is used. Run `taintgate demo` for the reproducible CLI scenario.

| Time | Action | Evidence |
| --- | --- | --- |
| 0:00Ã¢â‚¬â€œ0:30 | Explain the trusted planner and untrusted email boundary | Threat-model diagram |
| 0:30Ã¢â‚¬â€œ1:00 | Show the poisoned email's attacker-selected recipient | Synthetic attack fixture |
| 1:00Ã¢â‚¬â€œ1:40 | Run the demo: a trusted send succeeds and the poisoned recipient fails | Decisions and one recorded send |
| 1:40Ã¢â‚¬â€œ2:10 | Start `taintgate ui`, enter the printed local token and run the same plan | Timeline, labels and derivation explanation |
| 2:10Ã¢â‚¬â€œ2:35 | Run the rug-pull regression tests and show metadata quarantine | Changed approval hash and diff |
| 2:35Ã¢â‚¬â€œ3:00 | Demonstrate edited audit data and anchored truncation | Verification fails |

The plain-agent attack lab demonstrates what an unguarded tool call permits;
it is not a substitute for AgentDojo measurements. Present benchmark success
rates only after the actual comparative evaluation.

## Recorded evidence

Run `python scripts/record_demo.py` to reproduce `benchmarks/demo_results.json`.
It records real synthetic CLI outcomes, a post-approval description change and
both audit edit and anchored suffix-deletion checks. The result includes a
bounded metadata diff and no real private documents.

## Video

[Three-minute rendered demo](assets/demo.mp4) displays the recorded synthetic
outputs. It is labelled as a rendered demonstration, not an interactive screen
recording. Recreate it with `python -m pip install pillow imageio-ffmpeg` followed
by `python scripts/record_demo.py --video`. The six scenes total 180 seconds.
