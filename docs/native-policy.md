# Native positive-rule experiment

The Rust prototype implements only these positive recursive rules over integer
nodes, using indexed edges and semi-naive delta propagation:

```text
reach(X,Y) :- edge(X,Y).
reach(X,Z) :- reach(X,Y), edge(Y,Z).
```

It is a specialized experiment, not a replacement for the Python policy engine.
It has no Datalog parser, stratified negation, approvals, explanation tree,
label conversion or gateway integration. Security decisions continue through
the reviewed Python engine. A favorable microbenchmark does not establish a
full policy-engine speedup or justify replacing it.

Measured on 2026-10-02 with Rust 1.92.0 optimized compilation and the project's
Python 3.13 environment, a 100-node directed chain produced 4,950 reach facts.
The Python engine's complete reach relation matched a separate Python oracle.
Rust unit tests additionally exercise cycles, duplicates and disconnected edges.

| Implementation | Median evaluation time, five repetitions |
| --- | ---: |
| Python specialized oracle | 12.7422 ms |
| General Python policy engine | 1079.7252 ms |
| Specialized Rust rule | 4.5524 ms |

Times exclude native process startup and Python engine construction. These
different implementations provide different capabilities. Shared-machine load
and allocation differences affect results; rerun before making performance
claims. Exact results are retained in `benchmarks/native_results.json`.

## Reproduction on this Windows environment

The existing MSVC Rust compiler could not find `link.exe`. MinGW GCC was already
installed, so the matching GNU standard-library component was downloaded from
the official Rust distribution server, checked against its SHA-256 checksum,
and extracted under ignored project artifacts. No system installation changed.
The [official installation guidance](https://rust-lang.org/tools/install/)
documents the usual Windows compiler prerequisites.

```powershell
python scripts/prepare_native.py
& "$env:USERPROFILE/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/rustc.exe" native/reachability.rs --sysroot artifacts/native-toolchain/sysroot --target x86_64-pc-windows-gnu -C linker=gcc -O -o artifacts/native/reachability.exe
& "$env:USERPROFILE/.rustup/toolchains/stable-x86_64-pc-windows-msvc/bin/rustc.exe" native/reachability.rs --test --sysroot artifacts/native-toolchain/sysroot --target x86_64-pc-windows-gnu -C linker=gcc -o artifacts/native/reachability-tests.exe
& artifacts/native/reachability-tests.exe
python scripts/benchmark_native.py --binary artifacts/native/reachability.exe --size 100 --repeat 5
```

The component preparation script pins 1.92.0 to match the measured compiler.
Use the matching compiler/component pair; a different installed Rust version
requires updating the pin or installing the appropriate standard component.
Normal Python CI does not download this component or require Rust.
