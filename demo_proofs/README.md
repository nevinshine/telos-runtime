# Sentinel Stack: Academic Proofs

This directory contains conceptual Proof of Concept (PoC) demonstrations that formally and logically validate the architecture of the Sentinel Stack.

The Sentinel Stack combines **Static Formal Verification** (`sentinel-kv`) with a **Dynamic Intent-Aware Runtime** (`telos-runtime`). These proofs demonstrate exactly why *both* layers are strictly required to achieve a Zero-Trust environment.

## Proof 1: The Limits of Static Analysis (`halting_poc.c`)

### The Concept
Rice's Theorem (derived from Turing's Halting Problem) proves that no program can generally determine all non-trivial properties of another program without executing it.

### The Demonstration
`halting_poc.c` contains a deliberate buffer overflow vulnerability. However, the vulnerable branch is guarded by a pseudo-cryptographic hash function. 

To definitively prove whether the memory vulnerability is reachable, a static analyzer (like the SMT-backed LLVM verifier in `sentinel-kv`) must formally invert the hash function. For complex functions, SMT solvers (like Z3) will either hang infinitely or return `UNKNOWN`.

**Conclusion:** Static analysis cannot guarantee safety for all Turing-complete programs. A dynamic enforcement layer (the Telos eBPF runtime) is required to intercept the overflow if the attacker manages to trigger the formally "unreachable" state at runtime.

## Proof 2: Context Dependency (`intent_poc.py`)

### The Concept
A system call (e.g., `open('/etc/shadow')` or `connect()`) is inherently neutral. "Maliciousness" cannot be determined by observing actions alone; it requires understanding the *intent* of the entity executing the action.

### The Demonstration
`intent_poc.py` simulates reading sensitive system files and transmitting them over a network socket. 

- If the context is a scheduled **system backup**, the action is benign and required.
- If the context is an **autonomous web agent** handling HTTP requests, the exact same action is malicious data exfiltration.

**Conclusion:** Traditional firewalls and sandboxes fail because they lack context. The Telos Cortex Workload Control Plane maps dynamic actions to execution intent, allowing identical bytes of code to be dynamically permitted or denied based on architectural context.
