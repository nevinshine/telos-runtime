#!/usr/bin/env python3
"""
Sentinel Stack: Context Dependency PoC (Intent vs. Action)

This script proves that "maliciousness" cannot be determined by observing 
system calls alone. It requires understanding the execution context (intent).

The exact same bytes of code and system calls are executed in both scenarios:
  1. Opening files (reading data)
  2. Opening a network socket (sending data)

Without an Intent-Aware security runtime (like Telos Cortex), a traditional 
sandbox cannot distinguish between an authorized backup and data exfiltration.
"""

import os
import sys
import time
import socket

# Read the simulated intent context provided by the Telos AI Control Plane
# In a real environment, this is established via eBPF tracking and the LLM.
INTENT = os.environ.get("CORTEX_INTENT", "unknown")

def execute_action():
    print(f"[PROCESS] Executing with context intent: {INTENT}")
    print("[PROCESS] Syscall: open('/etc/shadow', O_RDONLY)")
    
    # Simulate reading sensitive data
    sensitive_data = "root:$6$xyz...:18000:0:99999:7:::"
    
    print("[PROCESS] Syscall: socket(AF_INET, SOCK_STREAM, 0)")
    print("[PROCESS] Syscall: connect(198.51.100.14:443)")
    print("[PROCESS] Syscall: send(sensitive_data)")
    
    # Simulate the Telos Cortex eBPF Enforcement Engine Intercepting the Action
    print("\n--- TELOS CORTEX INTERCEPT ---")
    if INTENT == "backup":
        print("[✔] VERDICT: ALLOW")
        print("    Reason: Action (read sensitive, network outbound) matches authorized")
        print("            intent (nightly system backup).")
    elif INTENT == "web_request":
        print("[✖] VERDICT: DENY (KILL_PROCESS)")
        print("    Reason: Action (read sensitive, network outbound) deviates drastically")
        print("            from context (handling HTTP web request). Flagged as Exfiltration.")
    else:
        print("[!] VERDICT: ESCALATE")
        print(f"    Reason: Unknown intent '{INTENT}'. Escalating to LLM for decision.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        print("=== Scenario A: The Sysadmin ===")
        os.environ["CORTEX_INTENT"] = "backup"
        INTENT = "backup"
        execute_action()
        
        print("\n=== Scenario B: The Web Vulnerability ===")
        os.environ["CORTEX_INTENT"] = "web_request"
        INTENT = "web_request"
        execute_action()
    else:
        execute_action()
