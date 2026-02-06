#!/usr/bin/env python3
"""
TELOS Safety Test - Verify normal system processes are NEVER blocked

This test runs common system commands that should ALWAYS succeed,
even when TELOS Core is active. If any of these fail, there's a bug.
"""

import os
import subprocess
import sys

# Commands that should ALWAYS work (never registered with TELOS)
SAFE_COMMANDS = [
    ["/bin/true"],
    ["/bin/echo", "hello"],
    ["/bin/ls", "/tmp"],
    ["/usr/bin/id"],
    ["/usr/bin/whoami"],
    ["/bin/cat", "/etc/hostname"],
    ["/usr/bin/date"],
    ["/bin/pwd"],
]

def main():
    print("╔═══════════════════════════════════════════════════════╗")
    print("║         TELOS System Safety Verification              ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print()
    print(f"PID: {os.getpid()} (NOT registered with TELOS)")
    print()
    
    passed = 0
    failed = 0
    blocked = 0
    
    for cmd in SAFE_COMMANDS:
        cmd_str = " ".join(cmd)
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"  ✅ {cmd_str}")
                passed += 1
            else:
                print(f"  ⚠️  {cmd_str} (exit code {result.returncode})")
                failed += 1
        except PermissionError:
            print(f"  ❌ {cmd_str} - BLOCKED!")
            blocked += 1
        except FileNotFoundError:
            print(f"  ⏭️  {cmd_str} - not found (skipped)")
        except Exception as e:
            print(f"  ❌ {cmd_str} - {e}")
            failed += 1
    
    print()
    print("=" * 50)
    print(f"  Passed:  {passed}")
    print(f"  Failed:  {failed}")
    print(f"  Blocked: {blocked}")
    print("=" * 50)
    
    if blocked > 0:
        print()
        print("❌ CRITICAL: Normal processes were blocked!")
        print("   This is a bug - TELOS should only block tainted processes.")
        return 1
    elif failed > 0:
        print()
        print("⚠️  Some commands failed (not blocked, just errors)")
        return 0
    else:
        print()
        print("✅ All system commands work normally!")
        print("   TELOS does NOT interfere with regular processes.")
        return 0

if __name__ == '__main__':
    sys.exit(main())
