#!/usr/bin/env python3
"""
TELOS Tainted vs Clean Stress Test

Compares performance of:
1. Clean processes (not in taint map)
2. Tainted processes (in taint map, but below threshold)
3. Blocked processes (in taint map, above threshold)
"""

import os
import sys
import time
import subprocess
import multiprocessing

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ITERATIONS = 200

def run_as_tainted_agent():
    """Register, get tainted, then try to spawn commands."""
    import grpc
    from shared import protocol_pb2, protocol_pb2_grpc
    
    my_pid = os.getpid()
    
    channel = grpc.insecure_channel('localhost:50051')
    stub = protocol_pb2_grpc.TelosControlStub(channel)
    
    # Register as agent
    intent = protocol_pb2.IntentRequest(
        agent_pid=my_pid,
        natural_language_goal="Stress test agent",
        planned_actions=["exec:test"]
    )
    stub.DeclareIntent(intent, timeout=5)
    print(f"    Registered PID {my_pid}")
    
    # Inject HIGH taint
    taint = protocol_pb2.TaintReport(
        source_id=f"stress_{my_pid}",
        url="http://stress.test",
        level=protocol_pb2.TaintLevel.HIGH,
        payload_preview="stress test"
    )
    ack = stub.ReportTaint(taint, timeout=5)
    print(f"    Taint response: {ack.message}")
    
    time.sleep(1.0)  # Wait for taint to propagate to kernel
    
    # Try to spawn - should be BLOCKED
    blocked = 0
    allowed = 0
    
    for _ in range(ITERATIONS):
        try:
            result = subprocess.run(["/bin/true"], capture_output=True, timeout=1)
            if result.returncode == 0:
                allowed += 1
        except PermissionError:
            blocked += 1
        except:
            pass
    
    return {"pid": my_pid, "blocked": blocked, "allowed": allowed}

def run_clean():
    """Run without registration - should all succeed."""
    successes = 0
    for _ in range(ITERATIONS):
        try:
            result = subprocess.run(["/bin/true"], capture_output=True, timeout=1)
            if result.returncode == 0:
                successes += 1
        except:
            pass
    return successes

def main():
    print("╔═══════════════════════════════════════════════════════╗")
    print("║       TELOS Tainted vs Clean Stress Test              ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print()
    
    # Test 1: Clean path (no registration)
    print("[1] Clean path (not registered with Cortex)")
    print("-" * 50)
    start = time.time()
    clean_count = run_clean()
    clean_time = time.time() - start
    print(f"    Spawns:     {clean_count}")
    print(f"    Time:       {clean_time:.2f}s")
    print(f"    Rate:       {clean_count/clean_time:.0f}/sec")
    print()
    
    # Test 2: Tainted path (registered + tainted)
    print("[2] Tainted path (registered + HIGH taint)")
    print("-" * 50)
    
    try:
        start = time.time()
        result = run_as_tainted_agent()
        tainted_time = time.time() - start
        
        print(f"    Agent PID:  {result['pid']}")
        print(f"    Blocked:    {result['blocked']}")
        print(f"    Allowed:    {result['allowed']}")
        print(f"    Time:       {tainted_time:.2f}s")
        print(f"    Block rate: {result['blocked']/(result['blocked']+result['allowed'])*100:.1f}%")
    except Exception as e:
        print(f"    Error: {e}")
        print("    (Is Cortex running?)")
    
    print()
    print("=" * 50)
    print("SUMMARY")
    print("=" * 50)
    print(f"  Clean path latency:   ~{clean_time/clean_count*1000:.1f}ms per spawn")
    if 'result' in dir() and result['blocked'] > 0:
        print(f"  Tainted path:         {result['blocked']} BLOCKED by kernel!")
        print()
        print("✅ LSM correctly blocks tainted processes")
    else:
        print("  Tainted path:         (run with Cortex to test)")
    
    # Test 3: Verify clean processes still work after tainting
    print()
    print("[3] Clean processes after taint test")
    print("-" * 50)
    
    # Test 2 already tainted this process (PID 76272 was blocked)
    # Now run a completely new clean process - should succeed
    clean_after = 0
    for _ in range(50):
        try:
            # This runs in a NEW process that isn't tainted
            result = subprocess.run(["/bin/true"], capture_output=True, timeout=1)
            if result.returncode == 0:
                clean_after += 1
        except PermissionError:
            pass  # We are tainted from test 2!
        except:
            pass
    
    print(f"    Spawns from THIS (now tainted) process: {clean_after}/50")
    
    if clean_after == 0:
        print("    ✓ This process is blocked (as expected - we're tainted)")
        print()
        print("✅ LSM correctly maintains taint state!")
    else:
        print("    Note: This process should be blocked from Test 2 taint")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
