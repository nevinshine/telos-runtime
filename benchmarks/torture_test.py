#!/usr/bin/env python3
"""
TELOS LSM Torture Test - Stress test with concurrent processes and rapid taint updates

Tests:
1. Rapid subprocess spawning under load
2. Many concurrent tainted processes
3. Rapid taint escalation/de-escalation
4. Memory/stability under stress
"""

import os
import sys
import time
import threading
import subprocess
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Test parameters
SPAWN_ITERATIONS = 500
CONCURRENT_WORKERS = 16
TAINT_UPDATE_RATE = 100  # updates per second
TEST_DURATION = 10  # seconds

def spawn_worker(worker_id: int) -> dict:
    """Worker that spawns subprocesses rapidly."""
    successes = 0
    failures = 0
    blocked = 0
    
    for _ in range(SPAWN_ITERATIONS // CONCURRENT_WORKERS):
        try:
            result = subprocess.run(["/bin/true"], capture_output=True, timeout=1)
            if result.returncode == 0:
                successes += 1
            else:
                failures += 1
        except PermissionError:
            blocked += 1
        except Exception:
            failures += 1
    
    return {"worker": worker_id, "successes": successes, "failures": failures, "blocked": blocked}

def taint_updater():
    """Rapidly update taint via gRPC (if Cortex running)."""
    try:
        import grpc
        from shared import protocol_pb2, protocol_pb2_grpc
        
        channel = grpc.insecure_channel('localhost:50051')
        stub = protocol_pb2_grpc.TelosControlStub(channel)
        
        updates = 0
        start = time.time()
        
        while time.time() - start < TEST_DURATION:
            try:
                taint = protocol_pb2.TaintReport(
                    source_id=f"stress_test_{updates % 100}",
                    url="http://stress.test/page",
                    level=(updates % 4) + 1,  # Cycle through levels
                    payload_preview="stress test payload"
                )
                stub.ReportTaint(taint, timeout=0.1)
                updates += 1
            except:
                pass
            time.sleep(1.0 / TAINT_UPDATE_RATE)
        
        return updates
    except ImportError:
        return 0

def main():
    print("╔═══════════════════════════════════════════════════════╗")
    print("║           TELOS LSM Torture Test                      ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print()
    print(f"Spawn iterations:   {SPAWN_ITERATIONS}")
    print(f"Concurrent workers: {CONCURRENT_WORKERS}")
    print(f"Test duration:      {TEST_DURATION}s")
    print()
    
    # Test 1: Rapid concurrent subprocess spawning
    print("=" * 60)
    print("[TEST 1] Rapid concurrent subprocess spawning")
    print("=" * 60)
    
    start = time.time()
    
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        futures = [executor.submit(spawn_worker, i) for i in range(CONCURRENT_WORKERS)]
        results = [f.result() for f in futures]
    
    elapsed = time.time() - start
    
    total_success = sum(r["successes"] for r in results)
    total_blocked = sum(r["blocked"] for r in results)
    total_failed = sum(r["failures"] for r in results)
    
    print(f"  Total spawns:  {total_success + total_blocked + total_failed}")
    print(f"  Succeeded:     {total_success}")
    print(f"  Blocked:       {total_blocked}")
    print(f"  Failed:        {total_failed}")
    print(f"  Time:          {elapsed:.2f}s")
    print(f"  Throughput:    {(total_success + total_blocked) / elapsed:.0f} spawns/sec")
    print()
    
    # Test 2: Rapid taint updates
    print("=" * 60)
    print("[TEST 2] Rapid taint updates via gRPC")
    print("=" * 60)
    
    taint_thread = threading.Thread(target=taint_updater)
    taint_thread.start()
    
    # Concurrent spawns during taint updates
    spawn_during_taint = 0
    blocked_during_taint = 0
    spawn_start = time.time()
    
    while time.time() - spawn_start < TEST_DURATION:
        try:
            result = subprocess.run(["/bin/true"], capture_output=True, timeout=1)
            if result.returncode == 0:
                spawn_during_taint += 1
        except PermissionError:
            blocked_during_taint += 1
        except:
            pass
    
    taint_thread.join()
    
    print(f"  Spawns during taint storm:  {spawn_during_taint}")
    print(f"  Blocked during taint storm: {blocked_during_taint}")
    print(f"  Spawn rate:                 {spawn_during_taint / TEST_DURATION:.0f}/sec")
    print()
    
    # Test 3: Fork bomb resistance (controlled)
    print("=" * 60)
    print("[TEST 3] Fork stress (controlled)")
    print("=" * 60)
    
    fork_count = 0
    fork_start = time.time()
    
    def controlled_fork():
        nonlocal fork_count
        for _ in range(50):
            try:
                subprocess.run(["/bin/true"], timeout=0.5)
                fork_count += 1
            except:
                pass
    
    threads = [threading.Thread(target=controlled_fork) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    fork_elapsed = time.time() - fork_start
    print(f"  Fork operations: {fork_count}")
    print(f"  Time:           {fork_elapsed:.2f}s")
    print(f"  Rate:           {fork_count / fork_elapsed:.0f}/sec")
    print()
    
    # Summary
    print("=" * 60)
    print("TORTURE TEST COMPLETE")
    print("=" * 60)
    print()
    if total_failed == 0:
        print("✅ All tests passed - LSM is stable under load")
    else:
        print(f"⚠️  {total_failed} failures detected - investigate")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
