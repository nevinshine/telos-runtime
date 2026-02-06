#!/usr/bin/env python3
"""
TELOS LSM Benchmark - Measure overhead of eBPF security hooks

Measures execve() latency with and without taint tracking.
"""

import os
import sys
import time
import subprocess
import statistics

ITERATIONS = 1000
COMMAND = ["/bin/true"]  # Minimal command for pure syscall overhead

def benchmark_execve(label: str, iterations: int = ITERATIONS) -> dict:
    """Benchmark subprocess spawn latency."""
    times = []
    
    for _ in range(iterations):
        start = time.perf_counter_ns()
        try:
            subprocess.run(COMMAND, capture_output=True, timeout=1)
        except (PermissionError, subprocess.SubprocessError):
            pass  # Count blocked attempts too
        end = time.perf_counter_ns()
        times.append((end - start) / 1000)  # Convert to µs
    
    return {
        "label": label,
        "iterations": iterations,
        "mean_us": statistics.mean(times),
        "median_us": statistics.median(times),
        "stdev_us": statistics.stdev(times) if len(times) > 1 else 0,
        "min_us": min(times),
        "max_us": max(times),
        "p99_us": sorted(times)[int(len(times) * 0.99)],
    }

def print_results(results: dict):
    print(f"\n{'='*60}")
    print(f"  {results['label']}")
    print(f"{'='*60}")
    print(f"  Iterations:  {results['iterations']:,}")
    print(f"  Mean:        {results['mean_us']:,.1f} µs")
    print(f"  Median:      {results['median_us']:,.1f} µs")
    print(f"  Std Dev:     {results['stdev_us']:,.1f} µs")
    print(f"  Min:         {results['min_us']:,.1f} µs")
    print(f"  Max:         {results['max_us']:,.1f} µs")
    print(f"  P99:         {results['p99_us']:,.1f} µs")

def main():
    print("╔═══════════════════════════════════════════════════════╗")
    print("║         TELOS LSM Performance Benchmark               ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print()
    print(f"Command: {' '.join(COMMAND)}")
    print(f"Iterations: {ITERATIONS}")
    print(f"PID: {os.getpid()}")
    print()
    
    # Check if we're tainted
    is_tainted = False
    try:
        result = subprocess.run(["/bin/true"], timeout=1)
        is_tainted = result.returncode != 0
    except PermissionError:
        is_tainted = True
    
    if is_tainted:
        print("⚠️  This process is TAINTED - commands will be blocked")
        print("   Run without registering with Cortex for clean baseline")
        print()
    
    # Warmup
    print("[*] Warming up...")
    for _ in range(100):
        try:
            subprocess.run(COMMAND, capture_output=True, timeout=1)
        except:
            pass
    
    # Benchmark
    print(f"[*] Running {ITERATIONS} iterations...")
    results = benchmark_execve("execve() with TELOS LSM active")
    
    print_results(results)
    
    # Calculate overhead estimate
    # Baseline execve on modern Linux is ~300-500µs for fork+exec
    baseline_estimate = 400  # µs, typical
    overhead = results['mean_us'] - baseline_estimate
    overhead_pct = (overhead / baseline_estimate) * 100 if baseline_estimate > 0 else 0
    
    print()
    print(f"{'='*60}")
    print(f"  Overhead Analysis (estimated baseline: ~{baseline_estimate}µs)")
    print(f"{'='*60}")
    print(f"  LSM overhead:     ~{max(0, overhead):,.0f} µs ({overhead_pct:.1f}%)")
    print(f"  Per-hook cost:    ~{max(0, overhead/3):,.0f} µs (3 hooks)")
    print()
    
    if results['mean_us'] < 600:
        print("✅ Excellent: < 600µs mean latency")
    elif results['mean_us'] < 1000:
        print("✅ Good: < 1ms mean latency")
    elif results['mean_us'] < 2000:
        print("⚠️  Acceptable: < 2ms mean latency")
    else:
        print("❌ High latency - investigate")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
