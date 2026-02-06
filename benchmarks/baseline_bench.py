#!/usr/bin/env python3
"""
Baseline benchmark - run this when TELOS Core is STOPPED to get true baseline.
Then compare with lsm_bench.py results when Core is running.
"""

import subprocess
import time
import statistics

ITERATIONS = 1000
COMMAND = ["/bin/true"]

def main():
    print("╔═══════════════════════════════════════════════════════╗")
    print("║       BASELINE Benchmark (run with Core STOPPED)      ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print()
    
    # Warmup
    for _ in range(100):
        subprocess.run(COMMAND, capture_output=True)
    
    # Measure
    times = []
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        subprocess.run(COMMAND, capture_output=True)
        end = time.perf_counter_ns()
        times.append((end - start) / 1000)  # µs
    
    mean = statistics.mean(times)
    median = statistics.median(times)
    p99 = sorted(times)[int(len(times) * 0.99)]
    
    print(f"Iterations: {ITERATIONS}")
    print(f"Mean:   {mean:,.1f} µs")
    print(f"Median: {median:,.1f} µs")
    print(f"P99:    {p99:,.1f} µs")
    print()
    print("Compare this with lsm_bench.py results when Core is running.")

if __name__ == '__main__':
    main()
