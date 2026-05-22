#!/usr/bin/env python3
"""
Telos Runtime — Enterprise Smoke Test Suite
============================================
Tests accuracy, throughput, and speed of the full kernel-to-userspace pipeline.

Requirements:
  - Telos daemon must be running (sudo ./telos start)
  - Run as root: sudo python3 tests/smoke_test.py

Test Categories:
  1. IPC Protocol Accuracy    — Validate all IPC commands
  2. Taint Tracking Pipeline  — End-to-end IFC enforcement
  3. Threat Intel Feed         — BULK_BLOCK_IPS batch insert
  4. NDJSON Alert Logging      — Structured SIEM output
  5. Prometheus Metrics        — Endpoint validation
  6. Throughput Benchmark      — High-volume IPC stress test
  7. Latency Benchmark         — Per-operation timing
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# ══════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════

SOCKET_PATH = os.environ.get("TELOS_SOCKET_PATH", "/var/run/telos.sock")
METRICS_URL = "http://localhost:9094/metrics"
ALERT_LOG = "/var/log/telos/alerts.json"
PROJECT_DIR = Path(__file__).resolve().parent.parent

# ANSI
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

passed = 0
failed = 0
skipped = 0
results = []


def ipc(command: str, data: dict = None) -> dict:
    """Send an IPC command to the Telos daemon and return the response."""
    payload = {"command": command}
    if data:
        payload["data"] = data
    raw = json.dumps(payload) + "\n"

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect(SOCKET_PATH)
    sock.sendall(raw.encode())

    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    sock.close()
    return json.loads(buf.decode().strip())


def test(name: str, condition: bool, detail: str = ""):
    """Record a test result."""
    global passed, failed
    if condition:
        passed += 1
        results.append((name, True, detail))
        print(f"  {GREEN}✓{RESET}  {name}  {DIM}{detail}{RESET}")
    else:
        failed += 1
        results.append((name, False, detail))
        print(f"  {RED}✕{RESET}  {name}  {detail}")


def skip(name: str, reason: str):
    global skipped
    skipped += 1
    results.append((name, None, reason))
    print(f"  {YELLOW}⊘{RESET}  {name}  {DIM}{reason}{RESET}")


def section(title: str):
    print(f"\n{CYAN}{BOLD}{'─' * 60}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{'─' * 60}{RESET}\n")


def timed(func):
    """Execute func and return (result, elapsed_ms)."""
    t0 = time.perf_counter()
    r = func()
    return r, (time.perf_counter() - t0) * 1000


# ══════════════════════════════════════════════════════════════
# 1. IPC PROTOCOL ACCURACY
# ══════════════════════════════════════════════════════════════

def test_ipc_protocol():
    section("1. IPC Protocol Accuracy")

    # PING
    r = ipc("PING")
    test("PING returns success", r.get("success") is True)
    test("PING returns 'pong'", r.get("data") == "pong", f"got: {r.get('data')}")

    # IPC_PING (heartbeat)
    r = ipc("IPC_PING")
    test("IPC_PING (heartbeat) accepted", r.get("success") is True)

    # Unknown command
    r = ipc("NONEXISTENT_CMD")
    test("Unknown command returns error", r.get("success") is False)

    # GET_STATE
    r = ipc("GET_STATE")
    test("GET_STATE returns success", r.get("success") is True)
    test("GET_STATE has process data", "processes" in (r.get("data") or {}))


# ══════════════════════════════════════════════════════════════
# 2. TAINT TRACKING PIPELINE
# ══════════════════════════════════════════════════════════════

def test_taint_pipeline():
    section("2. Taint Tracking Pipeline (IFC Accuracy)")

    # Use a fake PID — NOT os.getpid()!
    # Tainting our own PID would trigger the Network Slam on our next
    # socket_connect call, which is the system working correctly.
    test_pid = 88888

    # Register a fake agent
    r = ipc("REGISTER_AGENT", {"pid": test_pid, "comm": "smoke_test"})
    test("REGISTER_AGENT succeeds", r.get("success") is True)

    # Verify it appears in GET_STATE
    r = ipc("GET_STATE")
    procs = (r.get("data") or {}).get("processes", {})
    pid_key = str(test_pid)
    test("Agent visible in GET_STATE", pid_key in procs, f"pid={test_pid}")

    # Verify initial taint is CLEAN
    if pid_key in procs:
        test("Initial taint is CLEAN (0)",
             procs[pid_key].get("taint_level") == 0,
             f"got: {procs[pid_key].get('taint_level')}")

    # Elevate taint to CRITICAL
    r = ipc("UPDATE_TAINT", {"pid": test_pid, "taint_level": 4})
    test("UPDATE_TAINT to CRITICAL succeeds", r.get("success") is True)

    # Verify taint was elevated
    r = ipc("GET_STATE")
    procs = (r.get("data") or {}).get("processes", {})
    if pid_key in procs:
        test("Taint elevated to CRITICAL (4)",
             procs[pid_key].get("taint_level") == 4,
             f"got: {procs[pid_key].get('taint_level')}")

    # Clear taint
    r = ipc("CLEAR_TAINT", {"pid": test_pid})
    test("CLEAR_TAINT succeeds", r.get("success") is True)

    # Verify cleared
    r = ipc("GET_STATE")
    procs = (r.get("data") or {}).get("processes", {})
    test("PID removed after CLEAR_TAINT", pid_key not in procs)

    # === NETWORK SLAM PROOF ===
    # Spawn a child that reports its PID, parent taints it, child tries to connect.
    # This avoids tainting our own test runner process.
    r_fd, w_fd = os.pipe()

    child_pid = os.fork()
    if child_pid == 0:
        # Child: report PID, wait for parent to taint us, then try connect
        os.close(r_fd)
        os.write(w_fd, str(os.getpid()).encode())
        os.close(w_fd)
        time.sleep(1)  # Wait for parent to taint us

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(("1.1.1.1", 80))
            s.close()
            os._exit(0)   # Connected = slam FAILED
        except PermissionError:
            os._exit(42)  # -EPERM = slam WORKED
        except Exception:
            os._exit(42)  # Any block = slam WORKED

    # Parent: read child PID, taint it, wait for result
    os.close(w_fd)
    victim_pid = int(os.read(r_fd, 32).decode())
    os.close(r_fd)

    ipc("REGISTER_AGENT", {"pid": victim_pid, "comm": "slam_victim"})
    ipc("UPDATE_TAINT", {"pid": victim_pid, "taint_level": 4})

    _, status = os.waitpid(child_pid, 0)
    exit_code = os.WEXITSTATUS(status)

    test("Network Slam blocks tainted process", exit_code == 42,
         "socket_connect returned -EPERM ✓" if exit_code == 42
         else f"BYPASS! exit={exit_code}")

    # Cleanup
    ipc("CLEAR_TAINT", {"pid": victim_pid})


# ══════════════════════════════════════════════════════════════
# 3. INODE SENSITIVITY & NETWORK POLICY
# ══════════════════════════════════════════════════════════════

def test_inode_and_network():
    section("3. Inode Sensitivity & Network Policy")

    # Mark a test inode as CRITICAL (sensitivity=2)
    test_inode = 999999
    r = ipc("UPDATE_INODE", {"inode": test_inode, "sensitivity": 2})
    test("UPDATE_INODE (CRITICAL) succeeds", r.get("success") is True)

    # Update network policy — allow a test IP
    # 127.0.0.1 = 0x7F000001 = 2130706433
    r = ipc("UPDATE_NETWORK", {"ip": 2130706433, "allowed": 1})
    test("UPDATE_NETWORK (allow localhost) succeeds", r.get("success") is True)

    # Delete network entry
    r = ipc("DELETE_NETWORK", {"ip": 2130706433})
    test("DELETE_NETWORK succeeds", r.get("success") is True)


# ══════════════════════════════════════════════════════════════
# 4. BULK_BLOCK_IPS (Phase 4 — Threat Intel Feed)
# ══════════════════════════════════════════════════════════════

def test_bulk_block_ips():
    section("4. Threat Intel Feed (BULK_BLOCK_IPS)")

    malicious_ips = [
        "198.51.100.1", "198.51.100.2", "198.51.100.3",
        "203.0.113.10", "203.0.113.20", "203.0.113.30",
        "192.0.2.100", "192.0.2.200",
    ]

    r, ms = timed(lambda: ipc("BULK_BLOCK_IPS", {"ips": malicious_ips}))
    test("BULK_BLOCK_IPS succeeds", r.get("success") is True, f"{ms:.1f}ms")
    test("All 8 IPs blocked",
         "blocked 8 IPs" in str(r.get("data", "")),
         f"got: {r.get('data')}")

    # Verify map utilization increased — wait for next scrape cycle or check metrics
    # (metrics are sampled every 30s, so we check the IPC response directly)

    # Invalid input handling
    r = ipc("BULK_BLOCK_IPS", {"ips": ["not_an_ip", "256.256.256.256"]})
    test("Invalid IPs gracefully handled",
         r.get("success") is True,
         f"got: {r.get('data')}")

    # Missing field
    r = ipc("BULK_BLOCK_IPS", {})
    test("Missing 'ips' field returns error", r.get("success") is False)


# ══════════════════════════════════════════════════════════════
# 5. PROMETHEUS METRICS VALIDATION
# ══════════════════════════════════════════════════════════════

def test_prometheus():
    section("5. Prometheus Metrics Endpoint")

    try:
        resp = urllib.request.urlopen(METRICS_URL, timeout=5)
        body = resp.read().decode()
    except Exception as e:
        skip("Prometheus endpoint", f"unreachable: {e}")
        return

    test("Endpoint returns 200", resp.status == 200)

    expected_metrics = [
        "telos_exec_blocks_total",
        "telos_network_blocks_total",
        "telos_ifc_elevations_total",
        "telos_active_drawbridges",
        "telos_process_map_size",
        "telos_mirage_feeds_total",
        "telos_xdp_drops_total",
        "telos_bpf_map_utilization",
    ]

    for m in expected_metrics:
        test(f"Metric '{m}' exposed", m in body)

    # Check map utilization labels
    test("Map utilization has 'process_map' label",
         'map="process_map"' in body)
    test("Map utilization has 'network_map' label",
         'map="network_map"' in body)
    test("Map utilization has 'inode_map' label",
         'map="inode_map"' in body)


# ══════════════════════════════════════════════════════════════
# 6. NDJSON ALERT LOG VALIDATION
# ══════════════════════════════════════════════════════════════

def test_ndjson_alerts():
    section("6. NDJSON Alert Log (SIEM Integration)")

    log_path = Path(ALERT_LOG)
    if not log_path.exists():
        skip("NDJSON alert log", f"{ALERT_LOG} not found (no events yet)")
        return

    test("Alert log file exists", True, str(log_path))

    lines = log_path.read_text().strip().split("\n")
    lines = [l for l in lines if l.strip()]

    if not lines:
        skip("NDJSON content", "Log file is empty (no events triggered)")
        return

    test("Log has entries", len(lines) > 0, f"{len(lines)} events")

    # Parse the last line
    try:
        entry = json.loads(lines[-1])
        test("Entry is valid JSON", True)

        required_fields = ["timestamp", "hostname", "pid", "comm",
                           "action", "taint_level", "blocked", "engine"]
        for field in required_fields:
            test(f"Field '{field}' present", field in entry,
                 f"val={entry.get(field)}")

        test("Engine is 'telos_core'", entry.get("engine") == "telos_core")
        test("Timestamp is ISO 8601",
             "T" in entry.get("timestamp", ""),
             entry.get("timestamp", "")[:30])
    except json.JSONDecodeError as e:
        test("Entry is valid JSON", False, str(e))


# ══════════════════════════════════════════════════════════════
# 7. THROUGHPUT BENCHMARK — IPC Stress Test
# ══════════════════════════════════════════════════════════════

def test_throughput():
    section("7. Throughput Benchmark (IPC Stress)")

    # Rapid-fire REGISTER + TAINT + CLEAR cycles
    num_ops = 500
    t0 = time.perf_counter()

    for i in range(num_ops):
        fake_pid = 90000 + i
        ipc("REGISTER_AGENT", {"pid": fake_pid, "comm": f"bench_{i}"})
        ipc("UPDATE_TAINT", {"pid": fake_pid, "taint_level": 3})
        ipc("CLEAR_TAINT", {"pid": fake_pid})

    elapsed = time.perf_counter() - t0
    total_cmds = num_ops * 3
    ops_per_sec = total_cmds / elapsed

    test(f"Completed {total_cmds} IPC ops in {elapsed:.2f}s", True,
         f"{ops_per_sec:.0f} ops/sec")
    test("Throughput > 500 ops/sec", ops_per_sec > 500,
         f"{ops_per_sec:.0f} ops/sec")

    # BULK_BLOCK_IPS throughput
    big_list = [f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"
                for i in range(200)]
    r, ms = timed(lambda: ipc("BULK_BLOCK_IPS", {"ips": big_list}))
    test(f"Bulk-blocked 200 IPs in {ms:.1f}ms", r.get("success") is True)
    test("Bulk insert < 500ms", ms < 500, f"{ms:.1f}ms")


# ══════════════════════════════════════════════════════════════
# 8. LATENCY BENCHMARK — Per-Operation Timing
# ══════════════════════════════════════════════════════════════

def test_latency():
    section("8. Latency Benchmark (Per-Operation)")

    ops = {
        "PING": lambda: ipc("PING"),
        "IPC_PING": lambda: ipc("IPC_PING"),
        "GET_STATE": lambda: ipc("GET_STATE"),
        "REGISTER_AGENT": lambda: ipc("REGISTER_AGENT",
                                       {"pid": 99999, "comm": "lat_test"}),
        "UPDATE_TAINT": lambda: ipc("UPDATE_TAINT",
                                     {"pid": 99999, "taint_level": 2}),
        "CLEAR_TAINT": lambda: ipc("CLEAR_TAINT", {"pid": 99999}),
    }

    for name, fn in ops.items():
        # Warmup
        fn()
        # Measure
        samples = []
        for _ in range(20):
            _, ms = timed(fn)
            samples.append(ms)
        avg = sum(samples) / len(samples)
        p99 = sorted(samples)[int(len(samples) * 0.99)]
        test(f"{name:20s} avg={avg:.2f}ms  p99={p99:.2f}ms",
             avg < 50, f"{'FAST' if avg < 5 else 'OK' if avg < 20 else 'SLOW'}")


# ══════════════════════════════════════════════════════════════
# 9. REAL-WORLD: Fork Storm Resilience
# ══════════════════════════════════════════════════════════════

def test_fork_resilience():
    section("9. Real-World: Fork Storm Resilience")

    # Spawn 50 rapid subprocesses and verify the daemon stays responsive
    t0 = time.perf_counter()
    procs = []
    for _ in range(50):
        p = subprocess.Popen(
            ["true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        procs.append(p)

    for p in procs:
        p.wait()
    fork_ms = (time.perf_counter() - t0) * 1000

    test(f"Spawned 50 processes in {fork_ms:.0f}ms", True)

    # Verify daemon is still responsive after the fork storm
    r, ms = timed(lambda: ipc("PING"))
    test("Daemon responsive after fork storm",
         r.get("success") is True, f"latency={ms:.1f}ms")
    test("Post-storm latency < 50ms", ms < 50, f"{ms:.1f}ms")


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    print(f"\n{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}  TELOS RUNTIME — ENTERPRISE SMOKE TEST{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")

    if os.geteuid() != 0:
        print(f"\n  {RED}✕{RESET}  Must run as root: sudo python3 tests/smoke_test.py\n")
        sys.exit(1)

    if not os.path.exists(SOCKET_PATH):
        print(f"\n  {RED}✕{RESET}  Daemon not running ({SOCKET_PATH} not found)")
        print(f"     Start with: sudo ./telos start\n")
        sys.exit(1)

    t_start = time.perf_counter()

    test_ipc_protocol()
    test_taint_pipeline()
    test_inode_and_network()
    test_bulk_block_ips()
    test_prometheus()
    test_ndjson_alerts()
    test_throughput()
    test_latency()
    test_fork_resilience()

    elapsed = time.perf_counter() - t_start

    # ── Kernel Event Audit ──────────────────────────────────────
    section("10. Kernel Event Audit (Live Blocks)")

    log_path = Path(ALERT_LOG)
    if log_path.exists():
        lines = log_path.read_text().strip().split("\n")
        # Only show events generated during THIS test run
        recent = []
        for l in lines:
            if not l.strip():
                continue
            try:
                e = json.loads(l)
                ts = e.get("timestamp", "")
                if ts >= time.strftime("%Y-%m-%dT%H:", time.gmtime(t_start)):
                    recent.append(e)
            except Exception:
                continue

        blocked_events = [e for e in recent if e.get("blocked")]
        allowed_events = [e for e in recent if not e.get("blocked")]

        print(f"  {BOLD}Events during test run:{RESET} {len(recent)} total  "
              f"({RED}{len(blocked_events)} BLOCKED{RESET}  "
              f"{GREEN}{len(allowed_events)} ALLOWED{RESET})\n")

        if blocked_events:
            print(f"  {RED}{BOLD}  ┌─ BLOCKED EVENTS ──────────────────────────────────┐{RESET}")
            for e in blocked_events[-15:]:  # Last 15
                ts_short = e["timestamp"][11:19]
                pid = e.get("pid", "?")
                comm = e.get("comm", "?")[:12]
                action = e.get("action", "?")
                taint = e.get("taint_level", 0)
                taint_bar = "█" * min(taint, 4) + "░" * (4 - min(taint, 4))
                print(f"  {RED}  │{RESET} {DIM}{ts_short}{RESET}  "
                      f"PID:{pid:<7} {comm:<12}  "
                      f"{RED}{BOLD}{action:<20}{RESET}  "
                      f"taint=[{RED}{taint_bar}{RESET}] {taint}")
            print(f"  {RED}{BOLD}  └────────────────────────────────────────────────────┘{RESET}")
        else:
            print(f"  {DIM}  No blocked events during test run{RESET}")

        if allowed_events:
            print(f"\n  {GREEN}{BOLD}  ┌─ TAINT EVENTS (Propagation) ──────────────────────┐{RESET}")
            for e in allowed_events[-10:]:
                ts_short = e["timestamp"][11:19]
                pid = e.get("pid", "?")
                comm = e.get("comm", "?")[:12]
                action = e.get("action", "?")
                taint = e.get("taint_level", 0)
                taint_bar = "█" * min(taint, 4) + "░" * (4 - min(taint, 4))
                print(f"  {GREEN}  │{RESET} {DIM}{ts_short}{RESET}  "
                      f"PID:{pid:<7} {comm:<12}  "
                      f"{YELLOW}{action:<20}{RESET}  "
                      f"taint=[{YELLOW}{taint_bar}{RESET}] {taint}")
            print(f"  {GREEN}{BOLD}  └────────────────────────────────────────────────────┘{RESET}")
    else:
        print(f"  {DIM}  No alert log found{RESET}")

    # Summary
    total = passed + failed + skipped
    print(f"\n{BOLD}{'═' * 60}{RESET}")
    print(f"  {GREEN}{BOLD}{passed} passed{RESET}  "
          f"{RED}{BOLD}{failed} failed{RESET}  "
          f"{YELLOW}{BOLD}{skipped} skipped{RESET}  "
          f"{DIM}({total} total in {elapsed:.2f}s){RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}\n")

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
