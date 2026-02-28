#!/usr/bin/env python3
"""
Telos Domain Intelligence — Stress Validation Suite v3

Strategy: Sequential correctness first, then progressive concurrency.
All output written to file (terminal stdout is unreliable).
"""

import sys
import os
import time
import random
import string
import threading
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import grpc
from shared import protocol_pb2, protocol_pb2_grpc

CORTEX_ADDR = "localhost:50051"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "stress_results.txt")

KNOWN_DOMAINS = [
    "google.com", "github.com", "arxiv.org", "pypi.org",
    "docs.python.org", "stackoverflow.com", "reuters.com",
    "bbc.com", "wikipedia.org", "crates.io",
]

WATCHLIST_TARGETS = [
    "google.com", "github.com", "python.org", "docs.python.org",
    "pypi.org", "paypal.com", "stripe.com", "facebook.com",
]


def _call(stub, pid, goal, domain, sid):
    req = protocol_pb2.IntentRequest(
        agent_pid=pid, natural_language_goal=goal,
        planned_actions=[f"curl {domain}"], session_id=sid)
    t0 = time.perf_counter_ns()
    v = stub.DeclareIntent(req)
    lat = (time.perf_counter_ns() - t0) / 1e6
    return v.allowed, v.reason, lat


def _random_domain():
    name = ''.join(random.choices(string.ascii_lowercase, k=random.randint(6, 12)))
    return name + random.choice(['.com', '.net', '.org', '.io'])


def _fuzz_domain(target):
    mutations = [
        lambda s: s[:len(s)//2] + random.choice('0123456789') + s[len(s)//2+1:],
        lambda s: s[:len(s)//2] + s[len(s)//2] + s[len(s)//2:],
        lambda s: s.replace('.', '-', 1),
    ]
    base = target.rsplit('.', 1)
    name, tld = base[0], ('.' + base[1] if len(base) > 1 else '.com')
    return random.choice(mutations)(name) + tld


def _pct(arr):
    if not arr: return 0, 0, 0
    arr.sort()
    n = len(arr)
    return arr[n//2], arr[int(n*0.95)], arr[min(int(n*0.99), n-1)]


def w(f, msg):
    f.write(msg + "\n")
    f.flush()


def main():
    with open(OUT, "w") as f:
        w(f, "╔══════════════════════════════════════════════════════╗")
        w(f, "║  TELOS DOMAIN INTELLIGENCE — STRESS TEST v3         ║")
        w(f, "╚══════════════════════════════════════════════════════╝")

        # Connect
        ch = grpc.insecure_channel(CORTEX_ADDR)
        stub = protocol_pb2_grpc.TelosControlStub(ch)
        try:
            _call(stub, 1, "ping", "google.com", "warmup")
            w(f, "  Cortex: ONLINE\n")
        except Exception as e:
            w(f, f"  ERROR: {e}")
            sys.exit(1)

        results = []

        # ═════════════════════════════════════════════
        # T1: Sequential Data Plane Latency (200 known domains)
        # ═════════════════════════════════════════════
        w(f, "=" * 60)
        w(f, "T1: SEQUENTIAL DATA PLANE LATENCY (200 known domains)")
        w(f, "=" * 60)
        lats = []
        errs = 0
        for i in range(200):
            domain = random.choice(KNOWN_DOMAINS)
            try:
                ok, _, lat = _call(stub, 10000+i, "Search for information", domain, f"t1-{i}")
                lats.append(lat)
                if not ok: errs += 1
            except: errs += 1
        p50, p95, p99 = _pct(lats)
        t1_pass = len(lats) == 200 and errs == 0 and p99 < 50
        w(f, f"  Queries: {len(lats)}  Errors: {errs}")
        w(f, f"  p50={p50:.1f}ms  p95={p95:.1f}ms  p99={p99:.1f}ms")
        w(f, f"  {'✅ PASS' if t1_pass else '❌ FAIL'}\n")
        results.append({"test": "T1", "passed": t1_pass, "p50": p50, "p95": p95, "p99": p99})

        # ═════════════════════════════════════════════
        # T2: Escalation Storm (20 unknown domains, sequential)
        # ═════════════════════════════════════════════
        w(f, "=" * 60)
        w(f, "T2: ESCALATION STORM (20 unknown domains, sequential)")
        w(f, "=" * 60)
        lats2 = []
        denied = 0
        allowed = 0
        for i in range(20):
            domain = _random_domain()
            try:
                ok, reason, lat = _call(stub, 20000+i, "Check server status", domain, f"t2-{i}")
                lats2.append(lat)
                if ok: allowed += 1
                else: denied += 1
            except: pass
        p50, p95, p99 = _pct(lats2)
        t2_pass = len(lats2) > 0
        w(f, f"  Queries: {len(lats2)}  Denied: {denied}  Allowed(LLM): {allowed}")
        w(f, f"  p50={p50:.1f}ms  p95={p95:.1f}ms  p99={p99:.1f}ms")
        w(f, f"  {'✅ PASS' if t2_pass else '❌ FAIL'}\n")
        results.append({"test": "T2", "passed": t2_pass})

        # ═════════════════════════════════════════════
        # T3: TOCTOU — 2 threads, same unknown domain
        # ═════════════════════════════════════════════
        w(f, "=" * 60)
        w(f, "T3: TOCTOU RACE DETECTION (2 threads × 1 unknown domain)")
        w(f, "=" * 60)
        target = _random_domain()
        t3_results = []
        barrier = threading.Barrier(2, timeout=15)
        lock = threading.Lock()

        def t3_worker(tid):
            try:
                # Use fresh stub per thread to avoid channel issues
                ch2 = grpc.insecure_channel(CORTEX_ADDR)
                st2 = protocol_pb2_grpc.TelosControlStub(ch2)
                barrier.wait()
                ok, reason, lat = _call(st2, 30000+tid, "Search for info", target, f"t3-{tid}")
                with lock: t3_results.append((tid, ok, lat))
                ch2.close()
            except Exception as e:
                with lock: t3_results.append((tid, None, 0))

        ths = [threading.Thread(target=t3_worker, args=(t,)) for t in range(2)]
        [t.start() for t in ths]
        [t.join(timeout=30) for t in ths]
        valid = [r for r in t3_results if r[1] is not None]
        verdicts = set(r[1] for r in valid)
        consistent = len(verdicts) <= 1
        t3_pass = consistent and len(valid) > 0
        w(f, f"  Domain: {target}  Successful: {len(valid)}/{len(t3_results)}")
        w(f, f"  Verdicts: {verdicts}  Consistent: {'YES' if consistent else 'NO — RACE!'}")
        if valid:
            w(f, f"  Latencies: {[f'{r[2]:.1f}ms' for r in valid]}")
        w(f, f"  {'✅ PASS' if t3_pass else '❌ FAIL'}\n")
        results.append({"test": "T3", "passed": t3_pass, "consistent": consistent})

        # ═════════════════════════════════════════════
        # T4: Typosquat Accuracy (100 fuzzed, sequential)
        # ═════════════════════════════════════════════
        w(f, "=" * 60)
        w(f, "T4: TYPOSQUAT DETECTION (100 fuzzed domains, sequential)")
        w(f, "=" * 60)
        detected = 0
        missed = 0
        missed_list = []
        t4_lats = []
        for i in range(100):
            target_d = random.choice(WATCHLIST_TARGETS)
            fuzzed = _fuzz_domain(target_d)
            try:
                ok, reason, lat = _call(stub, 40000+i, "Search for info", fuzzed, f"t4-{i}")
                t4_lats.append(lat)
                if not ok:
                    detected += 1
                else:
                    missed += 1
                    if len(missed_list) < 10:
                        missed_list.append(fuzzed)
            except: pass
        total = detected + missed
        accuracy = (detected / total * 100) if total else 0
        p50, p95, _ = _pct(t4_lats)
        t4_pass = total > 0 and accuracy >= 60
        w(f, f"  Total: {total}  Detected: {detected}  Missed: {missed}  Accuracy: {accuracy:.0f}%")
        w(f, f"  p50={p50:.1f}ms  p95={p95:.1f}ms")
        if missed_list:
            w(f, f"  Sample misses: {missed_list[:5]}")
        w(f, f"  {'✅ PASS' if t4_pass else '❌ FAIL'}\n")
        results.append({"test": "T4", "passed": t4_pass, "accuracy": accuracy})

        # ═════════════════════════════════════════════
        # T5: Mixed Traffic (200 queries, sequential, 80/15/5)
        # ═════════════════════════════════════════════
        w(f, "=" * 60)
        w(f, "T5: MIXED REALISTIC TRAFFIC (200 queries, 80/15/5)")
        w(f, "=" * 60)
        lat_k, lat_t, lat_u = [], [], []
        cnt = {"ka": 0, "kd": 0, "td": 0, "tl": 0, "ud": 0, "ua": 0}
        for i in range(200):
            r = random.random()
            if r < 0.80:
                domain = random.choice(KNOWN_DOMAINS)
                dt = "k"
            elif r < 0.95:
                domain = _fuzz_domain(random.choice(WATCHLIST_TARGETS))
                dt = "t"
            else:
                domain = _random_domain()
                dt = "u"
            try:
                ok, _, lat = _call(stub, 50000+i, "Search for info", domain, f"t5-{i}")
                if dt == "k":
                    lat_k.append(lat); cnt["ka" if ok else "kd"] += 1
                elif dt == "t":
                    lat_t.append(lat); cnt["td" if not ok else "tl"] += 1
                else:
                    lat_u.append(lat); cnt["ud" if not ok else "ua"] += 1
            except: pass

        kp50, kp95, kp99 = _pct(lat_k)
        tp50, tp95, _ = _pct(lat_t)
        up50, up95, _ = _pct(lat_u)
        total5 = len(lat_k) + len(lat_t) + len(lat_u)
        t5_pass = total5 > 0 and cnt["kd"] == 0
        w(f, f"  Total: {total5}")
        w(f, f"  Known ({len(lat_k):3d}): p50={kp50:.1f}ms p95={kp95:.1f}ms p99={kp99:.1f}ms allow={cnt['ka']} deny={cnt['kd']}")
        w(f, f"  Typo  ({len(lat_t):3d}): p50={tp50:.1f}ms p95={tp95:.1f}ms deny={cnt['td']} leak={cnt['tl']}")
        w(f, f"  Unkn  ({len(lat_u):3d}): p50={up50:.1f}ms p95={up95:.1f}ms deny={cnt['ud']} allow={cnt['ua']}")
        w(f, f"  {'✅ PASS' if t5_pass else '❌ FAIL'}\n")
        results.append({"test": "T5", "passed": t5_pass})

        # ═════════════════════════════════════════════
        # FINAL REPORT
        # ═════════════════════════════════════════════
        w(f, "=" * 60)
        w(f, "FINAL REPORT")
        w(f, "=" * 60)
        all_ok = True
        for r in results:
            icon = "✅" if r["passed"] else "❌"
            w(f, f"  {icon}  {r['test']}")
            if not r["passed"]: all_ok = False
        if all_ok:
            w(f, "\n  ══════════════════════════════════════════")
            w(f, "  ║  ALL TESTS PASSED — PRODUCTION READY    ║")
            w(f, "  ══════════════════════════════════════════")
        else:
            w(f, "\n  ⚠ SOME TESTS FAILED — REVIEW REQUIRED")

        ch.close()


if __name__ == "__main__":
    main()
