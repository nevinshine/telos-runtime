"""
Test Guardian thread safety under concurrent gRPC-style access.
Spawns multiple threads to simulate concurrent agent registration,
taint updates, and session binding — verifying no state corruption.
"""
import threading
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cortex.guardian import Guardian


def test_concurrent_agent_registration():
    """Multiple threads registering agents simultaneously should not corrupt state."""
    guardian = Guardian({"max_taint_for_exec": 2})
    errors = []
    barrier = threading.Barrier(10)

    def register_agent(pid):
        barrier.wait()
        try:
            guardian.register_agent(pid)
        except Exception as e:
            errors.append(f"register_agent({pid}): {e}")

    threads = []
    for i in range(10):
        t = threading.Thread(target=register_agent, args=(1000 + i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Errors during concurrent registration: {errors}"
    assert len(guardian.agents) == 10, f"Expected 10 agents, got {len(guardian.agents)}"
    assert guardian.active_agent_pid is not None, "active_agent_pid should be set"
    print("[PASS] Concurrent agent registration: 10 threads, 10 agents, no corruption")


def test_concurrent_taint_updates():
    """Concurrent taint updates should not lose or corrupt taint levels."""
    guardian = Guardian({"max_taint_for_exec": 2})
    guardian.register_agent(2000)
    errors = []
    barrier = threading.Barrier(10)

    def update_taint(source_id, level):
        barrier.wait()
        try:
            guardian.update_taint(source_id, level, url=f"http://test/{source_id}")
        except Exception as e:
            errors.append(f"update_taint({source_id}, {level}): {e}")

    threads = []
    for i in range(10):
        t = threading.Thread(target=update_taint, args=(f"source_{i}", i % 5))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Errors during concurrent taint updates: {errors}"
    taint = guardian.get_taint_level(2000)
    assert taint == 4, f"Expected max taint 4, got {taint}"
    assert len(guardian.taint_records) == 10, f"Expected 10 taint records, got {len(guardian.taint_records)}"
    print("[PASS] Concurrent taint updates: 10 threads, max taint correctly tracked")


def test_concurrent_session_binding():
    """Concurrent session registrations should not corrupt session_map."""
    guardian = Guardian({"max_taint_for_exec": 2})
    guardian.register_agent(3000)
    errors = []
    barrier = threading.Barrier(10)

    def bind_session(session_id):
        barrier.wait()
        try:
            guardian.register_session(session_id, 3000)
        except Exception as e:
            errors.append(f"register_session({session_id}): {e}")

    threads = []
    for i in range(10):
        t = threading.Thread(target=bind_session, args=(f"session_{i}",))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Errors during concurrent session binding: {errors}"
    assert len(guardian.session_map) == 10, f"Expected 10 sessions, got {len(guardian.session_map)}"

    for i in range(10):
        pid = guardian.get_session_pid(f"session_{i}")
        assert pid == 3000, f"session_{i} -> {pid}, expected 3000"

    print("[PASS] Concurrent session binding: 10 threads, all sessions correctly mapped")


def test_concurrent_register_and_taint():
    """Registration and taint updates interleaved should not cause corruption."""
    guardian = Guardian({"max_taint_for_exec": 2})
    errors = []
    start_barrier = threading.Barrier(20)

    def register(pid):
        start_barrier.wait()
        try:
            guardian.register_agent(pid)
        except Exception as e:
            errors.append(f"register({pid}): {e}")

    def taint(source_id, level):
        start_barrier.wait()
        try:
            guardian.update_taint(source_id, level, url=f"http://test/{source_id}")
        except Exception as e:
            errors.append(f"taint({source_id}, {level}): {e}")

    threads = []
    for i in range(10):
        threads.append(threading.Thread(target=register, args=(4000 + i,)))
        threads.append(threading.Thread(target=taint, args=(f"src_{i}", i % 5)))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Errors during interleaved ops: {errors}"
    assert len(guardian.agents) == 10, f"Expected 10 agents, got {len(guardian.agents)}"
    assert len(guardian.taint_records) == 10, f"Expected 10 taint records, got {len(guardian.taint_records)}"
    print("[PASS] Interleaved register + taint: 20 threads, no corruption")


def test_concurrent_unregister():
    """Concurrent unregister should not corrupt remaining state."""
    guardian = Guardian({"max_taint_for_exec": 2})
    for i in range(10):
        guardian.register_agent(5000 + i)

    errors = []
    barrier = threading.Barrier(5)

    def unregister(pid):
        barrier.wait()
        try:
            guardian.unregister_agent(pid)
        except Exception as e:
            errors.append(f"unregister({pid}): {e}")

    threads = []
    for i in range(5):
        t = threading.Thread(target=unregister, args=(5000 + i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0, f"Errors during concurrent unregister: {errors}"
    assert len(guardian.agents) == 5, f"Expected 5 remaining agents, got {len(guardian.agents)}"
    for i in range(5, 10):
        assert (5000 + i) in guardian.agents, f"Agent {5000 + i} should still be registered"
    print("[PASS] Concurrent unregister: 5 threads, 5 agents removed, 5 remain")


def test_get_state_summary_thread_safe():
    """get_state_summary should not crash under concurrent mutation."""
    guardian = Guardian({"max_taint_for_exec": 2})
    for i in range(10):
        guardian.register_agent(6000 + i)

    errors = []
    barrier = threading.Barrier(15)

    def mutate(pid):
        barrier.wait()
        try:
            guardian.update_taint(f"view_{pid}", pid % 5, url=f"http://t/{pid}")
        except Exception as e:
            errors.append(f"mutate({pid}): {e}")

    def read():
        barrier.wait()
        try:
            summary = guardian.get_state_summary()
            assert 'agents' in summary
            assert 'taint_records' in summary
        except Exception as e:
            errors.append(f"read: {e}")

    threads = []
    for i in range(10):
        threads.append(threading.Thread(target=mutate, args=(6000 + i,)))
    for _ in range(5):
        threads.append(threading.Thread(target=read))

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Errors during read/write interleave: {errors}"
    print("[PASS] get_state_summary under concurrent mutation: no crashes or corruption")


if __name__ == "__main__":
    print("=== Guardian Thread Safety Tests ===\n")
    test_concurrent_agent_registration()
    test_concurrent_taint_updates()
    test_concurrent_session_binding()
    test_concurrent_register_and_taint()
    test_concurrent_unregister()
    test_get_state_summary_thread_safe()
    print("\n[ALL TESTS PASSED]")
