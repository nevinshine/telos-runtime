"""Tests for Guardian thread safety under concurrent access.

Uses multiple threads to simulate concurrent agent registration,
taint updates, and session binding — verifying no state corruption.
"""
import threading
import time
import unittest

from cortex.guardian import Guardian


class GuardianThreadSafetyTests(unittest.TestCase):
    """Thread-safety tests for the Guardian class."""

    def test_concurrent_agent_registration(self):
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

        self.assertEqual(len(errors), 0, f"Errors during concurrent registration: {errors}")
        self.assertEqual(guardian.get_agent_count(), 10, f"Expected 10 agents, got {guardian.get_agent_count()}")
        self.assertIsNotNone(guardian.get_active_agent_pid(), "active_agent_pid should be set")

    def test_concurrent_taint_updates(self):
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

        self.assertEqual(len(errors), 0, f"Errors during concurrent taint updates: {errors}")
        taint = guardian.get_taint_level(2000)
        self.assertEqual(taint, 4, f"Expected max taint 4, got {taint}")
        self.assertEqual(
            guardian.get_taint_record_count(), 10,
            f"Expected 10 taint records, got {guardian.get_taint_record_count()}"
        )

    def test_concurrent_session_binding(self):
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

        self.assertEqual(len(errors), 0, f"Errors during concurrent session binding: {errors}")
        self.assertEqual(
            guardian.get_session_count(), 10,
            f"Expected 10 sessions, got {guardian.get_session_count()}"
        )

        for i in range(10):
            pid = guardian.get_session_pid(f"session_{i}")
            self.assertEqual(pid, 3000, f"session_{i} -> {pid}, expected 3000")

    def test_concurrent_register_and_taint(self):
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

        self.assertEqual(len(errors), 0, f"Errors during interleaved ops: {errors}")
        self.assertEqual(guardian.get_agent_count(), 10, f"Expected 10 agents, got {guardian.get_agent_count()}")
        self.assertEqual(
            guardian.get_taint_record_count(), 10,
            f"Expected 10 taint records, got {guardian.get_taint_record_count()}"
        )

    def test_concurrent_unregister(self):
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

        self.assertEqual(len(errors), 0, f"Errors during concurrent unregister: {errors}")
        self.assertEqual(
            guardian.get_agent_count(), 5,
            f"Expected 5 remaining agents, got {guardian.get_agent_count()}"
        )
        for i in range(5, 10):
            self.assertTrue(guardian.has_agent(5000 + i), f"Agent {5000 + i} should still be registered")

    def test_get_state_summary_thread_safe(self):
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
                self.assertIn('agents', summary)
                self.assertIn('taint_records', summary)
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

        self.assertEqual(len(errors), 0, f"Errors during read/write interleave: {errors}")


if __name__ == "__main__":
    unittest.main()
