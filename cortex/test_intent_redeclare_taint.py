"""Regression tests for issue #27 (intent replay via taint not re-checked)."""

import os
import sys
import unittest

# Add repo root for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cortex.guardian import Guardian
from cortex.main import TelosControlService
from shared import protocol_pb2


class FakeIPC:
    def __init__(self, taint_by_pid=None):
        self._taint_by_pid = dict(taint_by_pid or {})
        self.exec_updates = []

    def get_pid_taint_level(self, pid):
        return self._taint_by_pid.get(pid)

    def send_update_exec(self, pid, allowed_bins, mode=1):
        self.exec_updates.append((pid, tuple(allowed_bins), mode))
        return True

    def send_clear_exec(self, pid):
        return True

    def add_network_rule(self, ip_int):
        return True

    def remove_network_rule(self, ip_int):
        return True


class FakeVerifier:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.calls = []

    def verify(self, pid, goal, planned_actions, exec_actions):
        self.calls.append((pid, goal, tuple(planned_actions), tuple(exec_actions)))
        if self.allowed:
            return True, "ok", 1000, [], []
        return False, "deny", 0, [], []


class FakeDNSProxy:
    def allow_domain(self, domain, ttl_ms):
        return True


class IntentRedeclareTaintTests(unittest.TestCase):
    def test_declare_intent_rejects_kernel_tainted_pid(self):
        pid = os.getpid()
        ipc = FakeIPC({pid: protocol_pb2.TaintLevel.CRITICAL})
        verifier = FakeVerifier(allowed=True)
        service = TelosControlService(Guardian({}), ipc, verifier, FakeDNSProxy())

        request = protocol_pb2.IntentRequest(
            agent_pid=pid,
            natural_language_goal="download weather",
            planned_actions=["curl https://weather.com"],
        )
        verdict = service.DeclareIntent(request, context=None)

        self.assertFalse(verdict.allowed)
        self.assertIn("tainted", verdict.reason.lower())
        self.assertNotEqual(ipc.exec_updates, [])
        self.assertEqual(verifier.calls, [])

    def test_declare_intent_allows_when_core_has_no_taint(self):
        ipc = FakeIPC({})
        verifier = FakeVerifier(allowed=True)
        service = TelosControlService(Guardian({}), ipc, verifier, FakeDNSProxy())
        pid = os.getpid()

        request = protocol_pb2.IntentRequest(
            agent_pid=pid,
            natural_language_goal="download weather",
            planned_actions=["curl https://weather.com"],
        )
        verdict = service.DeclareIntent(request, context=None)

        self.assertTrue(verdict.allowed)
        self.assertEqual(len(verifier.calls), 1)


if __name__ == "__main__":
    unittest.main()

