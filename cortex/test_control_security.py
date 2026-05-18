#!/usr/bin/env python3
"""Regression tests for Cortex control-plane hardening."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import grpc

from cortex.auth import auth_metadata, metadata_has_valid_token
from cortex.guardian import Guardian
from cortex.main import TelosControlService
from shared import protocol_pb2


class FakeAbort(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class FakeContext:
    def abort(self, code, message):
        raise FakeAbort(code, message)


class FakeIPC:
    def __init__(self):
        self.exec_updates = []
        self.registered = []
        self.network_rules = []

    def send_update_exec(self, pid, allowed_bins, mode=1):
        self.exec_updates.append((pid, tuple(allowed_bins), mode))
        return True

    def send_clear_exec(self, pid):
        return True

    def add_network_rule(self, ip_int):
        self.network_rules.append(ip_int)
        return True

    def remove_network_rule(self, ip_int):
        return True

    def send_register_agent(self, pid, name):
        self.registered.append((pid, name))
        return True


class FakeVerifier:
    def verify(self, pid, goal, planned_actions, exec_actions):
        return True, "ok", 1000, [], []


class FakeDNSProxy:
    def allow_domain(self, domain, ttl_ms):
        return True


def make_service():
    ipc = FakeIPC()
    service = TelosControlService(Guardian({}), ipc, FakeVerifier(), FakeDNSProxy())
    return service, ipc


class CortexAuthTests(unittest.TestCase):
    def test_auth_metadata_accepts_bearer_token(self):
        self.assertTrue(metadata_has_valid_token(auth_metadata("secret"), "secret"))

    def test_auth_metadata_rejects_missing_or_wrong_token(self):
        self.assertFalse(metadata_has_valid_token((), "secret"))
        self.assertFalse(
            metadata_has_valid_token((("authorization", "Bearer wrong"),), "secret")
        )


class CortexControlSecurityTests(unittest.TestCase):
    def test_declare_intent_rejects_missing_proc_pid_before_ipc_mutation(self):
        service, ipc = make_service()
        request = protocol_pb2.IntentRequest(
            agent_pid=999999,
            natural_language_goal="download weather",
        )

        with mock.patch("cortex.main._pid_exists", return_value=False):
            with self.assertRaises(FakeAbort) as raised:
                service.DeclareIntent(request, FakeContext())

        self.assertEqual(raised.exception.code, grpc.StatusCode.INVALID_ARGUMENT)
        self.assertEqual(ipc.exec_updates, [])

    def test_declare_intent_rejects_session_rebinding(self):
        service, ipc = make_service()
        service.guardian.register_session("session-a", 111)
        request = protocol_pb2.IntentRequest(
            agent_pid=222,
            natural_language_goal="download weather",
            session_id="session-a",
        )

        with mock.patch("cortex.main._pid_exists", return_value=True):
            with self.assertRaises(FakeAbort) as raised:
                service.DeclareIntent(request, FakeContext())

        self.assertEqual(raised.exception.code, grpc.StatusCode.PERMISSION_DENIED)
        self.assertEqual(ipc.exec_updates, [])

    def test_get_policy_rejects_missing_proc_pid_before_registration(self):
        service, ipc = make_service()
        request = protocol_pb2.PolicyQuery(pid=999999)

        with mock.patch("cortex.main._pid_exists", return_value=False):
            with self.assertRaises(FakeAbort) as raised:
                service.GetPolicy(request, FakeContext())

        self.assertEqual(raised.exception.code, grpc.StatusCode.INVALID_ARGUMENT)
        self.assertEqual(ipc.registered, [])
        self.assertFalse(service.guardian.has_agent(999999))


if __name__ == "__main__":
    unittest.main()
