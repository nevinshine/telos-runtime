"""
Regression test for issue #107.
"""

import threading
import time
import unittest

import cortex.unix_socket as ipc_module
from cortex.unix_socket import CoreIPCClient, DEFAULT_POOL_SIZE


class FakeSocket:
    DELAY = 0.1

    def settimeout(self, t): pass
    def sendall(self, data): pass
    def recv(self, n):
        time.sleep(self.DELAY)
        return b'{"success": true, "data": {}}\n'
    def close(self): pass
    def connect(self, path): pass


def _make_client(pool_size=DEFAULT_POOL_SIZE):
    client = CoreIPCClient(socket_path='/tmp/fake_telos.sock', pool_size=pool_size)
    for slot in client._pool._slots:
        slot.sock = FakeSocket()
        slot.connected = True
    return client


class TestIPCConcurrency(unittest.TestCase):

    def test_concurrent_calls_faster_than_serial(self):
        n = DEFAULT_POOL_SIZE
        client = _make_client(pool_size=n)
        individual_times = []
        lock = threading.Lock()

        def call():
            start = time.perf_counter()
            client._send_command('IPC_PING', {})
            with lock:
                individual_times.append(time.perf_counter() - start)

        threads = [threading.Thread(target=call) for _ in range(n)]
        wall_start = time.perf_counter()
        for t in threads: t.start()
        for t in threads: t.join()
        wall_time = time.perf_counter() - wall_start
        serial_sum = sum(individual_times)

        self.assertLess(wall_time, serial_sum * 0.5,
            f"Calls appear serialized: wall={wall_time:.3f}s serial_sum={serial_sum:.3f}s")

    def test_pool_size_one_serializes(self):
        n = 3
        client = _make_client(pool_size=1)
        threads = [threading.Thread(target=lambda: client._send_command('IPC_PING', {}))
                   for _ in range(n)]
        wall_start = time.perf_counter()
        for t in threads: t.start()
        for t in threads: t.join()
        wall_time = time.perf_counter() - wall_start

        self.assertGreaterEqual(wall_time, n * FakeSocket.DELAY * 0.9)

    def test_dead_slot_does_not_block_other_slots(self):
        n = DEFAULT_POOL_SIZE
        client = _make_client(pool_size=n)
        client._pool._slots[0].connected = False
        client._pool._slots[0].sock = None
        client._pool._slots[0]._next_reconnect_time = time.time() + 9999

        successes = []
        result_lock = threading.Lock()

        def call():
            result = client._send_command('IPC_PING', {})
            with result_lock:
                if result and result.get('success'):
                    successes.append(1)

        threads = [threading.Thread(target=call) for _ in range(n - 1)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(len(successes), n - 1)

    def test_pool_acquire_timeout_returns_none(self):
        original = ipc_module.POOL_ACQUIRE_TIMEOUT
        try:
            ipc_module.POOL_ACQUIRE_TIMEOUT = 0.2
            client = _make_client(pool_size=1)
            slot_held = threading.Event()
            release_slot = threading.Event()

            def hold():
                with client._pool.acquire():
                    slot_held.set()
                    release_slot.wait(timeout=5)

            holder = threading.Thread(target=hold, daemon=True)
            holder.start()
            slot_held.wait(timeout=2)

            result = client._send_command('IPC_PING', {})
            self.assertIsNone(result)
        finally:
            release_slot.set()
            holder.join(timeout=2)
            ipc_module.POOL_ACQUIRE_TIMEOUT = original

    def test_slots_have_independent_locks(self):
        client = _make_client()
        lock_ids = [id(slot.lock) for slot in client._pool._slots]
        self.assertEqual(len(lock_ids), len(set(lock_ids)))

    def test_all_public_methods_callable(self):
        client = _make_client()
        client.send_update_taint(1234, 2)
        client.send_clear_taint(1234)
        client.update_inode(999, 1)
        client.update_network(0x01010101, 1)
        client.add_network_rule(0x01010101)
        client.delete_network(0x01010101)
        client.remove_network_rule(0x01010101)
        client.clear_network_rule(0x01010101)
        client.send_register_agent(1234, "python3")
        client.get_state()
        client.get_pid_taint_level(1234)
        client.ping_core()
        client.send_update_exec(1234, ["curl"], mode=1)
        client.send_clear_exec(1234)
        client.add_mirage_trap(999, 1, "fake payload")

    def test_connected_property(self):
        client = _make_client(pool_size=2)
        self.assertTrue(client.connected)
        for slot in client._pool._slots:
            slot.connected = False
        self.assertFalse(client.connected)
        client._pool._slots[0].connected = True
        self.assertTrue(client.connected)


if __name__ == '__main__':
    unittest.main(verbosity=2)