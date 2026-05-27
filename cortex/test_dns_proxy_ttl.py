"""
Test: DNS Proxy Drawbridge TTL Cleanup
Validates the new bounded cleanup worker, TTL normalization, and shared-IP refcounting.
"""

import time
import threading
from unittest.mock import MagicMock
from cortex.dns_proxy import TelosDNSProxy

def test_duplicate_domain_extends_cleanup():
    mock_ipc = MagicMock()
    mock_ipc.add_network_rule.return_value = True
    mock_ipc.remove_network_rule.return_value = True

    proxy = TelosDNSProxy(ipc_client=mock_ipc, max_workers=4)
    # Bypass normalize to test specific TTL
    proxy._normalize_ttl = lambda ttl_seconds, ip_int=None, domain=None: int(ttl_seconds)

    ip_int = 0x0A0A0A0A
    proxy._schedule_drawbridge_cleanup(ip_int, "10.10.10.10", "example.com", ttl_seconds=1)
    proxy._schedule_drawbridge_cleanup(ip_int, "10.10.10.10", "example.com", ttl_seconds=3)

    assert len(proxy._pending_cleanups) == 1, "Duplicate domain cleanup should be de-duplicated"
    expiry = next(iter(proxy._pending_cleanups.values()))
    assert expiry > time.time() + 2, "Extended TTL should be preserved"
    proxy.stop()

def test_shared_ip_cleanup_defers_until_all_auths_expire():
    mock_ipc = MagicMock()
    mock_ipc.add_network_rule.return_value = True
    mock_ipc.remove_network_rule.return_value = True

    proxy = TelosDNSProxy(ipc_client=mock_ipc)
    proxy._normalize_ttl = lambda ttl_seconds, ip_int=None, domain=None: int(ttl_seconds)

    ip_int = 0x0A0A0A0A
    proxy._schedule_drawbridge_cleanup(ip_int, "10.10.10.10", "first.com", ttl_seconds=1)
    proxy._schedule_drawbridge_cleanup(ip_int, "10.10.10.10", "second.com", ttl_seconds=3)

    time.sleep(1.5)
    mock_ipc.remove_network_rule.assert_not_called()

    time.sleep(2.5)
    mock_ipc.remove_network_rule.assert_called_once_with(ip_int)
    proxy.stop()

def test_cleanup_ordering_respects_earliest_expiry():
    mock_ipc = MagicMock()
    mock_ipc.add_network_rule.return_value = True
    mock_ipc.remove_network_rule.return_value = True

    proxy = TelosDNSProxy(ipc_client=mock_ipc)
    proxy._normalize_ttl = lambda ttl_seconds, ip_int=None, domain=None: int(ttl_seconds)

    first_ip = 0x0A0A0A0A
    second_ip = 0x0B0B0B0B

    proxy._schedule_drawbridge_cleanup(first_ip, "10.10.10.10", "fast.com", ttl_seconds=1)
    proxy._schedule_drawbridge_cleanup(second_ip, "11.11.11.11", "slow.com", ttl_seconds=2)

    time.sleep(1.25)
    mock_ipc.remove_network_rule.assert_called_once_with(first_ip)

    time.sleep(1.25)
    assert mock_ipc.remove_network_rule.call_count == 2, "Both TTL entries should fire in order"
    mock_ipc.remove_network_rule.assert_any_call(second_ip)
    proxy.stop()

def test_ttl_normalization_bounds():
    mock_ipc = MagicMock()
    proxy = TelosDNSProxy(ipc_client=mock_ipc)

    assert proxy._normalize_ttl(0, ip_int=0x01010101, domain='d.com') == 60
    assert proxy._normalize_ttl(1, ip_int=0x01010101, domain='d.com') == 60
    assert proxy._normalize_ttl(3600, ip_int=0x01010101, domain='d.com') == 3600
    assert proxy._normalize_ttl(10000, ip_int=0x01010101, domain='d.com') == 3600
    proxy.stop()

def test_thread_pool_respects_max_workers():
    mock_ipc = MagicMock()
    proxy = TelosDNSProxy(ipc_client=mock_ipc, max_workers=4)

    start_event = threading.Event()
    barrier = threading.Event()
    active_task_count = []

    def blocking_task(index):
        active_task_count.append(index)
        start_event.set()
        barrier.wait(timeout=5)

    futures = [proxy.executor.submit(blocking_task, i) for i in range(10)]
    time.sleep(0.5)

    assert len(proxy.executor._threads) <= 4, "Thread pool should not exceed max_workers"

    barrier.set()
    for future in futures:
        future.result(timeout=5)
    
    proxy.stop()

if __name__ == "__main__":
    test_duplicate_domain_extends_cleanup()
    test_shared_ip_cleanup_defers_until_all_auths_expire()
    test_ttl_normalization_bounds()
    test_thread_pool_respects_max_workers()
    print("\n[ALL DNS PROXY TTL TESTS PASSED]")
