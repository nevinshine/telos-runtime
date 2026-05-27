"""
Test: DNS Proxy Drawbridge TTL Cleanup
Verifies that firewall rules opened by the DNS proxy are removed after TTL expires.
"""

import time
import threading
from unittest.mock import MagicMock, patch, call
from cortex.dns_proxy import TelosDNSProxy


def test_cleanup_timer_schedules_removal():
    """After add_network_rule, remove_network_rule should fire after TTL."""
    mock_ipc = MagicMock()
    mock_ipc.add_network_rule.return_value = True
    mock_ipc.remove_network_rule.return_value = True

    proxy = TelosDNSProxy(ipc_client=mock_ipc)

    # Simulate what happens inside _handle_request: schedule a cleanup with short TTL
    ip_int = 0x08080808  # 8.8.8.8
    proxy._schedule_drawbridge_cleanup(ip_int, "8.8.8.8", "example.com", ttl_seconds=1)

    # Timer should be tracked
    assert len(proxy._cleanup_timers) == 1, "Timer not tracked"

    # Wait for TTL to expire
    time.sleep(1.5)

    # remove_network_rule should have been called
    mock_ipc.remove_network_rule.assert_called_once_with(ip_int)

    # Timer should be cleaned up from the list
    assert len(proxy._cleanup_timers) == 0, "Timer not removed from list after firing"

    print("[PASS] Cleanup timer fires and removes rule after TTL")


def test_stop_cancels_pending_timers():
    """Calling stop() should cancel all pending cleanup timers."""
    mock_ipc = MagicMock()
    mock_ipc.add_network_rule.return_value = True
    mock_ipc.remove_network_rule.return_value = True

    proxy = TelosDNSProxy(ipc_client=mock_ipc)

    # Schedule multiple cleanups with long TTL
    proxy._schedule_drawbridge_cleanup(0x01010101, "1.1.1.1", "a.com", ttl_seconds=60)
    proxy._schedule_drawbridge_cleanup(0x02020202, "2.2.2.2", "b.com", ttl_seconds=60)
    proxy._schedule_drawbridge_cleanup(0x03030303, "3.3.3.3", "c.com", ttl_seconds=60)

    assert len(proxy._cleanup_timers) == 3, "Timers not tracked"

    # Stop should cancel all
    proxy.stop()

    assert len(proxy._cleanup_timers) == 0, "Timers not cleared on stop"

    # Wait a moment to confirm nothing fires
    time.sleep(0.5)
    mock_ipc.remove_network_rule.assert_not_called()

    print("[PASS] stop() cancels all pending timers")


def test_multiple_ips_independent_ttl():
    """Each IP gets its own independent TTL timer."""
    mock_ipc = MagicMock()
    mock_ipc.remove_network_rule.return_value = True

    proxy = TelosDNSProxy(ipc_client=mock_ipc)

    # Short TTL
    proxy._schedule_drawbridge_cleanup(0x0A0A0A0A, "10.10.10.10", "fast.com", ttl_seconds=1)
    # Longer TTL
    proxy._schedule_drawbridge_cleanup(0x0B0B0B0B, "11.11.11.11", "slow.com", ttl_seconds=3)

    time.sleep(1.5)

    # Only the short TTL should have fired
    mock_ipc.remove_network_rule.assert_called_once_with(0x0A0A0A0A)
    assert len(proxy._cleanup_timers) == 1, "Long TTL timer should still be pending"

    time.sleep(2)

    # Now both should have fired
    assert mock_ipc.remove_network_rule.call_count == 2
    mock_ipc.remove_network_rule.assert_any_call(0x0B0B0B0B)
    assert len(proxy._cleanup_timers) == 0

    print("[PASS] Independent TTL timers work correctly")


if __name__ == "__main__":
    test_cleanup_timer_schedules_removal()
    test_stop_cancels_pending_timers()
    test_multiple_ips_independent_ttl()
    print("\n[ALL TESTS PASSED]")
