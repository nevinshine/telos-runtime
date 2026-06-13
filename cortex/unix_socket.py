"""
Telos Cortex - Unix Socket IPC Client

Communicates with the Telos Core (Go eBPF Loader) via Unix Domain Socket.

Protocol:
    - JSON messages terminated by newline
    - Commands: UPDATE_TAINT, CLEAR_TAINT, GET_STATE
    - Responses: {success: bool, error?: string, data?: object}
"""

import json
import os
import socket
import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

log = logging.getLogger('telos.ipc')

DEFAULT_SOCKET_PATH = '/var/run/telos.sock'
BUFFER_SIZE = 4096
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0
DEFAULT_POOL_SIZE = int(os.environ.get('TELOS_IPC_POOL_SIZE', '4'))
POOL_ACQUIRE_TIMEOUT = 30.0

@dataclass
class _ConnectionSlot:
    """
    One persistent Unix socket connection with its own lock and backoff state.
    Each slot is independent — a slow or dead slot does not affect others.
    """
    socket_path: str
    slot_id: int
    sock: Optional[socket.socket] = field(default=None, repr=False)
    connected: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _next_reconnect_time: float = 0.0
    _reconnect_backoff: float = 1.0
    _max_backoff: float = 60.0

    def connect(self) -> bool:
        now = time.time()
        if now < self._next_reconnect_time:
            return False
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(CONNECT_TIMEOUT)
            self.sock.connect(self.socket_path)
            self.connected = True
            self._reconnect_backoff = 1.0
            self._next_reconnect_time = 0.0
            log.debug(f"[slot {self.slot_id}] Connected to {self.socket_path}")
            return True
        except FileNotFoundError:
            log.warning(f"[slot {self.slot_id}] Socket not found: {self.socket_path} (backoff {self._reconnect_backoff:.1f}s)")
            self._handle_failure(now)
            return False
        except ConnectionRefusedError:
            log.warning(f"[slot {self.slot_id}] Connection refused (backoff {self._reconnect_backoff:.1f}s)")
            self._handle_failure(now)
            return False
        except Exception as e:
            log.exception(f"[slot {self.slot_id}] Connection failed: {e}")
            self._handle_failure(now)
            return False

    def _handle_failure(self, now: float) -> None:
        self.connected = False
        self._next_reconnect_time = now + self._reconnect_backoff
        self._reconnect_backoff = min(self._reconnect_backoff * 2.0, self._max_backoff)

    def disconnect(self) -> None:
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def send_command(self, command: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send one command and read one response. Caller must hold self.lock."""
        if not self.connected:
            if not self.connect():
                return None
        try:
            message = {'command': command, 'data': data}
            payload = json.dumps(message) + '\n'
            if self.sock is None:
                log.error(f"[slot {self.slot_id}] sock is None after connect()")
                self.connected = False
                return None
            self.sock.sendall(payload.encode('utf-8'))
            log.debug(f"[slot {self.slot_id}] Sent: {command} -> {data}")
            self.sock.settimeout(READ_TIMEOUT)
            response_data = b''
            while True:
                chunk = self.sock.recv(BUFFER_SIZE)
                if not chunk:
                    break
                response_data += chunk
                if b'\n' in chunk:
                    break
            if response_data:
                response = json.loads(response_data.decode('utf-8').strip())
                log.debug(f"[slot {self.slot_id}] Received: {response}")
                return response
            log.warning(f"[slot {self.slot_id}] Empty response from Core")
            return None
        except socket.timeout:
            log.error(f"[slot {self.slot_id}] Response timeout")
            self.disconnect()
            return None
        except BrokenPipeError:
            log.error(f"[slot {self.slot_id}] Broken pipe")
            self.disconnect()
            return None
        except json.JSONDecodeError as e:
            log.error(f"[slot {self.slot_id}] Invalid JSON: {e}")
            return None
        except Exception as e:
            log.exception(f"[slot {self.slot_id}] IPC error: {e}")
            self.disconnect()
            return None


class _ConnectionPool:
    """
    Bounded pool of reusable Unix socket connections to the Core daemon.

    Threads acquire a slot via acquire(), use it, and the context manager
    returns it automatically. Slots are independent — one dead/slow slot
    does not block others.

    Note: With pool_size=N and READ_TIMEOUT=10s, worst-case wait for a new
    request is 10s (all slots blocked on slow Core responses). This is
    bounded and preferable to the previous design where one slow response
    blocked all requests indefinitely via a single global lock.

    The Go daemon supports concurrent connections (each gets its own goroutine
    via go handleConnection(conn)) so N simultaneous pool connections are safe.
    """

    def __init__(self, socket_path: str, pool_size: int):
        self._pool_size = pool_size
        self._slots: List[_ConnectionSlot] = [
            _ConnectionSlot(socket_path=socket_path, slot_id=i)
            for i in range(pool_size)
        ]
        self._semaphore = threading.Semaphore(pool_size)
        self._available: List[int] = list(range(pool_size))
        self._queue_lock = threading.Lock()

    def connect_all(self) -> bool:
        any_connected = False
        for slot in self._slots:
            with slot.lock:
                if slot.connect():
                    any_connected = True
        return any_connected

    def close_all(self) -> None:
        for slot in self._slots:
            with slot.lock:
                slot.disconnect()

    @contextmanager
    def acquire(self):
        acquired = self._semaphore.acquire(timeout=POOL_ACQUIRE_TIMEOUT)
        if not acquired:
            raise RuntimeError(
                f"IPC pool exhausted: no free connection slot within "
                f"{POOL_ACQUIRE_TIMEOUT}s. Core may be unresponsive."
            )
        with self._queue_lock:
            slot_id = self._available.pop()
        slot = self._slots[slot_id]
        try:
            yield slot
        finally:
            with self._queue_lock:
                self._available.append(slot_id)
            self._semaphore.release()

    @property
    def connected_count(self) -> int:
        return sum(1 for s in self._slots if s.connected)

class CoreIPCClient:
    """
    IPC Client to communicate with Telos Core (eBPF Loader).

    Uses a bounded connection pool so concurrent gRPC threads do not
    serialize on a single global lock. Each slot in the pool has its own
    socket and its own lock — unrelated agent operations proceed in parallel.

    Pool size defaults to DEFAULT_POOL_SIZE (4), configurable via the
    TELOS_IPC_POOL_SIZE environment variable.

    All public method signatures are unchanged from the previous implementation.
    """

    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH,
                 pool_size: int = DEFAULT_POOL_SIZE):
        self.socket_path = socket_path
        self._pool = _ConnectionPool(socket_path, pool_size)

    @property
    def connected(self) -> bool:
        """True if at least one pool slot has an open connection."""
        return self._pool.connected_count > 0

    def connect(self) -> bool:
        """
        Attempt to connect all pool slots.
        Returns True if at least one slot connected successfully.
        The client can operate without connection (standalone mode).
        """
        return self._pool.connect_all()

    def close(self) -> None:
        """Disconnect all pool slots."""
        self._pool.close_all()
        log.debug("IPC connection pool closed")

    def _send_command(self, command: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Acquire a free connection slot and send one command/response pair.

        The slot's own per-slot lock serializes only operations on that
        specific socket. Other slots are unaffected, so unrelated concurrent
        requests proceed in parallel.
        """
        try:
            with self._pool.acquire() as slot:
                with slot.lock:
                    return slot.send_command(command, data)
        except RuntimeError as e:
            log.error(f"IPC pool error: {e}")
            return None
        except Exception as e:
            log.exception(f"_send_command unexpected error: {e}")
            return None
    
    # === PUBLIC COMMANDS ===
    
    def send_update_taint(self, pid: int, taint_level: int) -> bool:
        """
        Update taint level for a process in the BPF map.
        
        Args:
            pid: Process ID to update
            taint_level: New taint level (0-4)
            
        Returns:
            True if Core acknowledged the update
        """
        response = self._send_command('UPDATE_TAINT', {
            'pid': pid,
            'taint_level': taint_level
        })
        
        if response and response.get('success'):
            log.info(f"Core: Taint updated for PID {pid} -> level {taint_level}")
            return True
        else:
            error = response.get('error', 'Unknown error') if response else 'No response'
            log.error(f"Core: Failed to update taint for PID {pid}: {error}")
            return False
    
    def send_clear_taint(self, pid: int) -> bool:
        """
        Clear taint for a process (remove from BPF map).
        
        Args:
            pid: Process ID to clear
            
        Returns:
            True if Core acknowledged
        """
        response = self._send_command('CLEAR_TAINT', {
            'pid': pid
        })
        
        if response and response.get('success'):
            log.info(f"Core: Taint cleared for PID {pid}")
            return True
        else:
            error = response.get('error', 'Unknown error') if response else 'No response'
            log.error(f"Core: Failed to clear taint for PID {pid}: {error}")
            return False

    def update_inode(self, inode: int, sensitivity: int) -> bool:
        """Update sensitivity for an inode."""
        response = self._send_command('UPDATE_INODE', {
            'inode': inode,
            'sensitivity': sensitivity
        })

        if response and response.get('success'):
            log.info(f"Core: Inode {inode} sensitivity updated to {sensitivity}")
            return True
        else:
            error = response.get('error', 'Unknown error') if response else 'No response'
            log.error(f"Core: Failed to update inode {inode} sensitivity: {error}")
            return False

    def update_network(self, ip: int, allowed: int) -> bool:
        """Update network allowlist for an IP."""
        resp = self._send_command('UPDATE_NETWORK', {
            'ip': ip,
            'allowed': allowed
        })
        return resp.get('success', False) if resp else False
        
    def add_network_rule(self, ip: int) -> bool:
        """Allow traffic to a specific IP."""
        return self.update_network(ip, 1)

    def delete_network(self, ip: int) -> bool:
        """
        Remove an IP from the allowlist map entirely.
        This frees up space in the BPF map.
        """
        resp = self._send_command('DELETE_NETWORK', {
            'ip': ip
        })
        return resp.get('success', False) if resp else False

    def remove_network_rule(self, ip: int) -> bool:
        """
        Block traffic to a specific IP by removing the rule.
        """
        # CHANGED: Use delete instead of update(0) to prevent map exhaustion
        return self.delete_network(ip)
    
    def send_register_agent(self, pid: int, comm: str = "") -> bool:
        """
        Register an agent process in the BPF map (for tracking).
        
        Args:
            pid: Agent process ID
            comm: Process command name (e.g., "python3")
            
        Returns:
            True if Core acknowledged
        """
        response = self._send_command('REGISTER_AGENT', {
            'pid': pid,
            'comm': comm[:15] if comm else ''  # BPF comm limit is 16 chars
        })
        
        if response and response.get('success'):
            log.info(f"Core: Agent registered PID {pid}")
            return True
        else:
            err = response.get('error', 'unknown mapping error') if response else 'No response from core'
            log.error(f"Core: Failed to register agent {pid}: {err}")
            return False
    
    def get_state(self) -> Optional[Dict[str, Any]]:
        """
        Get current state from Core (for debugging).
        
        Returns:
            State dict or None
        """
        response = self._send_command('GET_STATE', {})
        
        if response and response.get('success'):
            return response.get('data', {})
        return None

    def get_pid_taint_level(self, pid: int) -> Optional[int]:
        """Return the current kernel taint level for *pid* when Core is reachable."""
        state = self.get_state()
        if not state:
            return None
        processes = state.get("processes") or {}
        if not isinstance(processes, dict):
            return None
        rec = processes.get(str(pid))
        if not isinstance(rec, dict):
            return None
        try:
            return int(rec.get("taint_level", 0))
        except Exception:
            return None
    
    def clear_network_rule(self, ip_int: int) -> bool:
        """Helper to clear an IP from network map."""
        res = self._send_command('DELETE_NETWORK', {'ip': ip_int})
        return res is not None and res.get('success', False)

    def ping_core(self) -> bool:
        """
        [Phase 11: Heartbeat Mechanism]
        Send a heartbeat pulse to the Go Daemon.
        If this stops, the Daemon executes emergency Fail-Open or Fail-Closed.
        """
        res = self._send_command('IPC_PING', {})
        return res is not None and res.get('success', False)

    # === Phase 5: Execution Policy ===

    def send_update_exec(self, pid: int, allowed_bins: list, mode: int = 1) -> bool:
        """
        Push execution policy to BPF exec_policy_map.

        Args:
            pid: Agent process ID
            allowed_bins: List of allowed binary names (max 8, 16 chars each)
            mode: 0 = unrestricted, 1 = enforce allowlist

        Returns:
            True if Core acknowledged
        """
        response = self._send_command('UPDATE_EXEC', {
            'pid': pid,
            'mode': mode,
            'allowed_bins': allowed_bins[:8],
        })

        if response and response.get('success'):
            log.info(f"Core: Exec policy set for PID {pid}: {allowed_bins[:8]}")
            return True

        err = response.get('error', 'unknown error') if response else 'no response'
        log.error(f"Core: Failed to set exec policy for PID {pid}: {err}")
        return False

    def send_clear_exec(self, pid: int) -> bool:
        """
        Remove execution policy for a PID.

        Args:
            pid: Agent process ID

        Returns:
            True if Core acknowledged
        """
        response = self._send_command('CLEAR_EXEC', {'pid': pid})

        if response and response.get('success'):
            log.info(f"Core: Exec policy cleared for PID {pid}")
            return True
        return False

    # === Phase 4: Project Mirage ===

    def add_mirage_trap(self, inode: int, honey_id: int, payload: str) -> bool:
        """
        Inject a honey-token trap into the kernel maps.
        
        Args:
            inode: The real inode of the target file.
            honey_id: A unique ID for this payload.
            payload: The fake data to return (max 256 bytes per our C struct).
        """
        # Ensure payload fits within the kernel struct limits
        encoded_payload = payload.encode('utf-8')[:256]
        
        response = self._send_command('ADD_MIRAGE', {
            'inode': inode,
            'honey_id': honey_id,
            # Send as string; Go loader will convert to byte array
            'payload': encoded_payload.decode('utf-8', errors='ignore') 
        })
        
        if response and response.get('success'):
            log.info(f"Core: Mirage trap armed for inode {inode} (HoneyID: {honey_id})")
            return True
        else:
            error = response.get('error', 'Unknown error') if response else 'No response'
            log.error(f"Core: Failed to arm Mirage trap for inode {inode}: {error}")
            return False

    # === Phase 7: Layer 7 DPI (Hyperion XDP) ===

    def block_dns(self, domain: str) -> bool:
        """Push a malicious DNS domain signature to the XDP engine."""
        response = self._send_command('BLOCK_DNS', {
            'domain': domain
        })
        
        if response and response.get('success'):
            log.info(f"Core: XDP DNS Blocklist armed for '{domain}'")
            return True
        else:
            error = response.get('error', 'Unknown error') if response else 'No response'
            log.error(f"Core: Failed to arm DNS blocklist for '{domain}': {error}")
            return False

