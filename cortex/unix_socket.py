"""
Telos Cortex - Unix Socket IPC Client

Communicates with the Telos Core (Go eBPF Loader) via Unix Domain Socket.

Protocol:
    - JSON messages terminated by newline
    - Commands: UPDATE_TAINT, CLEAR_TAINT, GET_STATE
    - Responses: {success: bool, error?: string, data?: object}
"""

import json
import socket
import logging
from typing import Optional, Dict, Any

log = logging.getLogger('telos.ipc')

DEFAULT_SOCKET_PATH = '/var/run/telos.sock'
BUFFER_SIZE = 4096
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 10.0


class CoreIPCClient:
    """
    IPC Client to communicate with Telos Core (eBPF Loader).
    
    The Core listens on a Unix socket and accepts JSON commands
    to update BPF maps.
    """
    
    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH, auth_token: str = ""):
        self.socket_path = socket_path
        self.auth_token = auth_token
        self.sock: Optional[socket.socket] = None
        self.connected = False
    
    def connect(self) -> bool:
        """
        Establish connection to the Core daemon.
        
        Returns True if connected, False otherwise.
        The client can operate without connection (standalone mode).
        """
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(CONNECT_TIMEOUT)
            self.sock.connect(self.socket_path)
            self.connected = True
            log.info(f"Connected to Core at {self.socket_path}")
            return True
            
        except FileNotFoundError:
            log.warning(f"Core socket not found: {self.socket_path}")
            self.connected = False
            return False
        except ConnectionRefusedError:
            log.warning(f"Core connection refused: {self.socket_path}")
            self.connected = False
            return False
        except Exception as e:
            log.error(f"Core connection failed: {e}")
            self.connected = False
            return False
    
    def close(self) -> None:
        """Close the socket connection."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.connected = False
            log.debug("IPC connection closed")
    
    def _send_command(self, command: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send a command to Core and wait for response.
        
        Args:
            command: Command type (UPDATE_TAINT, CLEAR_TAINT, etc.)
            data: Command payload
            
        Returns:
            Response dict or None on failure
        """
        if not self.connected:
            # Try to reconnect
            if not self.connect():
                return None
        
        try:
            # Build message
            message = {
                'command': command,
                'data': data,
            }
            
            # Include auth token if configured (defense in depth)
            if self.auth_token:
                message['token'] = self.auth_token
            
            # Send as JSON + newline
            payload = json.dumps(message) + '\n'
            self.sock.sendall(payload.encode('utf-8'))
            log.debug(f"Sent: {command} -> {data}")
            
            # Read response
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
                log.debug(f"Received: {response}")
                return response
            else:
                log.warning("Empty response from Core")
                return None
                
        except socket.timeout:
            log.error("Core response timeout")
            self._handle_disconnect()
            return None
        except BrokenPipeError:
            log.error("Core disconnected (broken pipe)")
            self._handle_disconnect()
            return None
        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON response: {e}")
            return None
        except Exception as e:
            log.error(f"IPC error: {e}")
            self._handle_disconnect()
            return None
    
    def _handle_disconnect(self) -> None:
        """Handle unexpected disconnection."""
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
    
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


