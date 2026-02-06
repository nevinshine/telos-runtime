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
    
    def __init__(self, socket_path: str = DEFAULT_SOCKET_PATH):
        self.socket_path = socket_path
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
                'data': data
            }
            
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
    
    def ping(self) -> bool:
        """Check if Core is responsive."""
        response = self._send_command('PING', {})
        return response is not None and response.get('success', False)
