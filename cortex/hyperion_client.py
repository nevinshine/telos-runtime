import json
import socket
import logging
import time
from typing import Optional

log = logging.getLogger('telos.hyperion_client')

class HyperionClient:
    def __init__(self, socket_path: str = "/tmp/hyperion.sock"):
        self.socket_path = socket_path

    def _send_command(self, command: str, payload: str) -> bool:
        """Sends a JSON command to the Hyperion IPC server with basic retries."""
        req = {
            "command": command,
            "payload": payload
        }
        
        # Exponential backoff parameters (similar to CoreIPCClient)
        max_retries = 3
        base_delay = 0.5
        
        for attempt in range(max_retries):
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.settimeout(2.0)
                    s.connect(self.socket_path)
                    s.sendall(json.dumps(req).encode('utf-8'))
                    
                    response_data = s.recv(4096)
                    if not response_data:
                        return False
                        
                    resp = json.loads(response_data.decode('utf-8'))
                    if resp.get("success"):
                        return True
                    else:
                        log.error(f"Hyperion IPC Error: {resp.get('message')}")
                        return False
                        
            except (socket.timeout, ConnectionRefusedError, FileNotFoundError) as e:
                log.debug(f"Hyperion IPC connection failed (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(base_delay * (2 ** attempt))
            except Exception as e:
                log.error(f"Hyperion IPC exception: {e}")
                return False
                
        log.error("Failed to communicate with Hyperion XDP Controller")
        return False

    def block_ip(self, ip_address: str) -> bool:
        """Blocks an IP address at Layer 2 (wire-speed) via Hyperion XDP."""
        log.info(f"Issuing Hyperion BLOCK_IP for: {ip_address}")
        return self._send_command("block_ip", ip_address)

    def add_signature(self, signature: str) -> bool:
        """Adds a payload signature to the Hyperion XDP policy map."""
        log.info(f"Issuing Hyperion ADD_SIGNATURE for: {signature}")
        return self._send_command("add_signature", signature)
