"""
Telos Mirage Manager
Orchestrates active deception by binding honey-tokens to physical inodes.
"""

import os
import logging
from cortex.unix_socket import CoreIPCClient

log = logging.getLogger('telos.mirage')

class MirageManager:
    def __init__(self, ipc_client: CoreIPCClient, policy: dict):
        self.ipc = ipc_client
        self.config = policy.get('mirage', {})
        self.enabled = self.config.get('enabled', False)
        self.honey_files = self.config.get('honey_files', [])
        
        # Internal tracking
        self.active_traps = {} # path -> (inode, honey_id)
        self._next_honey_id = 1

    def arm_traps(self):
        """Resolve inodes and push traps to the kernel."""
        if not self.enabled:
            log.info("Mirage Engine is disabled in policy.")
            return

        log.info(f"Arming {len(self.honey_files)} Mirage traps...")
        
        for trap in self.honey_files:
            target_path = trap.get('path')
            payload = trap.get('payload', '')

            if not target_path or not os.path.exists(target_path):
                log.warning(f"Mirage target '{target_path}' does not exist. Skipping.")
                # In a production environment, you might touch/create the file here
                continue

            try:
                # 1. Resolve physical inode
                stat_info = os.stat(target_path)
                inode = stat_info.st_ino
                
                # 2. Assign Honey ID
                honey_id = self._next_honey_id
                self._next_honey_id += 1
                
                # 3. Push to Kernel via IPC
                success = self.ipc.add_mirage_trap(inode, honey_id, payload)
                
                if success:
                    self.active_traps[target_path] = (inode, honey_id)
                    log.info(f"✓ Trap armed on {target_path} (Inode: {inode})")

            except Exception as e:
                log.error(f"Failed to arm trap on {target_path}: {e}")
