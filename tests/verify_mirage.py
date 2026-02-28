#!/usr/bin/env python3
import os
import sys
import time

def check_file(path, is_tainted):
    role = "Tainted Agent" if is_tainted else "Clean Process"
    print(f"\n--- Testing as {role} ---")
    
    try:
        # 1. Check Metadata (The vfs_getattr Illusion)
        stat_info = os.stat(path)
        print(f"[*] stat() size reported: {stat_info.st_size} bytes")
        
        # 2. Read Content (The ksys_read Illusion)
        with open(path, 'r') as f:
            content = f.read()
            
        print(f"[*] Actual bytes read: {len(content)}")
        print(f"[*] Content:\n{content.strip()}")
        
    except PermissionError:
        print("[!] Blocked by LSM (Expected if Mirage is off and Tainted)")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: verify_mirage.py <path_to_honey_file>")
        sys.exit(1)
        
    target_file = sys.argv[1]
    
    # Test 1: Run normally (Clean)
    check_file(target_file, is_tainted=False)
    
    # Test 2: Taint this process and run again
    print("\n[*] Tainting current process via IPC...")
    from cortex.unix_socket import CoreIPCClient
    ipc = CoreIPCClient()
    ipc.connect()
    
    # Register and taint self to CRITICAL (4)
    pid = os.getpid()
    ipc.send_register_agent(pid, "verify_mirage")
    ipc.send_update_taint(pid, 4)
    time.sleep(0.5) # Wait for map update
    
    check_file(target_file, is_tainted=True)
    
    # Cleanup
    ipc.send_clear_taint(pid)
