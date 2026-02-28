#!/usr/bin/env python3
import sys
import os
import time
import socket
import argparse
import subprocess


# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cortex.unix_socket import CoreIPCClient

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8000
BLOCKED_HOST = '1.1.1.1' # Cloudflare DNS (often blocked in tests)
ALLOWED_HOST = '127.0.0.1' # Localhost

def test_file_access(path, expect_block=True):
    try:
        with open(path, 'r') as f:
            if expect_block:
                print(f"FAIL: Opened {path} (Expected Block=True)")
                return False
            else:
                print(f"PASS: Opened {path} (Allowed)")
                return True
    except PermissionError:
        if expect_block:
            print(f"PASS: Blocked {path} (Expected Block=True)")
            return True
        else:
            print(f"FAIL: Blocked {path} (Expected Block=False)")
            return False
    except Exception as e:
        print(f"ERROR: Accessing {path}: {e}")
        return False

def test_network_access(host, port=80, expect_block=True):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.close()
        if expect_block:
            print(f"FAIL: Connected to {host}:{port} (Expected Block=True)")
            return False
        else:
            print(f"PASS: Connected to {host}:{port} (Allowed)")
            return True
    except PermissionError:
         print(f"PASS: Blocked connection to {host} (EPERM)")
         return expect_block
    except OSError as e:
        # EPERM is 1 (Operation not permitted)
        if e.errno == 1:
            print(f"PASS: Blocked connection to {host} (EPERM)")
            return expect_block
        else:
            print(f"ERROR: Connecting to {host}: {e}")
            return False
    except Exception as e:
        print(f"ERROR: Connecting to {host}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, help='PID to taint (self if omitted)')
    parser.add_argument('--socket', default='/var/run/telos.sock', help='Path to Telos socket')
    args = parser.parse_args()

    pid = args.pid or os.getpid()
    client = CoreIPCClient(socket_path=args.socket)

    print(f"=== Telos M2 Verification [PID {pid}] ===")

    # 1. Clean State
    print("\n--- 1. Clean State ---")
    if not test_file_access('/etc/passwd', expect_block=False): sys.exit(1)
    if not test_network_access(BLOCKED_HOST, 80, expect_block=False): sys.exit(1)

    # 1.5 Populate Maps (Self-Contained Test)
    print("\n--- 1.5 Populating BPF Maps ---")
    
    # Block /etc/passwd
    import stat
    import struct
    try:
        passwd_ino = os.stat('/etc/passwd').st_ino
        if client.update_inode(passwd_ino, 4): # 4 = CRITICAL
            print(f"✓ Configured /etc/passwd (Inode {passwd_ino}) as SENSITIVE")
        else:
             print(f"✗ Failed to update inode {passwd_ino}")
    except Exception as e:
        print(f"✗ Error resolving /etc/passwd: {e}")

    # Allow 127.0.0.1 (Try both Endiannesses to be sure)
    try:
        packed_ip = socket.inet_aton("127.0.0.1")
        
        # Big Endian (Network Order)
        be_int = struct.unpack("!I", packed_ip)[0]
        if client.update_network(be_int, 1):
             print(f"✓ Configured 127.0.0.1 (Big Endian: {be_int}) as ALLOWED")

        # Little Endian (Native/Host Order on x86)
        le_int = struct.unpack("<I", packed_ip)[0]
        if client.update_network(le_int, 1):
             print(f"✓ Configured 127.0.0.1 (Little Endian: {le_int}) as ALLOWED")
             
    except Exception as e:
        print(f"✗ Error configuring network: {e}")

    # 2. Taint Process (CRITICAL)
    print("\n--- 2. Infecting Process (CRITICAL) ---")
    if client.send_update_taint(pid, 4): # 4 = CRITICAL
        print(f"✓ Tainted PID {pid} to Level 4")
    else:
        print("✗ Failed to taint process")
        sys.exit(1)
    
    time.sleep(1) # Give BPF map time to update

    # 3. Test File Blocking (Inode)
    print("\n--- 3. Testing Inode Blocking ---")
    # /etc/passwd is in policy as sensitive
    if not test_file_access('/etc/passwd', expect_block=True): sys.exit(1)
    
    # Symlink Attack Test
    symlink_path = '/tmp/telos_symlink_test'
    if os.path.exists(symlink_path):
        os.remove(symlink_path)
    os.symlink('/etc/passwd', symlink_path)
    print(f"Created symlink {symlink_path} -> /etc/passwd")
    
    if not test_file_access(symlink_path, expect_block=True): sys.exit(1)
    os.remove(symlink_path)

    # 4. Test Network Blocking
    print("\n--- 4. Testing Network Blocking ---")
    # 1.1.1.1 is NOT in allowed list (only 127.0.0.1 is)
    if not test_network_access(BLOCKED_HOST, 80, expect_block=True): sys.exit(1)

    # 5. Test Network Allowing
    print("\n--- 5. Testing Network Allowed ---")
    # 127.0.0.1 IS in allowed list
    # Need something listening there? Try standard port 22 or run a listener?
    # Actually, connect usually fails with ECONNREFUSED if nothing listening, which is NOT EPERM.
    # So if we get ECONNREFUSED, passed. If EPERM, failed.
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('127.0.0.1', 22)) 
        s.close()
        print(f"PASS: Connection to 127.0.0.1 allowed (Success)")
    except PermissionError:
        print(f"FAIL: Blocked connection to 127.0.0.1 (EPERM)")
        sys.exit(1)
    except OSError as e:
        if e.errno == 1: # EPERM
            print(f"FAIL: Blocked connection to 127.0.0.1 (EPERM)")
            sys.exit(1)
        else:
            print(f"PASS: Connection to 127.0.0.1 allowed ({e.strerror})")

    # 6. Clear Taint
    print("\n--- 6. Cleaning Up ---")
    client.send_clear_taint(pid)
    print("✓ Taint cleared")

    print("\n=== ✨ VERIFICATION SUCCESSFUL ✨ ===")

if __name__ == '__main__':
    main()
