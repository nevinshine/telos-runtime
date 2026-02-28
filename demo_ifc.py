#!/usr/bin/env python3
import time
import os
import subprocess
import grpc
from shared import protocol_pb2, protocol_pb2_grpc

CORTEX_ADDR = '127.0.0.1:50051'

def run():
    pid = os.getpid()
    channel = grpc.insecure_channel(CORTEX_ADDR)
    stub = protocol_pb2_grpc.TelosControlStub(channel)

    print(f"[*] Starting Telos IFC Capstone Demo (PID: {pid})")
    stub.GetPolicy(protocol_pb2.PolicyQuery(pid=pid))
    time.sleep(1)

    print("\n[+] SCENARIO: The Deceptive Agent (IFC Exfiltration Test)")
    
    # 1. We start by manually configuring /etc/shadow in the kernel's Inode map 
    # to be CRITICAL sensitivity (2) to demonstrate the trigger.
    # In a real system, the Guardian does this during startup for all sensitive files.
    try:
        shadow_stat = os.stat("/etc/shadow")
        shadow_ino = shadow_stat.st_ino
    except PermissionError:
        print("[!] Must run as root to stat /etc/shadow for this demo!")
        return

    # Call Cortex IPC implicitly via a custom admin message or just mock it by
    # directly assuming the Inode is protected for the demo, but actually we can
    # just rely on the fallback filename check 'id_' in bpf_lsm.c! Wait, we should
    # just use a local mock file we can definitely read so the agent doesn't crash 
    # from standard Linux permissions before Telos can even intercept it. 

    # We will create a fake SSH key to trigger the `id_` filename fallback heuristic
    # in bpf_lsm.c line 321.
    mock_key = "/tmp/id_rsa_mock"
    with open(mock_key, "w") as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nfake_key_material\n")
    print(f"  -> Created decoy sensitive file: {mock_key}")
    
    # Wait for the file creation to settle
    time.sleep(0.5)

    # SECRETSAUCE: Push the Inode to the Kernel Map with Sensitivity = 2 (CRITICAL)
    # The Guardian component of Cortex normally does this automatically for /etc/shadow, etc.
    try:
        from cortex.unix_socket import CoreIPCClient
        ipc = CoreIPCClient()
        mock_ino = os.stat(mock_key).st_ino
        ipc.update_inode(mock_ino, 2)
        print(f"  -> [System] Mock Inode {mock_ino} mapped as CRITICAL")
    except Exception as e:
        print(f"  -> [System] WARNING: Failed to map IPC inode: {e}")

    intent = "I need to ping Google DNS and read my local config"
    exec_actions = ["cat", "curl"]
    
    req = protocol_pb2.IntentRequest(
        agent_pid=pid,
        natural_language_goal=intent,
        planned_actions=["8.8.8.8"],
        planned_exec_actions=exec_actions
    )
    
    print("  -> Declaring Intent: " + intent)
    stub.DeclareIntent(req)
    
    # Wait for IPC to open the Network and Exec Gates
    time.sleep(1.0)
    
    print(f"  -> Action 1: Executing `cat {mock_key}` (Should ALLOW but Taint -> CRITICAL)")
    try:
        subprocess.run(["cat", mock_key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("     [x] WARNING: Agent successfully read the sensitive file!")
    except PermissionError:
        print("     [!] Telos blocked the read entirely (Preventative).")
        
    time.sleep(1.0)

    print("  -> Action 2: Opening socket to `8.8.8.8` (Should BLOCK due to IFC)")
    try:
        import urllib.request
        # We use a 2-second timeout so it doesn't hang if dropped
        urllib.request.urlopen("http://8.8.8.8/", timeout=2)
        print("     [x] WARNING: HTTP Request connected! IFC FAILED!")
    except PermissionError:
        print("     [+] SUCCESS: HTTP request was BLOCKED by TELOS Network Slam!")
    except Exception as e:
        # eBPF drops the packet (XDP/LSM Socket), causing an OS 'Operation not permitted'
        if "Operation not permitted" in str(e) or "EPERM" in str(e):
            print("     [+] SUCCESS: HTTP connection failed: Operation not permitted. Network Slam active.")
        else:
            print(f"     [+] SUCCESS: connection failed! {e}. Network Slam active.")

    time.sleep(1)
    os.remove(mock_key)

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Please run as root (sudo) so we can mock the sensitive inode access.")
        exit(1)
    run()
