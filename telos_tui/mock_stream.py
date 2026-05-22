#!/usr/bin/env python3
import socket
import os
import time
import json
import threading

EVENTS_SOCKET = "/var/run/telos_events.sock"
CORTEX_LOG = "/tmp/telos_cortex.log"

def mock_cortex():
    print(f"[*] Starting mock Cortex log writer to {CORTEX_LOG}...")
    try:
        if os.path.exists(CORTEX_LOG):
            os.remove(CORTEX_LOG)
    except PermissionError:
        pass

    with open(CORTEX_LOG, "a") as f:
        events = [
            "[Intent] declare network policy for node",
            "✅ Intent APPROVED: policy enforced",
            "[Intent] declare outbound connection to unknown IP",
            "❌ Intent DENIED: unverified signature"
        ]
        while True:
            for ev in events:
                f.write(ev + "\n")
                f.flush()
                time.sleep(3.5)

def mock_bpf():
    print(f"[*] Starting mock BPF event server on {EVENTS_SOCKET}...")
    if os.path.exists(EVENTS_SOCKET):
        os.remove(EVENTS_SOCKET)
    
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(EVENTS_SOCKET)
    except PermissionError:
        print("[!] Permission denied binding to /var/run/. Please run with sudo.")
        return
        
    server.listen(1)
    
    while True:
        print("[*] Waiting for UI to connect...")
        conn, _ = server.accept()
        print("[+] UI connected to mock BPF socket! Streaming events...")
        try:
            events = [
                {"timestamp": "12:00:00", "pid": 1042, "taint_level": 0, "desc": "sys_read"},
                {"timestamp": "12:00:01", "pid": 3391, "taint_level": 0, "desc": "sys_write"},
                {"timestamp": "12:00:02", "pid": 8991, "taint_level": 5, "desc": "taint_elevate"},
                {"timestamp": "12:00:03", "pid": 8991, "taint_level": 10, "desc": "exec_denied"},
                {"timestamp": "12:00:04", "pid": 8991, "taint_level": 10, "desc": "exfil_blocked"},
            ]
            while True:
                for ev in events:
                    conn.send((json.dumps(ev) + "\n").encode())
                    time.sleep(1.8)
        except Exception:
            print("[-] UI disconnected.")
            conn.close()

if __name__ == "__main__":
    t1 = threading.Thread(target=mock_cortex, daemon=True)
    t1.start()
    mock_bpf()
