import os
import sys
import time

# Add the parent directory to Python path to allow cortex import
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cortex.unix_socket import CoreIPCClient

ipc = CoreIPCClient()
if not ipc.connect():
    print("Failed to connect to Telos IPC. Is the daemon running?")
    sys.exit(1)

pid = os.getpid()
ipc.send_register_agent(pid, "torture_benchmark")

# Open the network and exec drawbridges so the test actually runs rather than just immediately faulting
import socket
ipc.add_network_rule(socket.gethostbyname("127.0.0.1"))
ipc._send_command('UPDATE_EXEC', {'pid': pid, 'allowed_bins': ['true', 'bench_torture'], 'mode': 1})

time.sleep(1) # Allow BPF maps to settle

# Replace current Python process with the C benchmark binary. 
# PID remains the same, so eBPF maps still apply!
os.execv("./bench_torture", ["./bench_torture"])
