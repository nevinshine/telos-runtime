import socket
import threading
import time
import json
import os
import random
from http.server import HTTPServer, BaseHTTPRequestHandler

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            metrics = f"""
# HELP telos_bpf_events_total Total BPF events processed
# TYPE telos_bpf_events_total counter
telos_bpf_events_total {random.randint(1000, 5000)}
# HELP telos_intent_events_total Total Intent events processed
# TYPE telos_intent_events_total counter
telos_intent_events_total {random.randint(500, 2000)}
# HELP telos_active_drawbridges Total active drawbridges
# TYPE telos_active_drawbridges gauge
telos_active_drawbridges {random.randint(1, 15)}
            """
            self.wfile.write(metrics.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def run_metrics_server():
    server = HTTPServer(("127.0.0.1", 9094), MetricsHandler)
    server.serve_forever()

def run_bpf_socket_server(socket_path="/tmp/telos_events.sock"):
    if os.path.exists(socket_path):
        os.remove(socket_path)
    
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(5)
    
    actions = ["exec_denied", "connect_denied", "file_open", "taint_elevate", "bpf_prog_load"]
    comms = ["bash", "curl", "python3", "node", "java", "wget", "containerd", "docker", "ssh"]

    while True:
        conn, _ = server.accept()
        def handle_client(c):
            with c:
                try:
                    while True:
                        target = random.choice([
                            f"/etc/shadow", f"/var/run/docker.sock", f"192.168.1.{random.randint(1,255)}:443", 
                            f"10.0.{random.randint(0,255)}.{random.randint(1,255)}:8080",
                            f"/usr/bin/cat", "unknown_syscall"
                        ])
                        event = {
                            "pid": random.randint(100, 30000),
                            "taint_level": random.choice([0, 0, 1, 1, 2, 3]),
                            "blocked": random.choice([0, 1, 1]),
                            "comm": random.choice(comms),
                            "desc": f"{random.choice(actions)} -> {target}"
                        }
                        c.sendall((json.dumps(event) + "\n").encode("utf-8"))
                        time.sleep(random.uniform(1.0, 4.0))
                except Exception:
                    pass
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

def run_cortex_logger(log_path="/tmp/telos_cortex.log"):
    intents = [
        "[Intent] Analyze unexpected process spawn graph",
        "[Intent] Validating container 10.4.0.12 network anomaly",
        "[Intent] Checking trust chain for system update",
        "[Intent] Deep trace of SSH lateral movement pattern",
        "[Intent] Verifying kernel module cryptographic signature"
    ]
    approvals = [
        "Intent APPROVED: Trust verified via signed certificate",
        "Intent APPROVED: Action matches known maintenance window",
        "Intent APPROVED: Routine database sync validated",
        "Intent APPROVED: Internal subnet traffic permitted"
    ]
    denials = [
        "Intent DENIED: Exploit signature matched in memory",
        "Intent DENIED: Unauthorized egress traffic to unknown IP",
        "Intent DENIED: Attempt to access sensitive credential store",
        "Intent DENIED: Kernel module load violates integrity policy",
        "Intent DENIED: Shell spawned from web server process"
    ]
    execs = [
        "[EI] Tracking spawned sub-process: /usr/bin/wget",
        "[EI] Enforcing rate limit on socket bind",
        "[EI] Initiated process snapshot for forensic buffer"
    ]
    with open(log_path, "a") as f:
        while True:
            category = random.choices([intents, approvals, denials, execs], weights=[0.2, 0.4, 0.3, 0.1])[0]
            log = random.choice(category)
            f.write(f"{datetime_now()} {log}\n")
            f.flush()
            time.sleep(random.uniform(1.5, 5.0))

def datetime_now():
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")

if __name__ == "__main__":
    threading.Thread(target=run_metrics_server, daemon=True).start()
    threading.Thread(target=run_bpf_socket_server, daemon=True).start()
    threading.Thread(target=run_cortex_logger, daemon=True).start()
    
    print("Simulating rich real-world data...")
    while True:
        time.sleep(1)
