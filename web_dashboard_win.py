#!/usr/bin/env python3
"""
Telos Web Dashboard Bridge (Windows Compatible)
"""

import argparse
import hmac
import http.cookies
import ipaddress
import json
import os
import socket
import threading
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Windows-friendly paths
DEFAULT_CORTEX_LOG = os.path.join(tempfile.gettempdir(), 'telos_cortex.log')
# Socket won't work on Windows, using a dummy path
EVENTS_SOCKET = "NUL" 
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_dashboard")
METRICS_URL = "http://127.0.0.1:9094/metrics"
MAX_EVENTS = 100

class DashboardState:
    def __init__(self, max_events: int = MAX_EVENTS):
        self.max_events = max_events
        self.bpf_events = deque(maxlen=max_events)
        self.intent_events = deque(maxlen=max_events)
        self.bridge_errors = deque(maxlen=20)
        self.stats = {"denied": 0, "elevated": 0, "allowed": 0}
        self.lock = threading.Lock()

    def add_bpf_event(self, event):
        if not isinstance(event, dict) or not event:
            return
        action = event.get("desc") or "unknown"
        item = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "pid": event.get("pid") or 0,
            "taint_level": event.get("taint_level") or 0,
            "blocked": event.get("blocked") or 0,
            "comm": event.get("comm") or "",
            "action": action,
        }
        with self.lock:
            if item["blocked"]:
                self.stats["denied"] += 1
            if action == "taint_elevate":
                self.stats["elevated"] += 1
            self.bpf_events.appendleft(item)

    def add_intent_line(self, line: str):
        if not line: return
        line = line.strip()
        item = None
        if "[Intent]" in line:
            item = {"time": datetime.now().strftime("%H:%M:%S"), "type": "intent", "message": line.split("[Intent]", 1)[-1].strip()}
        elif "Intent APPROVED" in line:
            item = {"time": datetime.now().strftime("%H:%M:%S"), "type": "approved", "message": line.split("APPROVED:", 1)[-1].strip()}
        elif "Intent DENIED" in line:
            item = {"time": datetime.now().strftime("%H:%M:%S"), "type": "denied", "message": line.split("DENIED:", 1)[-1].strip()}
        
        if item:
            with self.lock:
                if item["type"] == "approved": self.stats["allowed"] += 1
                self.intent_events.appendleft(item)

    def snapshot(self):
        with self.lock:
            return {
                "bpf_events": list(self.bpf_events),
                "intent_events": list(self.intent_events),
                "bridge_errors": list(self.bridge_errors),
                "stats": dict(self.stats),
            }

def authorized(headers, path, token):
    if not token: return True
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], token): return True
    return False

def stream_bpf_events(state):
    # eBPF not supported on Windows, just idle
    return

def tail_cortex_log(state, log_path):
    print(f"Monitoring Cortex log: {log_path}")
    while True:
        try:
            if os.path.exists(log_path):
                with open(log_path, "r", encoding='utf-8', errors='replace') as f:
                    f.seek(0, 2)
                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(0.5)
                            continue
                        state.add_intent_line(line)
            else:
                time.sleep(2)
        except Exception as e:
            print(f"Log tail error: {e}")
            time.sleep(2)

def make_handler(state, token):
    class DashboardHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=STATIC_DIR, **kwargs)

        def do_GET(self):
            if not authorized(self.headers, self.path, token):
                self.send_response(401)
                self.end_headers()
                return

            if self.path == "/api/snapshot":
                body = json.dumps(state.snapshot()).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
                return

            if self.path == "/api/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                while True:
                    try:
                        payload = json.dumps(state.snapshot())
                        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                        self.wfile.flush()
                        time.sleep(1)
                    except: break
                return
            
            return super().do_GET()
    return DashboardHandler

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--log", default=DEFAULT_CORTEX_LOG)
    args = parser.parse_args()

    state = DashboardState()
    token = os.environ.get("TELOS_DASH_TOKEN", "")

    threading.Thread(target=tail_cortex_log, args=(state, args.log), daemon=True).start()
    
    server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(state, token))
    print(f"Telos Dashboard running at http://127.0.0.1:{args.port}")
    server.serve_forever()

if __name__ == "__main__":
    main()
