#!/usr/bin/env python3
"""
Telos Web Dashboard Bridge

Serves a static browser dashboard and bridges existing local telemetry sources:
- /var/run/telos_events.sock for eBPF events
- /tmp/telos_cortex.log for Cortex intent events
- http://127.0.0.1:9094/metrics for Prometheus counters
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
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


EVENTS_SOCKET = "/var/run/telos_events.sock"
CORTEX_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "telos_cortex.log")
METRICS_URL = "http://127.0.0.1:9094/metrics"
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_dashboard")
MAX_EVENTS = 100
BPF_BLOCK_ACTIONS = {
    "exec_denied",
    "exec_tainted",
    "exfil_blocked",
    "connect_denied",
    "connect_ipv6_denied",
}


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
            if item["blocked"] or action in BPF_BLOCK_ACTIONS:
                self.stats["denied"] += 1
            if action == "taint_elevate":
                self.stats["elevated"] += 1
            self.bpf_events.appendleft(item)

    def add_intent_line(self, line: str):
        if not line:
            return

        line = line.strip()
        item = None
        if "[Intent]" in line:
            item = {"time": datetime.now().strftime("%H:%M:%S"), "type": "intent", "message": line.split("[Intent]", 1)[-1].strip()}
        elif "Intent APPROVED" in line:
            item = {"time": datetime.now().strftime("%H:%M:%S"), "type": "approved", "message": line.split("APPROVED:", 1)[-1].strip()}
        elif "Intent DENIED" in line:
            item = {"time": datetime.now().strftime("%H:%M:%S"), "type": "denied", "message": line.split("DENIED:", 1)[-1].strip()}
        elif "[EI]" in line:
            item = {"time": datetime.now().strftime("%H:%M:%S"), "type": "exec", "message": line.split("[EI]", 1)[-1].strip()}

        if item is None:
            return

        with self.lock:
            if item["type"] == "approved":
                self.stats["allowed"] += 1
            self.intent_events.appendleft(item)

    def add_bridge_error(self, message: str):
        if not message:
            return

        with self.lock:
            self.bridge_errors.appendleft({
                "time": datetime.now().strftime("%H:%M:%S"),
                "message": message,
            })

    def snapshot(self):
        with self.lock:
            return {
                "bpf_events": list(self.bpf_events),
                "intent_events": list(self.intent_events),
                "bridge_errors": list(self.bridge_errors),
                "stats": dict(self.stats),
            }


def parse_prometheus_metrics(text: str):
    metrics = {}
    if not text:
        return metrics

    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        name, value = parts
        if name.startswith("telos_"):
            try:
                metrics[name] = float(value)
            except ValueError:
                continue
    return metrics


def token_matches(value: str, token: str):
    return hmac.compare_digest(value, token)


def cookie_token(headers):
    try:
        cookies = http.cookies.SimpleCookie(headers.get("Cookie", ""))
    except http.cookies.CookieError:
        return ""
    morsel = cookies.get("telos_dash_token")
    return morsel.value if morsel else ""


def authorized(headers, path: str, token: str = ""):
    if not token:
        return True

    auth_header = headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and token_matches(auth_header[7:], token):
        return True

    if token_matches(cookie_token(headers), token):
        return True

    parsed = urllib.parse.urlparse(path)
    query = urllib.parse.parse_qs(parsed.query)
    # SECURITY: Query token support is only for the initial browser auth cookie exchange.
    return parsed.path in ("", "/") and token_matches(query.get("token", [""])[0], token)


def has_query_token(path: str, token: str):
    if not token:
        return False
    query = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
    return token_matches(query.get("token", [""])[0], token)


def strip_token_query(path: str):
    parsed = urllib.parse.urlparse(path)
    query = urllib.parse.parse_qs(parsed.query)
    query.pop("token", None)
    clean_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=clean_query))


def auth_cookie_header(token: str):
    cookie = http.cookies.SimpleCookie()
    cookie["telos_dash_token"] = token
    cookie["telos_dash_token"]["httponly"] = True
    cookie["telos_dash_token"]["samesite"] = "Strict"
    cookie["telos_dash_token"]["path"] = "/"
    return cookie.output(header="").strip()


def redact_path(path: str):
    parsed = urllib.parse.urlparse(path)
    query = urllib.parse.parse_qs(parsed.query)
    if "token" in query:
        query["token"] = ["REDACTED"]
    clean_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=clean_query))


def is_loopback_host(host: str):
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_bind_host(host: str, token: str):
    if not token and not is_loopback_host(host):
        raise SystemExit("Refusing non-loopback dashboard bind without TELOS_DASH_TOKEN")


def stream_bpf_events(state: DashboardState, socket_path: str = EVENTS_SOCKET):
    while True:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(socket_path)
                with client.makefile("r") as stream:
                    for line in stream:
                        try:
                            state.add_bpf_event(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            time.sleep(2)
        except Exception:
            time.sleep(2)


def tail_cortex_log(state: DashboardState, log_path: str = CORTEX_LOG):
    while True:
        try:
            with open(log_path, "r") as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    state.add_intent_line(line)
        except FileNotFoundError:
            time.sleep(2)
        except PermissionError as e:
            state.add_bridge_error(f"auth error reading Cortex log: {e}")
            time.sleep(5)
        except Exception:
            time.sleep(2)


def make_handler(state: DashboardState, token: str, metrics_url: str = METRICS_URL):
    class DashboardHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=STATIC_DIR, **kwargs)

        def _send_json(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_auth_error(self):
            self._send_json(401, {"error": "unauthorized"})

        def log_message(self, format, *args):
            clean_args = tuple(redact_path(arg) if isinstance(arg, str) else arg for arg in args)
            super().log_message(format, *clean_args)

        def do_GET(self):
            if not authorized(self.headers, self.path, token):
                self._send_auth_error()
                return

            parsed = urllib.parse.urlparse(self.path)
            if token and has_query_token(self.path, token) and parsed.path in ("", "/"):
                self.send_response(302)
                self.send_header("Location", strip_token_query(self.path) or "/")
                self.send_header("Set-Cookie", auth_cookie_header(token))
                self.end_headers()
                return

            if parsed.path == "/api/snapshot":
                self._send_json(200, state.snapshot())
                return

            if parsed.path == "/api/metrics":
                try:
                    with urllib.request.urlopen(metrics_url, timeout=1.0) as response:
                        body = response.read().decode("utf-8")
                    self._send_json(200, {"metrics": parse_prometheus_metrics(body)})
                except urllib.error.URLError as e:
                    self._send_json(503, {"error": str(e), "metrics": {}})
                return

            if parsed.path == "/api/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                last_payload = None
                loops_since_last = 0
                while True:
                    payload = json.dumps(state.snapshot())
                    if payload != last_payload:
                        try:
                            self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                            self.wfile.flush()
                            last_payload = payload
                            loops_since_last = 0
                        except (BrokenPipeError, ConnectionResetError):
                            break
                    else:
                        loops_since_last += 1
                        if loops_since_last >= 15:
                            try:
                                self.wfile.write(b": keepalive\n\n")
                                self.wfile.flush()
                                loops_since_last = 0
                            except (BrokenPipeError, ConnectionResetError):
                                break
                    time.sleep(1)
                return

            return super().do_GET()

    return DashboardHandler


def main():
    parser = argparse.ArgumentParser(description="Telos Web Dashboard Bridge")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8088, help="Port to bind (default: 8088)")
    parser.add_argument("--events-socket", default=EVENTS_SOCKET, help="BPF events socket path")
    parser.add_argument("--cortex-log", default=CORTEX_LOG, help="Cortex log path")
    args = parser.parse_args()

    state = DashboardState()
    token = os.environ.get("TELOS_DASH_TOKEN", "")
    validate_bind_host(args.host, token)

    threading.Thread(target=stream_bpf_events, args=(state, args.events_socket), daemon=True).start()
    threading.Thread(target=tail_cortex_log, args=(state, args.cortex_log), daemon=True).start()

    server = ThreadingHTTPServer((args.host, args.port), make_handler(state, token))
    print(f"Telos Web Dashboard running at http://{args.host}:{args.port}")
    if token:
        print("Auth enabled via TELOS_DASH_TOKEN")
    server.serve_forever()


if __name__ == "__main__":
    main()
