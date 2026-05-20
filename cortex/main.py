#!/usr/bin/env python3
"""
Telos Cortex - The Brain

Central gRPC server that:
1. Receives taint reports from Browser Eye (via Native Host)
2. Manages the Agent Registry (PID Bridge)
3. Pushes taint updates to the eBPF Core via Unix Socket

Usage:
    python3 cortex/main.py [--port 50051] [--socket /var/run/telos.sock]
"""

import argparse
import logging
import signal
import sys
import os
import time
import tempfile
from concurrent import futures
from typing import Dict, Optional

import grpc
import yaml
import glob  # [NEW] For resolving wildcards
import stat  # [NEW] For file stats
import threading
import socket
import struct
import tempfile


# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import protocol_pb2, protocol_pb2_grpc
from cortex.auth import CortexAuthInterceptor
from cortex.guardian import Guardian
from cortex.unix_socket import CoreIPCClient
from cortex.verifier import IntentVerifier
from cortex.dns_proxy import TelosDNSProxy
from cortex.mirage_manager import MirageManager
from cortex.config import load_config  # [NEW] Pydantic config validation

# === CONFIGURATION ===

DEFAULT_PORT = 50051
DEFAULT_BIND_HOST = '127.0.0.1'
DEFAULT_SOCKET = '/var/run/telos.sock'
MAX_WORKERS = 10
RATE_LIMIT_RPS = 5      # Max requests per second per agent PID
RATE_LIMIT_BURST = 10   # Burst capacity per PID

# Suppress noisy grpc/absl internal logs
os.environ.setdefault('GRPC_VERBOSITY', 'NONE')

# === LOGGING ===

LOG_PATH = os.getenv(
    'TELOS_CORTEX_LOG',
    os.path.join(tempfile.gettempdir(), 'telos_cortex.log')
)
os.makedirs(os.path.dirname(LOG_PATH) or '.', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_PATH)
    ]
)
log = logging.getLogger('telos.cortex')


# === RATE LIMITER (Token Bucket) ===

class _TokenBucket:
    """Per-PID token bucket rate limiter."""
    __slots__ = ('tokens', 'last_refill', 'rate', 'burst')

    def __init__(self, rate: float, burst: int):
        self.tokens = float(burst)
        self.last_refill = time.monotonic()
        self.rate = rate
        self.burst = burst

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class RateLimiter:
    """Thread-safe per-PID rate limiter with stale entry cleanup."""

    def __init__(self, rate: float = RATE_LIMIT_RPS, burst: int = RATE_LIMIT_BURST):
        self._rate = rate
        self._burst = burst
        self._buckets: Dict[int, _TokenBucket] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def allow(self, pid: int) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        with self._lock:
            now = time.monotonic()
            # Periodic cleanup of stale entries (every 60s)
            if now - self._last_cleanup > 60:
                stale = [p for p, b in self._buckets.items()
                         if now - b.last_refill > 60]
                for p in stale:
                    del self._buckets[p]
                self._last_cleanup = now

            if pid not in self._buckets:
                self._buckets[pid] = _TokenBucket(self._rate, self._burst)
            return self._buckets[pid].consume()


def _pid_exists(pid: int) -> bool:
    """Return True when *pid* refers to a live process.

    On Linux we validate via `/proc/<pid>`. On platforms without `/proc`,
    we can't reliably validate PIDs here, so we only check that the value
    is positive (this keeps unit tests portable across OSes).
    """
    if pid <= 0:
        return False
    if not os.path.isdir("/proc"):
        return True
    return os.path.isdir(f"/proc/{pid}")


def _context_abort(context: grpc.ServicerContext, code: grpc.StatusCode, message: str) -> None:
    """Abort the current RPC, with a fallback for direct unit-test contexts."""
    abort = getattr(context, "abort", None)
    if callable(abort):
        abort(code, message)
    raise ValueError(message)

# === GRPC SERVICE IMPLEMENTATION ===

class TelosControlService(protocol_pb2_grpc.TelosControlServicer):
    """
    gRPC Service implementing the TelosControl protocol.
    """
    
    def __init__(self, guardian: Guardian, ipc_client: CoreIPCClient, verifier: IntentVerifier, dns_proxy: TelosDNSProxy):
        self.guardian = guardian
        self.ipc = ipc_client
        self.verifier = verifier
        self.dns = dns_proxy # [NEW]
        self.rate_limiter = RateLimiter()
        log.info("TelosControlService initialized")

    def _validate_pid(
        self,
        pid: int,
        context: grpc.ServicerContext,
        action: str,
    ) -> None:
        """Reject policy mutations for missing, forged, or dead process IDs."""
        if not _pid_exists(pid):
            _context_abort(
                context,
                grpc.StatusCode.INVALID_ARGUMENT,
                f"{action} rejected: PID {pid} does not exist under /proc",
            )

    def _validate_session_binding(
        self,
        session_id: str,
        pid: int,
        context: grpc.ServicerContext,
    ) -> None:
        """Reject attempts to reuse a session ID for a different PID."""
        if not session_id:
            return

        mapped_pid = self.guardian.session_map.get(session_id)
        if mapped_pid is not None and mapped_pid != pid:
            _context_abort(
                context,
                grpc.StatusCode.PERMISSION_DENIED,
                f"session {session_id!r} is already bound to PID {mapped_pid}",
            )
    
    def ReportTaint(self, request: protocol_pb2.TaintReport, 
                    context: grpc.ServicerContext) -> protocol_pb2.Ack:
        """
        Handle taint reports from Browser Eye.
        
        Flow:
        1. Update internal state in Guardian
        2. Resolve which Agent PID is affected (PID Bridge)
        3. Push taint level to eBPF Core via Unix Socket
        """
        level_name = protocol_pb2.TaintLevel.Name(request.level)
        log.info(f"[!] Taint Detected: {level_name} at {request.url}")
        log.debug(f"    Source: {request.source_id}, Preview: {request.payload_preview[:32]}...")
        
        try:
            if request.pid:
                self._validate_pid(request.pid, context, "ReportTaint")

            # 1. Update Guardian state
            self.guardian.update_taint(
                request.source_id,
                request.level,
                request.url,
                request.session_id  # [NEW] Pass session ID for PID resolution
            )
            # 2. Resolve Agent PID (PID Bridge logic)
            agent_pid = self.guardian.get_agent_pid_for_view(request.source_id)
            
            if agent_pid is None:
                log.warning(f"No agent registered for source {request.source_id}")
                # Still acknowledge - taint is recorded
                return protocol_pb2.Ack(success=True, message="Taint recorded, no agent mapped")
            
            # 3. Push to Core if HIGH or above
            if request.level >= protocol_pb2.TaintLevel.HIGH:
                log.warning(f"[⚠] HIGH+ taint - pushing to Core for PID {agent_pid}")
                success = self.ipc.send_update_taint(agent_pid, request.level)
                
                if not success:
                    log.error("Failed to push taint to Core")
                    return protocol_pb2.Ack(success=False, message="Core IPC failed")
                
                return protocol_pb2.Ack(
                    success=True, 
                    message=f"Agent {agent_pid} taint updated to {level_name}"
                )
            else:
                # LOW/MEDIUM - record but don't block
                log.info(f"[~] {level_name} taint recorded, no enforcement action")
                return protocol_pb2.Ack(success=True, message="Taint recorded")
                
        except Exception as e:
            log.error(f"ReportTaint error: {e}")
            return protocol_pb2.Ack(success=False, message=str(e))
    
    def DeclareIntent(self, request: protocol_pb2.IntentRequest,
                      context: grpc.ServicerContext) -> protocol_pb2.IntentVerdict:
        """
        Handle intent declarations from Agents.
        
        For Phase 2, this is a stub. Full implementation in Phase 3.
        Currently: Allow all intents, log for audit.
        """
        log.info(f"[Intent] Agent {request.agent_pid}: {request.natural_language_goal}")

        self._validate_pid(request.agent_pid, context, "DeclareIntent")
        self._validate_session_binding(request.session_id, request.agent_pid, context)

        # Sync kernel taint state from Core before issuing a fresh policy.
        # This prevents "intent replay" where a previously-tainted PID tries to
        # redeclare a new intent and regain privileges.
        try:
            core_taint = self.ipc.get_pid_taint_level(request.agent_pid)
            if core_taint is not None:
                self.guardian.update_core_taint(request.agent_pid, core_taint)
                if core_taint >= protocol_pb2.TaintLevel.HIGH:
                    log.warning(
                        "[Intent] Denied: PID %d is tainted in kernel (%d)",
                        request.agent_pid,
                        core_taint,
                    )
                    self.ipc.send_update_exec(request.agent_pid, [], mode=1)
                    return protocol_pb2.IntentVerdict(
                        allowed=False,
                        reason=f"Agent is tainted in kernel ({core_taint}), intent rejected.",
                        policy_ttl_ms=1000,
                    )
        except Exception as e:
            # Standalone mode or Core unavailable — fall back to Guardian-only state.
            log.debug("Core taint sync skipped: %s", e)
        # Rate limit check — protect against DoS via intent flooding
        if not self.rate_limiter.allow(request.agent_pid):
            log.warning(f"⚠ Rate limited: Agent {request.agent_pid} ({RATE_LIMIT_RPS} req/s exceeded)")
            # Push a lockdown policy to ensure malicious agents can't exploit rate limits
            self.ipc.send_update_exec(request.agent_pid, [], mode=1)
            log.info(f"🚫 Exec Drawbridge locked COMPLETELY for PID {request.agent_pid} (Rate Limit Exceeded)")
            return protocol_pb2.IntentVerdict(
                allowed=False,
                reason=f"Rate limited: exceeded {RATE_LIMIT_RPS} requests/second",
                policy_ttl_ms=1000
            )

        # Verify Intent (Network + Execution gates)
        exec_actions = list(request.planned_exec_actions) if hasattr(request, 'planned_exec_actions') else []
        if exec_actions:
            log.info(f"[Intent] Exec actions: {exec_actions}")

        allowed, reason, ttl_ms, domains, allowed_bins = self.verifier.verify(
            request.agent_pid, 
            request.natural_language_goal, 
            request.planned_actions,
            exec_actions
        )

        if allowed:
            log.info(f"✅ Intent APPROVED: {reason}")
            
            # [PHASE 5: Intent-Based Execution]
            if allowed_bins:
                self.ipc.send_update_exec(request.agent_pid, allowed_bins, mode=1)
                log.info(f"🛡 Exec Drawbridge locked to: {allowed_bins}")
                
                # Schedule Cleanup Timer
                def cleanup_exec(pid=request.agent_pid):
                    self.ipc.send_clear_exec(pid)
                    log.info(f"🔓 Exec Drawbridge released for PID {pid}")
                    
                timer_exec = threading.Timer(ttl_ms / 1000.0, cleanup_exec)
                timer_exec.start()

            # [PHASE 3: Intent-Based Networking]
            import socket
            for domain in domains:
                # 1. Authorize domain in DNS Proxy (Phase 4)
                self.dns.allow_domain(domain, ttl_ms)
                
                # 2. Resolve domain to IP (Simple for Phase 3 MVP)
                try:
                    addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
                    for _, _, _, _, sockaddr in addr_info:
                        ip_str = sockaddr[0]
                        import struct
                        packed = socket.inet_aton(ip_str)
                        ip_int = struct.unpack("!I", packed)[0]
                        
                        # 3. Push to Kernel Map
                        if self.ipc.add_network_rule(ip_int):
                            log.info(f"🌐 Drawbridge lowered for {domain} ({ip_str})")
                            
                            # 4. Schedule Cleanup Timer
                            def cleanup(ip_to_remove=ip_int, domain_name=domain):
                                self.ipc.remove_network_rule(ip_to_remove)
                                log.info(f"🔒 Drawbridge raised for {domain_name}")
                                
                            timer = threading.Timer(ttl_ms / 1000.0, cleanup)
                            timer.start()
                except Exception as e:
                    log.warning(f"Failed to resolve/allow domain {domain} for IPC: {e}")
                
        else:
            log.warning(f"❌ Intent DENIED: {reason}")
            # [PHASE 5: Intent-Based Execution]
            if exec_actions:
                self.ipc.send_update_exec(request.agent_pid, [], mode=1)
                log.info(f"🚫 Exec Drawbridge locked COMPLETELY for PID {request.agent_pid}")
                
                # Release after TTL
                def cleanup_deny(pid=request.agent_pid):
                    self.ipc.send_clear_exec(pid)
                    log.info(f"🔓 Exec Drawbridge released for PID {pid}")
                    
                timer_deny = threading.Timer(10.0, cleanup_deny)  # 10s penalty box
                timer_deny.start()
        
        # Register this agent if not already known
        self.guardian.register_agent(request.agent_pid)
        
        # [NEW] Register Session ID if provided
        if request.session_id:
            self.guardian.register_session(request.session_id, request.agent_pid)
        
        return protocol_pb2.IntentVerdict(
            allowed=allowed,
            reason=reason,
            policy_ttl_ms=ttl_ms
        )
    
    def GetPolicy(self, request: protocol_pb2.PolicyQuery,
                  context: grpc.ServicerContext) -> protocol_pb2.PolicyRules:
        """
        Return current policy rules for a given PID.
        Used by daemons to sync state. Also registers the agent for tracking.
        """
        log.debug(f"[Policy] Query from PID {request.pid}")
        self._validate_pid(request.pid, context, "GetPolicy")
        
        # [NEW] Register agent for eBPF tracking
        self.guardian.register_agent(request.pid)
        self.ipc.send_register_agent(request.pid, "telos_agent")
        
        # Get current taint level for this process
        taint_level = self.guardian.get_taint_level(request.pid)
        
        # Get allowed destinations from policy
        policy = self.guardian.get_policy()
        
        return protocol_pb2.PolicyRules(
            max_allowed_taint=policy.get('max_taint', protocol_pb2.TaintLevel.MEDIUM),
            allowed_ips=policy.get('allowed_ips', []),
            allowed_paths=policy.get('allowed_paths', ['/tmp/*'])
        )


# === SERVER LIFECYCLE ===

class CortexServer:
    """
    Manages the gRPC server lifecycle and IPC connections.
    """
    
    def __init__(
        self,
        port: int,
        socket_path: str,
        policy_path: str,
        bind_host: str = DEFAULT_BIND_HOST,
        auth_token: str | None = None,
        validated_policy: dict | None = None,
    ):
        self.port = port
        self.bind_host = bind_host
        self.auth_token = auth_token
        self.socket_path = socket_path
        self.policy_path = policy_path
        self._validated_policy = validated_policy
        self.server = None
        self.guardian = None
        self.ipc = None
        self._shutdown = False
        self._heartbeat_thread = None

    def _heartbeat_loop(self):
        """
        [Phase 11] Background thread that continuously pulses the Go daemon.
        If this thread dies, the Go daemon executes its Fail-Open/Fail-Closed protocol.
        """
        log.info("Starting Cortex Heartbeat Pulse...")
        sweep_counter = 0
        while not self._shutdown:
            if self.ipc and self.ipc.connected:
                self.ipc.ping_core()
            
            # Periodically sweep dead agents to prevent memory leaks and PID collision attacks
            sweep_counter += 1
            if sweep_counter >= 10:
                sweep_counter = 0
                dead_pids = [pid for pid in list(self.guardian.agents.keys()) if not _pid_exists(pid)]
                for pid in dead_pids:
                    self.guardian.unregister_agent(pid)
                    if self.ipc and self.ipc.connected:
                        self.ipc.send_clear_exec(pid)
                        self.ipc.send_clear_taint(pid) # Also flushes from eBPF ProcessMap

            time.sleep(2.0)
        
    def start(self):
        """Start the Cortex server."""
        # ANSI
        R  = "\033[0m"
        B  = "\033[1m"
        D  = "\033[2m"
        G  = "\033[32m"
        Y  = "\033[33m"
        C  = "\033[36m"
        M  = "\033[35m"
        P  = "\033[38;5;135m"
        W  = "\033[37m"
        BG = "\033[48;5;235m"
        UP = "\033[1A"
        CLR = "\033[2K"

        def step(msg, status="working"):
            if status == "working":
                print(f"  {D}◼{R}  {msg}{D}...{R}")
            elif status == "ok":
                print(f"  {G}▶{R}  {msg}")
            elif status == "warn":
                print(f"  {Y}▲{R}  {msg}")
            elif status == "fail":
                print(f"  {P}✕{R}  {msg}")

        # Suppress log noise during boot
        root_logger = logging.getLogger()
        original_level = root_logger.level
        root_logger.setLevel(logging.CRITICAL)

        print()
        print(f"  {P}{B}cortex{R} {D}v0.5.0{R}")
        print()

        # 1. Policy
        if self._validated_policy:
            self.policy = self._validated_policy
        else:
            self.policy = self._load_policy()
        step(f"Policy loaded {D}({len(self.policy)} sections){R}", "ok")

        # 2. Guardian
        self.guardian = Guardian(self.policy)
        step("Guardian initialized", "ok")

        # 3. Verifier
        self.verifier = IntentVerifier(self.guardian)
        di_status = "DI" if self.verifier.di else ""
        ei_status = "EI" if self.verifier.ei else ""
        llm_status = "LLM" if self.verifier.llm else ""
        engines = " + ".join(filter(None, [di_status, ei_status, llm_status])) or "Heuristic"
        step(f"Intent Verifier {D}({engines}){R}", "ok")

        # 4. IPC
        self.ipc = CoreIPCClient(self.socket_path)
        connected = self.ipc.connect()
        if connected:
            step(f"Core IPC {D}({self.socket_path}){R}", "ok")
        else:
            step(f"Core IPC {D}(standalone mode){R}", "warn")

        # 5. gRPC server
        self.server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=MAX_WORKERS),
            interceptors=(CortexAuthInterceptor(self.auth_token),),
        )

        # 6. DNS Proxy
        self.dns_proxy = TelosDNSProxy(self.ipc)
        self.dns_proxy.start()
        step(f"DNS Proxy {D}(127.0.0.1:5353){R}", "ok")

        # 7. Mirage
        self.mirage = MirageManager(self.ipc, self.policy)
        self.mirage.arm_traps()
        honey_count = len(self.policy.get('mirage', {}).get('honey_files', []))
        step(f"Project Mirage {D}({honey_count} traps){R}", "ok")

        # 8. Bind service + port
        service = TelosControlService(self.guardian, self.ipc, self.verifier, self.dns_proxy)
        protocol_pb2_grpc.add_TelosControlServicer_to_server(service, self.server)

        bound = False
        for offset in range(5):
            try_port = self.port + offset
            address = f'{self.bind_host}:{try_port}'
            try:
                port_result = self.server.add_insecure_port(address)
                if port_result > 0:
                    if offset > 0:
                        self.port = try_port
                    bound = True
                    break
            except RuntimeError:
                # grpcio >= 1.64 raises RuntimeError on bind failure
                if offset < 4:
                    # Need a fresh server object since the old one is tainted
                    self.server = grpc.server(
                        futures.ThreadPoolExecutor(max_workers=MAX_WORKERS),
                        interceptors=(CortexAuthInterceptor(self.auth_token),),
                    )
                    protocol_pb2_grpc.add_TelosControlServicer_to_server(service, self.server)
                continue

        if not bound:
            step(f"Could not bind to ports {self.port}–{self.port + 4}", "fail")
            sys.exit(1)

        self.server.start()
        step(f"gRPC server {D}({self.bind_host}:{self.port}){R}", "ok")

        # 9. Heartbeat
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()
        step("Heartbeat watchdog", "ok")

        # Restore logging
        root_logger.setLevel(original_level)

        # Final summary
        print()
        print(f"  {G}{B}ready{R} in {D}~1s{R}")
        print()
        print(f"  {D}┃{R}  {B}gRPC{R}    {C}grpc://{self.bind_host}:{self.port}{R}")
        print(f"  {D}┃{R}  {B}DNS{R}     {C}udp://127.0.0.1:5353{R}")
        print(f"  {D}┃{R}  {B}IPC{R}     {C}{self.socket_path}{R}")
        print(f"  {D}┃{R}  {B}Mode{R}    {P}{engines}{R}")
        print()
        
        # [REMOVED] _wait_for_termination call from here
        
    def _load_policy(self) -> dict:
        """Fallback policy loader (used when Pydantic validation is bypassed)."""
        try:
            with open(self.policy_path, 'r') as f:
                policy = yaml.safe_load(f) or {}
                log.info(f"✓ Loaded policy from {self.policy_path}")
                return policy
        except FileNotFoundError:
            log.warning(f"⚠ Policy file not found: {self.policy_path}, using defaults")
            return {}
        except Exception as e:
            log.error(f"Failed to load policy: {e}")
            return {}
    
    def wait_for_termination(self): # [NEW] Public method for waiting
        """Block until shutdown signal received."""
        try:
            while not self._shutdown:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def stop(self):
        """Gracefully stop the server."""
        log.info("Shutting down Cortex...")
        
        if hasattr(self, 'dns_proxy'):
            self.dns_proxy.stop()
            log.info("✓ DNS Proxy stopped")
        
        if self.server:
            self.server.stop(grace=5)
            log.info("✓ gRPC server stopped")
        
        if self.ipc:
            self.ipc.close()
            log.info("✓ IPC connection closed")
        
        log.info("TELOS CORTEX offline")
    
    def signal_handler(self, signum, frame):
        """Handle termination signals."""
        log.info(f"Received signal {signum}")
        self._shutdown = True

# [NEW FUNCTION]
def sync_filesystem_policy(config: dict, ipc: CoreIPCClient):
    """
    Resolve configured sensitive paths to inodes and push to Core.
    """
    fs_policy = config.get('filesystem', {})
    sensitive_patterns = fs_policy.get('sensitive_paths', [])
    
    count = 0
    for pattern in sensitive_patterns:
        # Resolve wildcards
        for filepath in glob.glob(pattern, recursive=True):
            try:
                # specific check for shadow/passwd to mark as critical?
                # For now, everything in sensitive_paths is CRITICAL (2)
                sensitivity = 2
                
                # Get inode
                st = os.stat(filepath)
                if stat.S_ISREG(st.st_mode): # Only regular files
                    inode = st.st_ino
                    
                    # Push to Core
                    if ipc.update_inode(inode, sensitivity):
                        count += 1
                        log.debug(f"Protected {filepath} (inode {inode})")
            except Exception as e:
                log.warning(f"Failed to protect {filepath}: {e}")
                
    log.info(f"✓ Protected {count} sensitive inodes")

# [NEW FUNCTION]
def sync_network_policy(config: dict, ipc: CoreIPCClient):
    """
    Push allowed network destinations (IPs) to Core.
    """
    net_policy = config.get('network', {})
    allowed_hosts = net_policy.get('always_allowed', [])
    
    # Also resolve blocked hosts? No, our policy is "Deny All except Allowed"
    # So we only need to push the allowlist.
    
    count = 0
    import socket
    
    for host in allowed_hosts:
        try:
            # Resolve hostname to IPv4
            # Note: This is a simple resolver. Production would need to handle
            # multiple IPs per host, DNS rotation, and IPv6.
            # Ideally, the agent would use a DNS proxy or update this dynamically.
            # For M2 POC, we resolve once at startup.
            addr_info = socket.getaddrinfo(host, None, socket.AF_INET)
            
            for _, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0] # e.g. "127.0.0.1"
                
                # Convert to uint32 (network byte order? typically host byte order for BPF maps usually)
                # BPF usually expects network byte order if dealing with SKB, but we are using socket structs.
                # Let's check bpf_lsm.c: dest_ip = addr->sin_addr.s_addr;
                # sin_addr.s_addr is Network Byte Order (Big Endian).
                # So we must push Network Byte Order.
                
                packed = socket.inet_aton(ip_str)
                # unpack as Big Endian uint32
                import struct
                ip_int = struct.unpack("!I", packed)[0]
                
                if ipc.update_network(ip_int, 1): # 1 = Allowed
                    count += 1
                    log.debug(f"Allowed {host} -> {ip_str} ({ip_int})")

        except Exception as e:
            log.warning(f"Failed to resolve/allow {host}: {e}")
            
    log.info(f"✓ Allowed {count} network destinations")


# === MAIN ===

def main():
    parser = argparse.ArgumentParser(description='Telos Cortex - Central Control Server')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'gRPC server port (default: {DEFAULT_PORT})')
    parser.add_argument('--bind-host', type=str,
                        default=os.getenv('TELOS_CORTEX_BIND_HOST', DEFAULT_BIND_HOST),
                        help=f'gRPC bind host (default: {DEFAULT_BIND_HOST})')
    parser.add_argument('--auth-token', type=str,
                        default=os.getenv('TELOS_CORTEX_AUTH_TOKEN'),
                        help='Cortex gRPC auth token (or set TELOS_CORTEX_AUTH_TOKEN)')
    parser.add_argument('--socket', type=str, default=DEFAULT_SOCKET,
                        help=f'Unix socket path for Core IPC (default: {DEFAULT_SOCKET})')
    parser.add_argument('--policy', type=str, 
                        default=os.path.join(os.path.dirname(__file__), 'policy.yaml'),
                        help='Path to policy YAML file')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # [NEW] Validate all configuration before starting (fail-fast)
    settings, validated_policy = load_config(args)

    # Create and run server
    server = CortexServer(
        settings.port,
        settings.socket_path,
        args.policy,
        bind_host=settings.bind_host,
        auth_token=settings.auth_token,
        validated_policy=validated_policy.model_dump(),
    )
    
    # Register signal handlers
    signal.signal(signal.SIGINT, server.signal_handler)
    signal.signal(signal.SIGTERM, server.signal_handler)
    
    server.start()
    
    # Suppress sync noise
    root_logger = logging.getLogger()
    sync_level = root_logger.level
    root_logger.setLevel(logging.CRITICAL)

    # Sync policies silently
    sync_filesystem_policy(server.policy, server.ipc) 
    sync_network_policy(server.policy, server.ipc)

    # Restore logging for runtime
    root_logger.setLevel(sync_level)

    server.wait_for_termination()


if __name__ == '__main__':
    main()
