"""
Telos Intent-Based DNS Proxy
Intercepts agent DNS queries, verifies intent, and dynamically opens the kernel firewall.
"""

import socket
import logging
import struct
import threading
import time
import concurrent.futures
import dnslib
from dnslib import DNSRecord, QTYPE, RR, A

from cortex.domain_intel import DomainIntel

log = logging.getLogger('telos.dns')

# TTL bounds for DNS-authorized firewall holes
TTL_MIN = 60
TTL_MAX = 3600
MAX_PENDING_CLEANUPS = 10000
CLEANUP_SLEEP_MAX = 1.0

class TelosDNSProxy:
    def __init__(self, ipc_client, host='127.0.0.1', port=5353, upstream_dns='8.8.8.8', max_workers=20):
        self.host = host
        self.port = port
        self.upstream_dns = upstream_dns
        self.ipc = ipc_client
        self.di = DomainIntel() # [PHASE 4.2] Initialize the SQLite scoring engine
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow port reuse just in case
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self._allowed_domains = {}
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        
        # Cleanup queue and refcounting
        self._pending_cleanups = {}
        self._cleanup_lock = threading.Lock()
        self._cleanup_event = threading.Event()
        self._stop_event = threading.Event()
        
        self._ip_refcount = {}
        self._ip_refcount_lock = threading.Lock()
        
        self._cleanup_worker = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name='dns_cleanup_worker',
        )
        self._cleanup_worker.start()

    def start(self):
        self.sock.bind((self.host, self.port))
        self.running = True
        thread = threading.Thread(target=self._listen, daemon=True)
        thread.start()
        log.info(f"✓ DNS Proxy listening on {self.host}:{self.port} (Upstream: {self.upstream_dns})")

    def stop(self):
        self.running = False
        self._stop_event.set()
        self._cleanup_event.set()
        try:
            if self._cleanup_worker.is_alive():
                self._cleanup_worker.join(timeout=2.0)
        except Exception as e:
            log.debug(f"Cleanup worker join failed: {e}")
            
        with self._cleanup_lock:
            self._pending_cleanups.clear()
        with self._ip_refcount_lock:
            self._ip_refcount.clear()
            
        try:
            self.executor.shutdown(wait=False)
            self.sock.close()
        except Exception as e:
            log.debug(f"Cleanup during stop: {e}")

    def allow_domain(self, domain: str, ttl_ms: int):
        """
        Manually pre-authorize a domain in the proxy (used by explicit DeclareIntent RPCs).
        """
        expiry = time.time() + (ttl_ms / 1000.0)
        self._allowed_domains[domain] = expiry
        log.info(f"[DNS] Authorized explicit intent for '{domain}' ({ttl_ms}ms)")

    def _normalize_ttl(self, ttl_seconds, ip_int=None, domain=None):
        ttl = int(ttl_seconds) if isinstance(ttl_seconds, (int, float)) else 0
        if ttl <= 0:
            ttl = TTL_MIN
        if ttl < TTL_MIN:
            log.debug(f"[DNS] TTL below minimum: requested={ttl_seconds}s, normalized={TTL_MIN}s for IP={ip_int} domain={domain}")
            ttl = TTL_MIN
        if ttl > TTL_MAX:
            log.warning(f"[DNS] TTL capped: requested={ttl_seconds}s, capped={TTL_MAX}s for IP={ip_int} domain={domain}")
            ttl = TTL_MAX
        return ttl

    def _acquire_ip(self, ip_int, auth_id, ttl_seconds):
        """Increment refcount; return True if this is the first active auth for this IP."""
        with self._ip_refcount_lock:
            entry = self._ip_refcount.get(ip_int)
            if entry is None:
                entry = {
                    'auth_ids': set(),
                    'max_expiry_ts': 0.0,
                }
                self._ip_refcount[ip_int] = entry
            
            is_first = len(entry['auth_ids']) == 0
            if auth_id not in entry['auth_ids']:
                entry['auth_ids'].add(auth_id)
                log.debug(f"[DNS] IP {ip_int}: acquired by auth_id={auth_id}, refcount={len(entry['auth_ids'])}")
            else:
                log.debug(f"[DNS] IP {ip_int}: auth_id={auth_id} already active, refcount={len(entry['auth_ids'])}")
            
            entry['max_expiry_ts'] = max(entry['max_expiry_ts'], time.time() + ttl_seconds)
            return is_first

    def _release_ip(self, ip_int, auth_id):
        """Decrement refcount; return True if this was the last active auth for this IP."""
        with self._ip_refcount_lock:
            entry = self._ip_refcount.get(ip_int)
            if entry is None:
                log.warning(f"[DNS] IP {ip_int}: release without acquire (auth_id={auth_id})")
                return False
                
            entry['auth_ids'].discard(auth_id)
            if entry['auth_ids']:
                pending = [exp for (ip, aid), exp in self._pending_cleanups.items() if ip == ip_int and aid in entry['auth_ids']]
                entry['max_expiry_ts'] = max(pending) if pending else 0.0
                log.debug(f"[DNS] IP {ip_int}: released auth_id={auth_id}, refcount={len(entry['auth_ids'])}, next_expiry={entry['max_expiry_ts']:.1f}")
                return False
                
            del self._ip_refcount[ip_int]
            log.debug(f"[DNS] IP {ip_int}: last auth_id={auth_id} released, refcount=0")
            return True

    def _active_domains_for_ip(self, ip_int):
        with self._ip_refcount_lock:
            entry = self._ip_refcount.get(ip_int)
            return sorted(entry['auth_ids']) if entry else []

    def _schedule_drawbridge_cleanup(self, ip_int, ip_str, domain, ttl_seconds):
        """Queue cleanup for a resolved IP instead of creating one timer per request."""
        ttl_seconds = self._normalize_ttl(ttl_seconds, ip_int=ip_int, domain=domain)
        auth_id = domain.lower()
        expiry = time.time() + ttl_seconds
        key = (ip_int, auth_id)
        
        with self._cleanup_lock:
            if len(self._pending_cleanups) >= MAX_PENDING_CLEANUPS and key not in self._pending_cleanups:
                log.error(f"[DNS] Cleanup queue full ({len(self._pending_cleanups)} pending), dropping cleanup for IP={ip_int} domain={domain}")
                return
            
            old_expiry = self._pending_cleanups.get(key)
            if old_expiry is None:
                self._pending_cleanups[key] = expiry
                log.debug(f"[DNS] Scheduled cleanup for IP={ip_int} domain={domain} expiry={expiry:.0f}")
            elif expiry > old_expiry:
                self._pending_cleanups[key] = expiry
                log.debug(f"[DNS] Extended cleanup for IP={ip_int} domain={domain} {old_expiry:.0f}→{expiry:.0f}")
            else:
                log.debug(f"[DNS] Cleanup unchanged for IP={ip_int} domain={domain} existing={old_expiry:.0f} new={expiry:.0f}")
                
        self._acquire_ip(ip_int, auth_id, ttl_seconds)
        self._cleanup_event.set()

    def _cleanup_loop(self):
        """Single background worker that expires pending cleanup entries."""
        while not self._stop_event.is_set():
            now = time.time()
            expired = []
            with self._cleanup_lock:
                expired = [key for key, exp in self._pending_cleanups.items() if exp <= now]
                for key in expired:
                    del self._pending_cleanups[key]
                next_expiry = min(self._pending_cleanups.values()) if self._pending_cleanups else None
                
            for ip_int, auth_id in expired:
                if self._release_ip(ip_int, auth_id):
                    active_domains = self._active_domains_for_ip(ip_int)
                    log.info(f"[DNS] IP {ip_int}: rule removed after expiry for auth_id={auth_id}")
                    try:
                        self.ipc.remove_network_rule(ip_int)
                    except Exception as e:
                        log.error(f"[DNS] Failed to remove expired rule for IP {ip_int}: {e}")
                else:
                    active_domains = self._active_domains_for_ip(ip_int)
                    log.debug(f"[DNS] IP {ip_int}: cleanup deferred, active domains={active_domains}")
                    
            wait_secs = CLEANUP_SLEEP_MAX
            if next_expiry is not None:
                wait_secs = max(0.1, min(CLEANUP_SLEEP_MAX, next_expiry - time.time()))
                
            self._cleanup_event.wait(timeout=wait_secs)
            self._cleanup_event.clear()

    def _listen(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(512)
                # Handle request using bounded thread pool
                self.executor.submit(self._handle_request, data, addr)
            except Exception as e:
                if self.running:
                    log.error(f"DNS listener error: {e}")

    def _handle_request(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip('.').lower()
            qtype = QTYPE[request.q.qtype]
            
            log.debug(f"[DNS] Intercepted query: {qname} ({qtype})")

            # Ignore IPv6 AAAA records entirely since we blackholed AF_INET6
            if qtype == 'AAAA':
                reply = request.reply()
                self.sock.sendto(reply.pack(), addr)
                return

            # =======================================================
            # PHASE 4.2 - Domain Intelligence Engine Integration
            # =======================================================
            if qname in self._allowed_domains and time.time() < self._allowed_domains[qname]:
                decision = "ALLOW"
                log.debug(f"[DNS] '{qname}' allowed via Intent pre-authorization")
            else:
                if qname in self._allowed_domains:
                    del self._allowed_domains[qname] # Cleanup expired
                decision, score, reason = self.di.classify(qname, "Fetch data")
            
            if decision == "DENY" or decision == "ESCALATE":
                if decision == "ESCALATE":
                    log.warning(f"[DNS] ⚠️ ESCALATED: '{qname}' denied by default at DNS layer (Score: {score}). Reason: {reason}")
                else:
                    log.warning(f"[DNS] 🚫 DENIED: '{qname}' blocked by Intelligence Engine (Score: {score}). Reason: {reason}")
                
                # =======================================================
                # PHASE 13 - Bridging Telos with Hyperion XDP
                # =======================================================
                try:
                    # Resolve the malicious domain to get underneath IPs
                    bad_response = request.send(self.upstream_dns, 53, tcp=False)
                    bad_parsed = DNSRecord.parse(bad_response)
                    import urllib.request
                    import json
                    for rr in bad_parsed.rr:
                        if rr.rtype == QTYPE.A:
                            malicious_ip = str(rr.rdata)
                            req = urllib.request.Request(
                                "http://127.0.0.1:9095/block", 
                                data=json.dumps({"ip": malicious_ip}).encode('utf-8'), 
                                headers={'Content-Type': 'application/json'}, 
                                method='POST'
                            )
                            try:
                                urllib.request.urlopen(req, timeout=1.0)
                                log.info(f"[DNS] ⚡ Pushed malicious IP {malicious_ip} ({qname}) to Hyperion XDP")
                            except Exception as e:
                                log.error(f"[DNS] ⚠️ Failed to reach Hyperion RPC: {e}")
                except Exception as e:
                    log.error(f"[DNS] ⚠️ Failed to extract malicious IPs: {e}")

                reply = request.reply()
                # Return NXDOMAIN (Non-Existent Domain) to instantly kill the agent's connection
                reply.header.rcode = getattr(dnslib.RCODE, 'NXDOMAIN', 3) 
                self.sock.sendto(reply.pack(), addr)
                return

            # Forward to upstream DNS to get the actual IPs
            upstream_response = request.send(self.upstream_dns, 53, tcp=False)
            reply = DNSRecord.parse(upstream_response)

            resolved_ips = []
            for rr in reply.rr:
                if rr.rtype == QTYPE.A:
                    ip_str = str(rr.rdata)
                    resolved_ips.append(ip_str)
                    
                    # Convert IP string to 32-bit integer formatted for eBPF
                    packed = socket.inet_aton(ip_str)
                    ip_int = struct.unpack("!I", packed)[0]
                    
                    # Use DNS record TTL for drawbridge lifetime (default 60s)
                    ttl_seconds = rr.ttl if rr.ttl > 0 else 60

                    # 🔥 THE DRAWBRIDGE 🔥
                    # Push the resolved IP down to the eBPF kernel map via IPC
                    success = self.ipc.add_network_rule(ip_int)
                    if success:
                        log.info(f"[DNS] 🟢 ALLOWED: '{qname}' -> {ip_str} (Firewall hole punched, TTL: {ttl_seconds}s)")
                        self._schedule_drawbridge_cleanup(ip_int, ip_str, qname, ttl_seconds)
                    else:
                        log.error(f"[DNS] ❌ IPC Failed to open firewall for {ip_str}")

            self.sock.sendto(reply.pack(), addr)

        except Exception as e:
            log.error(f"Failed to process DNS request: {e}")
