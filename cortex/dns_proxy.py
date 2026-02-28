"""
Telos Intent-Based DNS Proxy
Intercepts agent DNS queries, verifies intent, and dynamically opens the kernel firewall.
"""

import socket
import logging
import threading
import dnslib
from dnslib import DNSRecord, QTYPE, RR, A

from cortex.domain_intel import DomainIntel

log = logging.getLogger('telos.dns')

class TelosDNSProxy:
    def __init__(self, ipc_client, host='127.0.0.1', port=5353, upstream_dns='8.8.8.8'):
        self.host = host
        self.port = port
        self.upstream_dns = upstream_dns
        self.ipc = ipc_client
        self.di = DomainIntel() # [PHASE 4.2] Initialize the SQLite scoring engine
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow port reuse just in case
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False

    def start(self):
        self.sock.bind((self.host, self.port))
        self.running = True
        thread = threading.Thread(target=self._listen, daemon=True)
        thread.start()
        log.info(f"✓ DNS Proxy listening on {self.host}:{self.port} (Upstream: {self.upstream_dns})")

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except:
            pass

    def allow_domain(self, domain: str, ttl_ms: int):
        """
        Manually pre-authorize a domain in the proxy (used by explicit DeclareIntent RPCs).
        In a full implementation, this populates an LRU cache or Redis.
        """
        log.info(f"[DNS] Authorized explicit intent for '{domain}' ({ttl_ms}ms)")

    def _listen(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(512)
                # Handle each request in a lightweight thread to prevent blocking
                threading.Thread(target=self._handle_request, args=(data, addr), daemon=True).start()
            except Exception as e:
                if self.running:
                    log.error(f"DNS listener error: {e}")

    def _handle_request(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip('.')
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
            decision, score, reason = self.di.classify(qname, "Fetch data") # Generic intent for unauthenticated DNS queries
            
            if decision == "DENY":
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
                    import struct
                    ip_int = struct.unpack("!I", packed)[0]
                    
                    # 🔥 THE DRAWBRIDGE 🔥
                    # Push the resolved IP down to the eBPF kernel map via IPC
                    success = self.ipc.add_network_rule(ip_int)
                    if success:
                        log.info(f"[DNS] 🟢 ALLOWED: '{qname}' -> {ip_str} (Firewall hole punched)")
                    else:
                        log.error(f"[DNS] ❌ IPC Failed to open firewall for {ip_str}")

            self.sock.sendto(reply.pack(), addr)

        except Exception as e:
            log.error(f"Failed to process DNS request: {e}")
