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
from concurrent import futures
from typing import Dict, Optional

import grpc
import yaml

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import protocol_pb2, protocol_pb2_grpc
from cortex.guardian import Guardian
from cortex.unix_socket import CoreIPCClient

# === CONFIGURATION ===

DEFAULT_PORT = 50051
DEFAULT_SOCKET = '/var/run/telos.sock'
MAX_WORKERS = 10

# === LOGGING ===

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/telos_cortex.log')
    ]
)
log = logging.getLogger('telos.cortex')

# === GRPC SERVICE IMPLEMENTATION ===

class TelosControlService(protocol_pb2_grpc.TelosControlServicer):
    """
    gRPC Service implementing the TelosControl protocol.
    """
    
    def __init__(self, guardian: Guardian, ipc_client: CoreIPCClient):
        self.guardian = guardian
        self.ipc = ipc_client
        log.info("TelosControlService initialized")
    
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
            # 1. Update Guardian state
            self.guardian.update_taint(request.source_id, request.level, request.url)
            
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
        log.debug(f"    Planned actions: {request.planned_actions}")
        
        # Phase 2: Stub - allow all
        # Phase 3: Will integrate with Guardian for actual verification
        
        # Register this agent if not already known
        self.guardian.register_agent(request.agent_pid)
        
        return protocol_pb2.IntentVerdict(
            allowed=True,
            reason="Intent noted (enforcement pending Phase 3)",
            policy_ttl_ms=60000  # 1 minute
        )
    
    def GetPolicy(self, request: protocol_pb2.PolicyQuery,
                  context: grpc.ServicerContext) -> protocol_pb2.PolicyRules:
        """
        Return current policy rules for a given PID.
        Used by daemons to sync state.
        """
        log.debug(f"[Policy] Query from PID {request.pid}")
        
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
    
    def __init__(self, port: int, socket_path: str, policy_path: str):
        self.port = port
        self.socket_path = socket_path
        self.policy_path = policy_path
        self.server = None
        self.guardian = None
        self.ipc = None
        self._shutdown = False
        
    def start(self):
        """Start the Cortex server."""
        # ANSI color codes
        RESET = "\033[0m"
        BOLD = "\033[1m"
        GREEN = "\033[32m"
        CYAN = "\033[36m"
        MAGENTA = "\033[35m"
        PURPLE = "\033[38;5;135m"
        
        # Print colorful banner
        print()
        print(f"{PURPLE}   ██████╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗{RESET}")
        print(f"{PURPLE}  ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝{RESET}")
        print(f"{PURPLE}  ██║     ██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝ {RESET}")
        print(f"{PURPLE}  ██║     ██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗ {RESET}")
        print(f"{PURPLE}  ╚██████╗╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗{RESET}")
        print(f"{PURPLE}   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{RESET}")
        print()
        print(f"{CYAN}            ╔═══════════════════════════════╗{RESET}")
        print(f"{CYAN}            ║{BOLD}       AI SECURITY BRAIN       {RESET}{CYAN}║{RESET}")
        print(f"{CYAN}            ╚═══════════════════════════════╝{RESET}")
        print()
        
        log.info("Initializing...")
        
        # Load policy configuration
        policy = self._load_policy()
        
        # Initialize Guardian
        self.guardian = Guardian(policy)
        log.info("✓ Guardian initialized")
        
        # Initialize IPC to Core
        self.ipc = CoreIPCClient(self.socket_path)
        connected = self.ipc.connect()
        if connected:
            log.info(f"✓ Connected to Core at {self.socket_path}")
        else:
            log.warning(f"⚠ Core not available at {self.socket_path} - running standalone")
        
        # Create gRPC server
        self.server = grpc.server(futures.ThreadPoolExecutor(max_workers=MAX_WORKERS))
        
        # Register service
        service = TelosControlService(self.guardian, self.ipc)
        protocol_pb2_grpc.add_TelosControlServicer_to_server(service, self.server)
        
        # Bind to port
        address = f'[::]:{self.port}'
        self.server.add_insecure_port(address)
        
        # Start
        self.server.start()
        log.info(f"✓ gRPC server listening on port {self.port}")
        
        print()
        print(f"{GREEN}  ╔═══════════════════════════════════════════════════════╗{RESET}")
        print(f"{GREEN}  ║{BOLD}               CORTEX ONLINE - Awaiting Input          {RESET}{GREEN}║{RESET}")
        print(f"{GREEN}  ╚═══════════════════════════════════════════════════════╝{RESET}")
        print()
        
        # Wait for shutdown
        self._wait_for_termination()
        
    def _load_policy(self) -> dict:
        """Load policy configuration from YAML."""
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
    
    def _wait_for_termination(self):
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


# === MAIN ===

def main():
    parser = argparse.ArgumentParser(description='Telos Cortex - Central Control Server')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'gRPC server port (default: {DEFAULT_PORT})')
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
    
    # Create and run server
    server = CortexServer(args.port, args.socket, args.policy)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, server.signal_handler)
    signal.signal(signal.SIGTERM, server.signal_handler)
    
    server.start()


if __name__ == '__main__':
    main()
