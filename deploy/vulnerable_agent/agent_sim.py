#!/usr/bin/env python3
"""
Vulnerable Agent Simulation

Simulates an AI Agent that:
1. Connects to Telos Cortex to declare intent.
2. Generates a Session ID for browser correlation.
3. Enters a loop simulating tool execution (Shell).
4. Can be "attacked" by verifying if Telos blocks its actions when tainted.

Usage:
    python3 agent_sim.py [--cortex localhost:50051]
"""

import argparse
import grpc
import logging
import os
import sys
import time
import uuid
import socket
import subprocess

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared import protocol_pb2, protocol_pb2_grpc

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] Agent: %(message)s'
)
log = logging.getLogger('agent')

class AgentSimulator:
    def __init__(self, cortex_address):
        self.cortex_address = cortex_address
        self.pid = os.getpid()
        self.session_id = str(uuid.uuid4())
        self.channel = None
        self.stub = None

    def connect(self):
        """Connect to Cortex gRPC."""
        try:
            self.channel = grpc.insecure_channel(self.cortex_address)
            self.stub = protocol_pb2_grpc.TelosControlStub(self.channel)
            log.info(f"Connected to Cortex at {self.cortex_address}")
        except Exception as e:
            log.error(f"Failed to connect to Cortex: {e}")
            sys.exit(1)

    def declare_intent(self, goal, actions):
        """Register with Cortex and get Policy."""
        log.info(f"Declaring intent for PID {self.pid} Session {self.session_id[:8]}...")
        log.info(f"Goal: {goal}")
        log.info(f"Actions: {actions}")
        
        req = protocol_pb2.IntentRequest(
            agent_pid=self.pid,
            natural_language_goal=goal,
            planned_actions=actions,
            session_id=self.session_id
        )
        
        try:
            verdict = self.stub.DeclareIntent(req)
            if verdict.allowed:
                log.info("Intent APPROVED by Cortex.")
                return True
            else:
                log.warning(f"Intent DENIED: {verdict.reason}")
                return False
        except grpc.RpcError as e:
            log.error(f"RPC Failed: {e}")
            return False

    def run_shell_loop(self, single_cmd=None):
        """Simulate an agent execution loop."""
        if single_cmd:
            print(f"Executing single command: {single_cmd}")
            self._exec(single_cmd)
            return

        print("\n=== AGENT SIMULATOR RUNNING ===")
        # ... (rest of interactive loop) ...
        # But I need to extract _exec method or duplicate logic?
        # Let's refactor slightly to keep it clean.
        print(f"PID: {self.pid}")
        # ...
        while True:
            try:
                cmd = input(f"\n[{self.pid}] agent> ").strip()
                if not cmd: continue
                if cmd == 'exit': break
                self._exec(cmd)
            except (EOFError, KeyboardInterrupt):
                break

    def _exec(self, cmd):
        if "curl" in cmd and "attacker" in cmd:
             log.warning("⚠️  Executing POTENTIALLY MALICIOUS command...")
        
        start = time.time()
        try:
            # We use subprocess.run, which uses fork+execve
            # This should trigger the BPF hook (check_exec/check_connect)
            # check_connect requires the process to actually make a socket call.
            # curl does that.
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                print(f"✅ Success:\n{result.stdout}")
            else:
                print(f"❌ Failed (Return Code {result.returncode}):")
                print(f"Stdout: {result.stdout}")
                print(f"Stderr: {result.stderr}")
                
                if "Operation not permitted" in result.stderr:
                    print("🔒 BLOCKED BY TELOS RUNTIME")
                    
        except Exception as e:
            print(f"Error executing: {e}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cortex', default='localhost:50051', help='Cortex gRPC address')
    parser.add_argument('--goal', default="I am a helpful assistant simulating a vulnerability.", help='Natural language goal')
    parser.add_argument('--actions', nargs='+', default=["exec:ls"], help='List of planned actions')
    parser.add_argument('--no-intent', action='store_true', help='Skip intent declaration')
    parser.add_argument('--exec', dest='exec_cmd', help='Execute single command and exit')
    args = parser.parse_args()
    
    sim = AgentSimulator(args.cortex)
    sim.connect()
    
    if not args.no_intent:
        sim.declare_intent(args.goal, args.actions)
    
    sim.run_shell_loop(args.exec_cmd)

if __name__ == '__main__':
    main()
