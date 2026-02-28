#!/usr/bin/env python3
"""
Attack Simulator (Fake Browser)

Simulates the Browser Extension reporting a tainting event.
Used to verify that Cortex correctly maps the session ID to the Agent PID.

Usage:
    python3 attack_sim.py --session <SESSION_ID> [--level CRITICAL]
"""

import argparse
import grpc
import logging
import os
import sys

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared import protocol_pb2, protocol_pb2_grpc

logging.basicConfig(level=logging.INFO)
log = logging.getLogger('attacker')

def report_taint(server_addr, session_id, level_str):
    channel = grpc.insecure_channel(server_addr)
    stub = protocol_pb2_grpc.TelosControlStub(channel)
    
    level_map = {
        'CLEAN': protocol_pb2.TaintLevel.CLEAN,
        'LOW': protocol_pb2.TaintLevel.LOW,
        'MEDIUM': protocol_pb2.TaintLevel.MEDIUM,
        'HIGH': protocol_pb2.TaintLevel.HIGH,
        'CRITICAL': protocol_pb2.TaintLevel.CRITICAL,
    }
    level = level_map.get(level_str.upper(), protocol_pb2.TaintLevel.HIGH)

    log.info(f"Reporting taint {level_str} for session {session_id} to {server_addr}")
    
    req = protocol_pb2.TaintReport(
        source_id="fake_browser_tab_1",
        pid=1234, # Fake browser PID
        url="http://attacker.com/exploit.html",
        level=level,
        payload_preview="Ignore previous instructions...",
        session_id=session_id
    )
    
    try:
        ack = stub.ReportTaint(req)
        if ack.success:
            log.info(f"Success: {ack.message}")
        else:
            log.error(f"Failed: {ack.message}")
    except grpc.RpcError as e:
        log.error(f"RPC Error: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--session', required=True, help='Session ID from agent_sim.py')
    parser.add_argument('--level', default='HIGH', help='Taint level (LOW, MEDIUM, HIGH, CRITICAL)')
    parser.add_argument('--cortex', default='localhost:50051', help='Cortex gRPC address')
    args = parser.parse_args()
    
    report_taint(args.cortex, args.session, args.level)
