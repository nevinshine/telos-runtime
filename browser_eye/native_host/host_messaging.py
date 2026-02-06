#!/usr/bin/env python3
"""
Telos Native Messaging Host

Bridges Chrome Extension (Browser Eye) to Telos Cortex via gRPC.
Uses Chrome's Native Messaging Protocol: 4-byte length prefix + JSON.

Protocol:
    Chrome → Host: {source_id, url, level, payload, findings, timestamp}
    Host → Chrome: {type: "ack", success: bool} or {type: "error", message: str}
"""

import struct
import sys
import json
import os
import logging
from typing import Optional, Dict, Any

# Add parent directories to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    import grpc
    from shared import protocol_pb2, protocol_pb2_grpc
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

# === CONFIGURATION ===

CORTEX_ADDRESS = 'localhost:50051'
LOG_FILE = '/tmp/telos_native_host.log'

# Map string levels to protobuf enum
TAINT_LEVEL_MAP = {
    'CLEAN': 0,
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4
}

# === LOGGING ===

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger('telos_native')


# === NATIVE MESSAGING PROTOCOL ===

def read_message() -> Optional[Dict[str, Any]]:
    """
    Read a message from Chrome using Native Messaging protocol.
    Format: 4-byte little-endian length prefix + JSON payload
    """
    try:
        # Read 4-byte length prefix
        raw_length = sys.stdin.buffer.read(4)
        if len(raw_length) == 0:
            log.info("Chrome closed connection (EOF)")
            return None
        if len(raw_length) != 4:
            log.error(f"Invalid length prefix: got {len(raw_length)} bytes")
            return None
        
        # Unpack as native unsigned int (little-endian on most systems)
        msg_length = struct.unpack('@I', raw_length)[0]
        
        # Sanity check
        if msg_length > 1024 * 1024:  # 1MB limit
            log.error(f"Message too large: {msg_length} bytes")
            return None
        
        # Read JSON payload
        msg_bytes = sys.stdin.buffer.read(msg_length)
        if len(msg_bytes) != msg_length:
            log.error(f"Incomplete message: expected {msg_length}, got {len(msg_bytes)}")
            return None
        
        msg = json.loads(msg_bytes.decode('utf-8'))
        log.debug(f"Received: {msg}")
        return msg
        
    except json.JSONDecodeError as e:
        log.error(f"JSON decode error: {e}")
        return None
    except Exception as e:
        log.error(f"Read error: {e}")
        return None


def send_message(msg: Dict[str, Any]) -> bool:
    """
    Send a message to Chrome using Native Messaging protocol.
    """
    try:
        encoded = json.dumps(msg).encode('utf-8')
        length = struct.pack('@I', len(encoded))
        
        sys.stdout.buffer.write(length)
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        
        log.debug(f"Sent: {msg}")
        return True
        
    except Exception as e:
        log.error(f"Send error: {e}")
        return False


# === GRPC CLIENT ===

class CortexClient:
    """gRPC client to communicate with Telos Cortex"""
    
    def __init__(self, address: str):
        self.address = address
        self.channel = None
        self.stub = None
        
    def connect(self) -> bool:
        """Establish gRPC connection"""
        if not GRPC_AVAILABLE:
            log.warning("gRPC not available - running in standalone mode")
            return False
            
        try:
            self.channel = grpc.insecure_channel(self.address)
            self.stub = protocol_pb2_grpc.TelosControlStub(self.channel)
            log.info(f"Connected to Cortex at {self.address}")
            return True
        except Exception as e:
            log.error(f"Failed to connect to Cortex: {e}")
            return False
    
    def report_taint(self, source_id: str, url: str, level: str, payload: str) -> bool:
        """Send taint report to Cortex"""
        if not self.stub:
            log.warning("Not connected to Cortex - dropping taint report")
            return False
        
        try:
            # Map level string to enum value
            level_value = TAINT_LEVEL_MAP.get(level, 0)
            
            request = protocol_pb2.TaintReport(
                source_id=source_id,
                url=url,
                level=level_value,
                payload_preview=payload[:64] if payload else ''
            )
            
            # Non-blocking: fire and forget for responsiveness
            # In production, this should be async or queued
            response = self.stub.ReportTaint(request, timeout=5.0)
            
            log.info(f"Taint reported: {level} at {url} -> {response.success}")
            return response.success
            
        except grpc.RpcError as e:
            log.error(f"gRPC error: {e.code()} - {e.details()}")
            return False
        except Exception as e:
            log.error(f"Report error: {e}")
            return False
    
    def close(self):
        """Close gRPC channel"""
        if self.channel:
            self.channel.close()
            log.info("Cortex connection closed")


# === MAIN LOOP ===

def main():
    log.info("=" * 50)
    log.info("Telos Native Host starting...")
    
    # Initialize Cortex client
    cortex = CortexClient(CORTEX_ADDRESS)
    connected = cortex.connect()
    
    if not connected:
        log.warning("Running without Cortex connection - taint reports will be logged only")
    
    # Send ready message to Chrome
    send_message({
        'type': 'ready',
        'version': '0.1.0',
        'cortex_connected': connected
    })
    
    try:
        while True:
            msg = read_message()
            
            if msg is None:
                # EOF or error - exit cleanly
                break
            
            # Process taint report
            source_id = msg.get('source_id', 'unknown')
            url = msg.get('url', 'unknown')
            level = msg.get('level', 'LOW')
            payload = msg.get('payload', '')
            
            log.info(f"Taint [{level}] from {source_id}: {url}")
            
            # Forward to Cortex if connected
            if connected:
                success = cortex.report_taint(source_id, url, level, payload)
            else:
                # Standalone mode - just log
                success = True
                log.warning(f"[STANDALONE] Would report taint: {level} at {url}")
            
            # Acknowledge to Chrome
            send_message({
                'type': 'ack',
                'success': success,
                'source_id': source_id
            })
            
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    except Exception as e:
        log.error(f"Fatal error: {e}")
        send_message({
            'type': 'error',
            'message': str(e)
        })
    finally:
        cortex.close()
        log.info("Telos Native Host exiting")


if __name__ == '__main__':
    main()
