#!/bin/bash
# Verify Map Cleanup under Stress (Issue #129)

if ! command -v bpftool &> /dev/null; then
    echo "❌ bpftool not found."
    exit 1
fi

# Cleanup previous runs
pkill -f "telos_daemon" || true
pkill -f "cortex/main.py" || true
rm -f /tmp/cortex_stress.log /tmp/telos_daemon_stress.log

echo "Starting Telos Daemon..."
nohup ./bin/telos_daemon > /tmp/telos_daemon_stress.log 2>&1 &
DAEMON_PID=$!
sleep 2

echo "Starting Cortex..."
nohup python3 cortex/main.py > /tmp/cortex_stress.log 2>&1 &
CORTEX_PID=$!
sleep 2

MAP_ID=$(bpftool map show | grep network_map | awk '{print $1}' | tr -d ':')
if [ -z "$MAP_ID" ]; then
    echo "❌ Failed to find network_map."
    kill $CORTEX_PID
    kill $DAEMON_PID
    exit 1
fi

INITIAL_COUNT=$(bpftool map dump id $MAP_ID | grep "key:" | wc -l)
echo "Initial Map Entries: $INITIAL_COUNT"

echo "Running Stress Add/Remove..."
python3 -c "
from cortex.unix_socket import CoreIPCClient
import time
c = CoreIPCClient()
c.connect()
for i in range(100):
    # Simulate adding and removing 100 random IPs
    ip = 16843009 + i
    c.add_network_rule(ip)
    c.remove_network_rule(ip)
"

sleep 1
FINAL_COUNT=$(bpftool map dump id $MAP_ID | grep "key:" | wc -l)
echo "Final Map Entries: $FINAL_COUNT"

kill $CORTEX_PID
kill $DAEMON_PID

if [ "$FINAL_COUNT" -gt "$((INITIAL_COUNT + 10))" ]; then
    echo "❌ Map size exploded during stress test (leak detected)."
    exit 1
fi

echo "✅ Map Cleanup Stress Test Passed."
