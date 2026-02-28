#!/bin/bash
# Verify PID Mapping Fix

# Kill any existing processes
pkill -f "cortex/main.py"
pkill -f "agent_sim.py"

echo "Starting Cortex..."
nohup python3 cortex/main.py > /tmp/cortex.log 2>&1 &
CORTEX_PID=$!
sleep 2

echo "Starting Agent Simulation..."
# Run in background
nohup python3 deploy/vulnerable_agent/agent_sim.py > /tmp/agent.log 2>&1 &
AGENT_PID=$!
sleep 2

# Extract Session ID
SESSION_ID=$(grep "Session ID:" /tmp/agent.log | head -n 1 | awk '{print $3}')
AGENT_REAL_PID=$(grep "PID:" /tmp/agent.log | head -n 1 | awk '{print $2}')

if [ -z "$SESSION_ID" ]; then
    echo "FAILED to get Session ID from agent logs."
    cat /tmp/agent.log
    kill $CORTEX_PID $AGENT_PID
    exit 1
fi

echo "Found Session ID: $SESSION_ID (Agent PID: $AGENT_REAL_PID)"

echo "Triggering Attack..."
python3 deploy/vulnerable_agent/attack_sim.py --session "$SESSION_ID" --level HIGH

sleep 1

echo "Checking Cortex Logs for mapping..."
if grep -q "Session mapped: ${SESSION_ID:0:8}" /tmp/cortex.log; then
    echo "✓ SUCCESS: Session mapped correctly."
else
    echo "❌ FAILURE: Session mapping not found in Cortex logs."
    cat /tmp/cortex.log
    kill $CORTEX_PID $AGENT_PID
    exit 1
fi

if grep -q "Agent ${AGENT_REAL_PID} taint escalated to" /tmp/cortex.log; then
    echo "✓ SUCCESS: Agent taint escalated."
else
    echo "❌ FAILURE: Agent taint escalation not found in Cortex logs."
    cat /tmp/cortex.log
    kill $CORTEX_PID $AGENT_PID
    exit 1
fi

# Cleanup
kill $CORTEX_PID $AGENT_PID
echo "PID Verification Complete."
