#!/bin/bash
# Verify Phase 3: Intent-Based Networking

# Cleanup
pkill -f "cortex/main.py"
pkill -f "agent_sim.py"
rm -f /tmp/cortex_p3.log /tmp/agent_p3.log

echo "Starting Cortex..."
nohup python3 cortex/main.py > /tmp/cortex_p3.log 2>&1 &
CORTEX_PID=$!
sleep 3

echo "--- Test 1: Block by Default (Strict Mode) ---"
# Agent tries to curl without declaring intent.
# We expect EPERM or connection blocked.
# We use google.com
python3 deploy/vulnerable_agent/agent_sim.py --no-intent --exec "curl -v 1.1.1.1" > /tmp/agent_block.log 2>&1

if grep -q "Operation not permitted" /tmp/agent_block.log || grep -q "BLOCKED BY TELOS" /tmp/agent_block.log; then
    echo "✅ Test 1 Passed: strict blocking works."
else
    # It might also fail with "connect: permission denied" depending on curl version
    if grep -q "Permission denied" /tmp/agent_block.log; then
         echo "✅ Test 1 Passed: Permission denied detected."
    else
         echo "❌ Test 1 Failed: Traffic not blocked?"
         cat /tmp/agent_block.log
    fi
fi

echo "--- Test 2: Verified Allow (Search Google) ---"
# Goal: "search for info" -> Keyword "search" -> Allow "google.com"
# Action: "curl google.com"
# Note: google.com resolves to multiple IPs. agent_sim.py will declare intent, 
# Cortex will resolve and add IPs. Then agent executes curl.
python3 deploy/vulnerable_agent/agent_sim.py \
    --goal "I want to search for info" \
    --actions "curl google.com" \
    --exec "curl -I google.com" > /tmp/agent_allow.log 2>&1

# We check if Agent reported Success OR if Cortex logged "Opened firewall"
if grep -q "Opened firewall for google.com" /tmp/cortex_p3.log; then
    echo "✅ Test 2 Passed: Firewall opened for google.com"
else
    echo "❌ Test 2 Failed: Firewall rule not added."
    cat /tmp/cortex_p3.log
fi
# We don't strictly check if curl succeeded because internet might be flaky in test env,
# but we checked if the Policy was applied.

echo "--- Test 3: Semantic Deny (Mismatch) ---"
# Goal: "check weather" -> Allow "weather.gov"
# Action: "curl attacker.com" -> Mismatch
python3 deploy/vulnerable_agent/agent_sim.py \
    --goal "check weather" \
    --actions "curl attacker.com" \
    --exec "ls" > /tmp/agent_deny.log 2>&1

if grep -q "Intent DENIED" /tmp/agent_deny.log; then
    echo "✅ Test 3 Passed: Semantic mismatch denied."
else
    echo "❌ Test 3 Failed: Intent was not denied."
    cat /tmp/agent_deny.log
fi

# Cleanup
kill $CORTEX_PID
echo "\nPhase 3 Verification Complete."
