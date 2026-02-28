#!/bin/bash
# Verify Phase 4: DNS Interception

# Cleanup
pkill -f "cortex/main.py"
pkill -f "agent_sim.py"
rm -f /tmp/cortex_dns.log

echo "Starting Cortex (with DNS Proxy)..."
nohup python3 cortex/main.py > /tmp/cortex_dns.log 2>&1 &
CORTEX_PID=$!
sleep 3

# We need to simulate the Agent using the Telos DNS (127.0.0.1:5353)
# Since we can't easily change /etc/resolv.conf in this env, we will use 'dig' 
# or python's resolver pointing to localhost:5353 in the verification command.

echo "--- Test 1: DNS-Based Authorization ---"
# Goal: "search" -> Allows "google.com"
# Action: Resolve google.com via 127.0.0.1:5353
# Expectation: Cortex sees DNS query, adds IP to BPF. Connection succeeds.

# 1. Trigger Intent
echo "1. Declaring Intent..."
python3 deploy/vulnerable_agent/agent_sim.py \
    --goal "search for info" \
    --actions "curl google.com" \
    --no-exec > /dev/null 2>&1

sleep 1

# 2. Perform DNS Query via Proxy
echo "2. Querying DNS Proxy (127.0.0.1:5353)..."
# Using python one-liner to query specific nameserver
IP=$(python3 -c "
import dns.resolver
res = dns.resolver.Resolver()
res.nameservers = ['127.0.0.1']
res.port = 5353
try:
    ans = res.resolve('google.com', 'A')
    print(ans[0])
except Exception as e:
    print('ERROR')
")

echo "Resolved IP: $IP"

if [ "$IP" == "ERROR" ] || [ -z "$IP" ]; then
    echo "❌ DNS Query Failed."
    cat /tmp/cortex_dns.log
    kill $CORTEX_PID
    exit 1
fi

# 3. Verify BPF Map Update
# We can check logs or attempt connection
if grep -q "Opened" /tmp/cortex_dns.log; then
    echo "✅ DNS Interceptor: Opened firewall for $IP"
else
    echo "❌ DNS Interceptor: Failed to open firewall."
    cat /tmp/cortex_dns.log
fi

# Cleanup
kill $CORTEX_PID
