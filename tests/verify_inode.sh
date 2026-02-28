#!/bin/bash
# Verify Inode Protection

SECRET_FILE="/tmp/secret_file"
if [ ! -f "$SECRET_FILE" ]; then
    echo "This is a secret file." > "$SECRET_FILE"
fi

INODE=$(stat -c '%i' "$SECRET_FILE")
echo "Secret file inode: $INODE"

# Kill existing cortex
pkill -f "cortex/main.py"

echo "Starting Cortex..."
nohup python3 cortex/main.py > /tmp/cortex_inode.log 2>&1 &
CORTEX_PID=$!
sleep 2

# Kill immediately, we just need startup logs
kill $CORTEX_PID

echo "Checking logs for inode protection attempt..."
# We expect "Failed to update inode <INODE> sensitivity" because daemon is not running/accessible
# But the attempt confirming the resolution is what matters for the Python logic verification.
if grep -q "inode $INODE" /tmp/cortex_inode.log; then
    echo "✓ SUCCESS: Cortex attempted to protect inode $INODE"
else
    echo "❌ FAILURE: Inode protection attempt not found."
    cat /tmp/cortex_inode.log
    exit 1
fi

echo "Inode Verification Complete."
