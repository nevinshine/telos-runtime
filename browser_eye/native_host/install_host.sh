#!/bin/bash
#
# Telos Native Host Installation Script
# Installs the Chrome Native Messaging Host manifest
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_NAME="com.telos.native"
HOST_SCRIPT="$SCRIPT_DIR/host_messaging.py"
MANIFEST_TEMPLATE="$SCRIPT_DIR/com.telos.native.json"

# Detect Chrome installation
CHROME_MANIFEST_DIRS=(
    "$HOME/.config/google-chrome/NativeMessagingHosts"
    "$HOME/.config/chromium/NativeMessagingHosts"
    "$HOME/.config/google-chrome-beta/NativeMessagingHosts"
    "$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
)

echo "╔═══════════════════════════════════════════════════════╗"
echo "║     TELOS Native Messaging Host Installer             ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo

# Make the host script executable
chmod +x "$HOST_SCRIPT"
echo "✓ Made $HOST_SCRIPT executable"

# Get extension ID from user if needed
read -p "Enter your Chrome Extension ID (or press Enter to skip): " EXT_ID

if [ -z "$EXT_ID" ]; then
    EXT_ID="EXTENSION_ID_PLACEHOLDER"
    echo "⚠ Using placeholder - update manifest after installing extension"
fi

# Create manifest with correct paths
MANIFEST_CONTENT=$(cat <<EOF
{
  "name": "$HOST_NAME",
  "description": "Telos Security Runtime - Native Messaging Host",
  "path": "$HOST_SCRIPT",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXT_ID/"
  ]
}
EOF
)

# Install to all detected Chrome directories
INSTALLED=0

for DIR in "${CHROME_MANIFEST_DIRS[@]}"; do
    if [ -d "$(dirname "$DIR")" ]; then
        mkdir -p "$DIR"
        MANIFEST_PATH="$DIR/$HOST_NAME.json"
        echo "$MANIFEST_CONTENT" > "$MANIFEST_PATH"
        echo "✓ Installed manifest to: $MANIFEST_PATH"
        INSTALLED=1
    fi
done

if [ $INSTALLED -eq 0 ]; then
    # Try default Chrome location
    DEFAULT_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
    mkdir -p "$DEFAULT_DIR"
    MANIFEST_PATH="$DEFAULT_DIR/$HOST_NAME.json"
    echo "$MANIFEST_CONTENT" > "$MANIFEST_PATH"
    echo "✓ Installed manifest to: $MANIFEST_PATH"
fi

echo
echo "╔═══════════════════════════════════════════════════════╗"
echo "║                  Installation Complete                 ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo
echo "Next steps:"
echo "  1. Load the Browser Eye extension in Chrome (chrome://extensions)"
echo "  2. Copy the Extension ID"
echo "  3. Re-run this script with the Extension ID, or manually update:"
echo "     $HOME/.config/google-chrome/NativeMessagingHosts/$HOST_NAME.json"
echo
echo "  4. Ensure Telos Cortex is running on localhost:50051"
echo "  5. Restart Chrome"
echo
