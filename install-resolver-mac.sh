#!/bin/bash
# LNID Resolver Installation Script for macOS
# Uses launchd instead of systemctl

set -e

PLIST_FILE="/Library/LaunchDaemons/com.lnid.resolver.plist"
EXECUTABLE="/usr/local/bin/lnid-resolver"
CONFIG_FILE="/etc/lnid-resolver.conf"

echo "=== LNID Resolver Installation for macOS ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Check if executable exists
if [ ! -f "$EXECUTABLE" ]; then
    echo "Error: $EXECUTABLE not found. Run 'make install' first."
    exit 1
fi

# Create default configuration if not exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Creating default configuration..."
    cat > "$CONFIG_FILE" << EOF
# LNID Resolver Configuration for macOS
# Subnets to scan (without .0 suffix, comma separated)
# Examples: SUBNET=192.168.1 or SUBNET=192.168.1,10.0.1,172.16.1
SUBNET=192.168.1
SCAN_INTERVAL=300
PORT=16969
DOMAIN=local
ENCRYPTED=0
TIMEOUT=100
DELAY=50
VERBOSE=0
EOF
    chmod 644 "$CONFIG_FILE"
    echo "Configuration created: $CONFIG_FILE"
fi

# Create launchd plist
echo "Creating launchd service..."
cat > "$PLIST_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.lnid.resolver</string>
    <key>ProgramArguments</key>
    <array>
        <string>$EXECUTABLE</string>
        <string>-f</string>
        <string>-v</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/lnid-resolver.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/lnid-resolver.log</string>
</dict>
</plist>
EOF

chmod 644 "$PLIST_FILE"

# Load and start service
echo "Loading service..."
launchctl load "$PLIST_FILE"
launchctl start com.lnid.resolver

echo "✓ LNID Resolver installed and started"
echo ""
echo "Management commands:"
echo "  sudo launchctl start com.lnid.resolver    # Start"
echo "  sudo launchctl stop com.lnid.resolver     # Stop"
echo "  sudo launchctl unload $PLIST_FILE         # Uninstall"
echo "  tail -f /var/log/lnid-resolver.log        # View logs"
echo ""
echo "Configuration: $CONFIG_FILE"