#!/bin/bash
# LNID Server Installation Script for macOS
# Uses launchd instead of systemctl

set -e

PLIST_FILE="/Library/LaunchDaemons/com.lnid.server.plist"
EXECUTABLE="/usr/local/bin/lnidd"
CONFIG_FILE="/etc/lnid-server.conf"

echo "=== LNID Server Installation for macOS ==="

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
# LNID Server Configuration for macOS
ETHERNET=en0
PORT=16969
HOSTNAME=
ENCRYPTED=0
SECURE_MODE=1
AUTHORIZED_NETWORKS=
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
    <string>com.lnid.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>$EXECUTABLE</string>
        <string>-v</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/lnid-server.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/lnid-server.log</string>
</dict>
</plist>
EOF

chmod 644 "$PLIST_FILE"

# Load and start service
echo "Loading service..."
launchctl load "$PLIST_FILE"
launchctl start com.lnid.server

echo "✓ LNID Server installed and started"
echo ""
echo "Management commands:"
echo "  sudo launchctl start com.lnid.server    # Start"
echo "  sudo launchctl stop com.lnid.server     # Stop"
echo "  sudo launchctl unload $PLIST_FILE       # Uninstall"
echo "  tail -f /var/log/lnid-server.log        # View logs"
echo ""
echo "Configuration: $CONFIG_FILE"