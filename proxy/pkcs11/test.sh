#!/bin/bash
# Test script for PocketSSHAgent PKCS#11 Provider

set -e

PROVIDER="./libpocket-pkcs11.so"

echo "==================================================="
echo "PocketSSHAgent PKCS#11 Provider Test"
echo "==================================================="
echo ""

# Check if library exists
if [ ! -f "$PROVIDER" ]; then
    echo "ERROR: Provider not found: $PROVIDER"
    echo "Run 'make' first"
    exit 1
fi

echo "✓ Provider library found: $PROVIDER"
echo ""

# Check if pkcs11-tool is installed
if ! command -v pkcs11-tool &> /dev/null; then
    echo "WARNING: pkcs11-tool not installed"
    echo "Install with: sudo apt-get install opensc"
    echo ""
    echo "Skipping pkcs11-tool tests..."
    exit 0
fi

echo "✓ pkcs11-tool found"
echo ""

# Test 1: List slots
echo "Test 1: List Slots"
echo "-------------------"
pkcs11-tool --module "$PROVIDER" --list-slots || {
    echo "FAILED: Could not list slots"
    echo "Make sure Android app is running and paired"
    exit 1
}
echo ""

# Test 2: Get token info
echo "Test 2: Get Token Info"
echo "----------------------"
pkcs11-tool --module "$PROVIDER" --slot 0 --show-info || {
    echo "FAILED: Could not get token info"
    exit 1
}
echo ""

# Test 3: List objects (requires BLE connection)
echo "Test 3: List Objects (Keys)"
echo "---------------------------"
echo "NOTE: This requires Android app to be running with BLE enabled"
echo ""
pkcs11-tool --module "$PROVIDER" --list-objects || {
    echo "FAILED: Could not list objects"
    echo ""
    echo "Possible causes:"
    echo "  - Android app not running"
    echo "  - BLE not connected"
    echo "  - No keys generated in Android app"
    echo "  - Not paired (run: ../pocket-agent pair)"
    exit 1
}
echo ""

echo "==================================================="
echo "All tests passed!"
echo "==================================================="
echo ""
echo "Next steps:"
echo "  1. Test with SSH:"
echo "     ssh -I $PWD/$PROVIDER user@hostname"
echo ""
echo "  2. Add to SSH config:"
echo "     echo 'PKCS11Provider $PWD/$PROVIDER' >> ~/.ssh/config"
echo ""
