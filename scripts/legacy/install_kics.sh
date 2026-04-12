#!/bin/bash
# KICS Installation Script for SusCheck
# Targets Linux x86_64 and installs into project .venv/bin

set -e

PROJECT_ROOT="/home/shivam/Minor02/suscheck"
INSTALL_DIR="$PROJECT_ROOT/.venv/bin"
VERSION="2.1.3"
URL="https://github.com/Checkmarx/kics/releases/download/v${VERSION}/kics_${VERSION}_linux_x64.tar.gz"

echo "--- Installing KICS v${VERSION} ---"

if [ -f "$INSTALL_DIR/kics" ]; then
    echo "KICS already exists in $INSTALL_DIR. Skipping download."
    exit 0
fi

# Use a temporary directory for extraction
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo "Downloading KICS from GitHub..."
curl -L "$URL" -o kics.tar.gz

echo "Extracting binary..."
tar -xzf kics.tar.gz

echo "Moving kics to $INSTALL_DIR..."
mv kics "$INSTALL_DIR/"

# Cleanup
cd "$PROJECT_ROOT"
rm -rf "$TEMP_DIR"

echo "Setting permissions..."
chmod +x "$INSTALL_DIR/kics"

echo "Verifying installation..."
"$INSTALL_DIR/kics" version

echo "--- KICS Installation Complete ---"
