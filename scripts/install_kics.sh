#!/bin/bash
# KICS Official Binary Installer for SusCheck
# Downloads the latest Linux x86_64 binary directly from Checkmarx

set -e

KICS_VERSION="1.7.13" # Stable version
KICS_URL="https://github.com/Checkmarx/kics/releases/download/v${KICS_VERSION}/kics_${KICS_VERSION}_linux_x64.tar.gz"
INSTALL_DIR="/home/shivam/Minor02/suscheck/.venv/bin"

echo "--- 🛠️ Installing KICS Binary ---"

# 1. Create temporary directory
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# 2. Download KICS
echo "Downloading KICS v${KICS_VERSION}..."
curl -L "$KICS_URL" -o "$TMP_DIR/kics.tar.gz"

# 3. Extract
echo "Extracting binary..."
tar -xzf "$TMP_DIR/kics.tar.gz" -C "$TMP_DIR"

# 4. Install to .venv/bin
echo "Installing to $INSTALL_DIR..."
mv "$TMP_DIR/kics" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/kics"

# 5. Verify
echo "Verifying installation..."
"$INSTALL_DIR/kics" version

echo "--- ✅ KICS installed successfully ---"
