#!/bin/bash
# SusCheck Tool Setup Utility
# Automates installation of Python dependencies and checks for external binaries.

set -e

echo "--- SusCheck Tool Setup ---"

# 1. Update Python dependencies
echo "[1/3] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# 2. Check for External Binaries
echo "[2/3] Checking for external binaries..."

check_tool() {
    if command -v "$1" >/dev/null 2>&1; then
        echo "  ✅ $1 found: $(command -v "$1")"
    else
        echo "  ❌ $1 not found"
        return 1
    fi
}

check_tool "gitleaks" || echo "     💡 Install gitleaks: https://github.com/gitleaks/gitleaks"
check_tool "semgrep" || echo "     💡 semgrep should be installed via pip (check venv)"
check_tool "bandit" || echo "     💡 bandit should be installed via pip (check venv)"
check_tool "checkov" || echo "     💡 checkov should be installed via pip (check venv)"
check_tool "kics" || echo "     💡 KICS binary is optional (secondary to Checkov)"
check_tool "docker" || echo "     💡 Docker is recommended for dynamic MCP scanning."

# 3. Final Verification
echo "[3/3] Running SusCheck diagnostics..."
suscheck version
suscheck check-keys

echo "--- Setup Complete ---"
