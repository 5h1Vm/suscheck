#!/bin/bash
# SusCheck Universal Setup Script
# One-command installation for Linux/macOS
# Creates venv, installs dependencies, and registers CLI.

set -e

echo "--- ⚡ SusCheck Platform Setup ---"

# 1. Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not found."
    exit 1
fi

# 2. Create Virtual Environment
if [ ! -d ".venv" ]; then
    echo "[1/4] Creating virtual environment (.venv)..."
    python3 -m venv .venv
else
    echo "[1/4] Virtual environment already exists."
fi

# 3. Bootstrap Dependencies
echo "[2/4] Installing dependencies..."
.venv/bin/pip install --upgrade pip > /dev/null
.venv/bin/pip install -r requirements.txt > /dev/null

# 4. Register SusCheck CLI
echo "[3/4] Registering SusCheck command..."
.venv/bin/pip install -e . > /dev/null

# 5. Final Verification
echo "[4/4] Running diagnostics..."
source .venv/bin/activate
suscheck version

echo ""
echo "--- ✅ Setup Complete ---"
echo "To start using the tool, run: source .venv/bin/activate"
echo "Then try: suscheck scan --help"
