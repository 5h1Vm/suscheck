#!/bin/bash
# SusCheck (v1.0.0 Gold) — Universal Setup Script
# Automated environment initialization for NFSU Pre-execution Security Platform

set -e

echo "--------------------------------------------------"
echo "   SusCheck: Pre-execution Security Platform       "
echo "   Researcher: Shivam Kumar Singh (NFSU)           "
echo "--------------------------------------------------"

# 1. Environment Check
echo "[1/5] Checking environment dependencies..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found. Please install Python 3.10+."
    exit 1
fi

# 2. Virtual Environment Initialization
if [ ! -d ".venv" ]; then
    echo "[2/5] Initializing isolated virtual environment (.venv)..."
    python3 -m venv .venv
else
    echo "[2/5] Virtual environment detected."
fi

# 3. Core Dependency Installation
echo "[3/5] Installing security engines and core dependencies..."
.venv/bin/pip install --upgrade pip > /dev/null
.venv/bin/pip install -r requirements.txt > /dev/null
.venv/bin/pip install -e . > /dev/null

# 4. Tool Restoration (KICS)
if [ ! -f ".venv/bin/kics" ]; then
    echo "[4/5] Restoring KICS binary for IaC forensics..."
    bash scripts/install_kics.sh > /dev/null || echo "      ⚠️  KICS binary download skipped (Optional, Checkov is active)."
else
    echo "[4/5] KICS binary verified."
fi

# 5. Final Diagnostic
echo "[5/5] Performing platform health check..."
source .venv/bin/activate
suscheck diagnostics --help > /dev/null # Verify CLI path
suscheck version

echo ""
echo "--------------------------------------------------"
echo "✅ Setup Successful!"
echo "--------------------------------------------------"
echo "Next Steps:"
echo "  1. Activate: source .venv/bin/activate"
echo "  2. Configure: Add API keys to your .env file"
echo "  3. Scan: suscheck scan ./your_project"
echo "--------------------------------------------------"
