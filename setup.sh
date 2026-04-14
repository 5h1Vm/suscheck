#!/bin/bash
# SusCheck (v1.0.0 Gold) — Universal Setup Script
# Automated environment initialization for Forensic Pre-execution Security Platform

set -e

echo "--------------------------------------------------"
echo "   SusCheck: Forensic Pre-execution Orchestrator   "
echo "   Single entrypoint: setup.sh                     "
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

# 4. Tool Provisioning (KICS)
echo "[4/5] Provisioning KICS runtime for IaC forensics..."
# Optional local archive path can be provided through env
# e.g. SUSCHECK_KICS_ARCHIVE=/path/to/kics-binary.zip bash setup.sh
if [ -n "${SUSCHECK_KICS_ARCHIVE:-}" ]; then
    bash scripts/install_kics.sh "$SUSCHECK_KICS_ARCHIVE" > /dev/null || echo "      ⚠️  KICS provisioning failed."
else
    bash scripts/install_kics.sh > /dev/null || echo "      ⚠️  KICS provisioning failed."
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
echo "  2. Configure: Add API keys and optional paths to your .env file"
echo "  3. Check: suscheck version"
echo "  4. Scan: suscheck scan ./your_project"
echo "--------------------------------------------------"
