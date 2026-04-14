#!/bin/bash
# SusCheck (v1.0.0 Gold) — Universal Setup Script
# Automated environment initialization for Forensic Pre-execution Security Platform

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_BIN="$ROOT_DIR/.venv/bin"

persist_kics_env() {
    local kics_bin="$VENV_BIN/kics"
    local env_file="$ROOT_DIR/.env"

    if [[ ! -x "$kics_bin" ]]; then
        return 0
    fi

    if [[ -f "$env_file" ]] && grep -q '^SUSCHECK_KICS_PATH=' "$env_file"; then
        return 0
    fi

    {
        echo ""
        echo "# Auto-configured by setup.sh"
        echo "SUSCHECK_KICS_PATH=$kics_bin"
    } >> "$env_file"

    echo "      ✓ Persisted SUSCHECK_KICS_PATH in .env"
}

download_kics_archive() {
    local out_archive="$1"

    python3 - "$out_archive" <<'PY'
import json
import platform
import re
import sys
import urllib.request
from pathlib import Path

out_archive = Path(sys.argv[1])

machine = platform.machine().lower()
system = platform.system().lower()

if system.startswith("linux"):
    os_tag = "linux"
elif system.startswith("darwin"):
    os_tag = "darwin"
else:
    raise SystemExit(3)

if machine in {"x86_64", "amd64"}:
    arch_tags = ["amd64", "x64", "x86_64"]
elif machine in {"aarch64", "arm64"}:
    arch_tags = ["arm64", "aarch64"]
else:
    raise SystemExit(4)

api = "https://api.github.com/repos/Checkmarx/kics/releases/latest"
req = urllib.request.Request(api, headers={"User-Agent": "suscheck-setup"})
with urllib.request.urlopen(req, timeout=30) as resp:
    rel = json.loads(resp.read().decode())

assets = rel.get("assets", [])
download_url = None
asset_name = None
for asset in assets:
    name = (asset.get("name") or "").lower()
    if os_tag not in name:
        continue
    if not any(tag in name for tag in arch_tags):
        continue
    if not (name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".zip")):
        continue
    if "checksums" in name or "sha" in name:
        continue
    download_url = asset.get("browser_download_url")
    asset_name = asset.get("name")
    break

if not download_url:
    raise SystemExit(5)

out_archive.parent.mkdir(parents=True, exist_ok=True)
req_asset = urllib.request.Request(download_url, headers={"User-Agent": "suscheck-setup"})
with urllib.request.urlopen(req_asset, timeout=120) as resp:
    out_archive.write_bytes(resp.read())

print(asset_name or out_archive.name)
PY
}

provision_kics() {
    local archive_path="${1:-}"
    local install_dir="$VENV_BIN"

    if [[ ! -d "$install_dir" ]]; then
        echo "ERROR: Virtual environment bin not found at: $install_dir"
        return 1
    fi

    if command -v kics >/dev/null 2>&1; then
        echo "      ✓ Found local KICS binary: $(command -v kics)"
        return 0
    fi

    install_from_archive() {
        local archive="$1"
        if [[ -z "$archive" || ! -f "$archive" ]]; then
            return 1
        fi

        local tmp_dir
        tmp_dir="$(mktemp -d)"

        set +e
        python3 - "$archive" "$tmp_dir" <<'PY'
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

archive = Path(sys.argv[1])
out_dir = Path(sys.argv[2])

def is_candidate(name: str) -> bool:
    return Path(name).name == "kics"

def extract_candidate_from_zip(path: Path, dst: Path) -> bool:
    with zipfile.ZipFile(path) as zf:
        for member in zf.infolist():
            if member.is_dir() or not is_candidate(member.filename):
                continue
            zf.extract(member, dst)
            extracted = dst / member.filename
            target = dst / "kics"
            target.write_bytes(extracted.read_bytes())
            return True
    return False

def extract_candidate_from_tar(path: Path, dst: Path) -> bool:
    with tarfile.open(path) as tf:
        for member in tf.getmembers():
            if member.isdir() or not is_candidate(member.name):
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            (dst / "kics").write_bytes(extracted.read())
            return True
    return False

ok = False
name = archive.name.lower()
if name.endswith(".zip"):
    ok = extract_candidate_from_zip(archive, out_dir)
elif name.endswith(".tar.gz") or name.endswith(".tgz") or name.endswith(".tar"):
    ok = extract_candidate_from_tar(archive, out_dir)

if not ok:
    raise SystemExit(2)

target = out_dir / "kics"
target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
        local py_status=$?
        set -e

        if [[ $py_status -ne 0 || ! -f "$tmp_dir/kics" ]]; then
            rm -rf "$tmp_dir"
            return 2
        fi

        cp "$tmp_dir/kics" "$install_dir/kics"
        chmod +x "$install_dir/kics"
        rm -rf "$tmp_dir"

        echo "      ✓ Installed KICS binary: $install_dir/kics"
        "$install_dir/kics" version >/dev/null 2>&1 || true
        persist_kics_env
        return 0
    }

    if install_from_archive "$archive_path"; then
        return 0
    fi

    echo "      • Attempting automatic KICS binary download for local install..."
    local dl_archive
    dl_archive="$(mktemp -u)/kics-download"
    if download_kics_archive "$dl_archive" >/dev/null 2>&1; then
        if install_from_archive "$dl_archive"; then
            rm -f "$dl_archive"
            return 0
        fi
        rm -f "$dl_archive"
        echo "      ⚠️  Download succeeded, but archive extraction failed."
    else
        echo "      ⚠️  Automatic KICS download failed (network/asset resolution issue)."
    fi

    if [[ -n "$archive_path" ]]; then
        echo "      ⚠️  Provided archive did not include standalone 'kics' binary."
    fi

    if command -v docker >/dev/null 2>&1; then
        docker pull checkmarx/kics:latest >/dev/null
        echo "      ✓ Docker KICS runtime ready (checkmarx/kics:latest)"
        return 0
    fi

    echo "      ✗ Could not provision KICS (no valid archive and Docker unavailable)."
    return 3
}

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
if ! provision_kics "${SUSCHECK_KICS_ARCHIVE:-}"; then
    echo "      ⚠️  KICS provisioning failed. You can still run scans without KICS."
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
