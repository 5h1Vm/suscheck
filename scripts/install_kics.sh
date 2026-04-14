#!/bin/bash
# SusCheck KICS installer/provisioner.
#
# Usage:
#   bash scripts/install_kics.sh [optional-archive-path]
#
# Priority:
#   1) Use existing local `kics` binary (PATH or .venv/bin)
#   2) Install from provided archive if it contains executable `kics`
#   3) Provision Docker KICS runtime (`checkmarx/kics:latest`)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL_DIR="$ROOT_DIR/.venv/bin"
ARCHIVE_PATH="${1:-}"

echo "--- Provisioning KICS for SusCheck ---"

if [[ ! -d "$INSTALL_DIR" ]]; then
  echo "ERROR: Virtual environment bin not found at: $INSTALL_DIR"
  echo "Create/activate .venv first, then rerun this script."
  exit 1
fi

# Fast path: local binary already available.
if command -v kics >/dev/null 2>&1; then
	echo "Found local KICS binary: $(command -v kics)"
	echo "--- KICS provision step complete ---"
	exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

install_from_archive() {
	local archive="$1"
	if [[ ! -f "$archive" ]]; then
		return 1
	fi

	echo "Inspecting archive: $archive"

	set +e
	python3 - "$archive" "$TMP_DIR" <<'PY'
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

archive = Path(sys.argv[1])
out_dir = Path(sys.argv[2])

def is_candidate(name: str) -> bool:
	base = Path(name).name
	return base == "kics"

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
	print("NO_BINARY")
	raise SystemExit(2)

target = out_dir / "kics"
target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
print("OK")
PY
	PY_STATUS=$?
	set -e

	if [[ $PY_STATUS -ne 0 || ! -f "$TMP_DIR/kics" ]]; then
		return 2
	fi

	cp "$TMP_DIR/kics" "$INSTALL_DIR/kics"
	chmod +x "$INSTALL_DIR/kics"

	echo "Installed local binary: $INSTALL_DIR/kics"
	echo "Verifying local binary..."
	"$INSTALL_DIR/kics" version || true
	return 0
}

# Try archive install if user provided one.
if [[ -n "$ARCHIVE_PATH" ]]; then
	if install_from_archive "$ARCHIVE_PATH"; then
		echo "--- KICS provision step complete ---"
		exit 0
	else
		echo "Archive does not contain standalone executable 'kics'."
		echo "This usually means source zip/tar, not release binary package."
	fi
fi

# Fallback provisioning: Docker runtime for KICS.
if command -v docker >/dev/null 2>&1; then
	echo "No local KICS binary available. Provisioning Docker KICS runtime..."
	docker pull checkmarx/kics:latest >/dev/null
	echo "Docker KICS runtime ready: checkmarx/kics:latest"
	echo "--- KICS provision step complete (docker mode) ---"
	exit 0
fi

echo "ERROR: Could not provision KICS."
echo "Provide a valid KICS binary archive, or install Docker for runtime mode."
exit 3
