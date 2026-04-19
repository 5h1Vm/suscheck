"""Deterministic fingerprint helpers for unchanged file targets."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from suscheck.modules.external.hash_engine import HashResult


@dataclass(frozen=True)
class FileFingerprint:
    path: str
    size: int
    mtime_ns: int


def build_file_fingerprint(path: str | Path) -> FileFingerprint:
    resolved = Path(path).resolve()
    stat = resolved.stat()
    return FileFingerprint(path=str(resolved), size=stat.st_size, mtime_ns=stat.st_mtime_ns)


def _cache_path() -> Path:
    override = os.environ.get("SUSCHECK_TIER0_CACHE_FILE")
    if override:
        return Path(override)
    return Path.cwd() / ".suscheck" / "cache" / "tier0_hash_cache.json"


class Tier0FingerprintCache:
    """Store and retrieve hash results for unchanged files."""

    def __init__(self, cache_path: str | Path | None = None) -> None:
        self.cache_path = Path(cache_path) if cache_path else _cache_path()

    def _load(self) -> dict[str, Any]:
        if not self.cache_path.is_file():
            return {}
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return raw if isinstance(raw, dict) else {}

    def _save(self, data: dict[str, Any]) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    def get(self, fingerprint: FileFingerprint) -> HashResult | None:
        data = self._load()
        entry = data.get(fingerprint.path)
        if not isinstance(entry, dict):
            return None
        if entry.get("size") != fingerprint.size or entry.get("mtime_ns") != fingerprint.mtime_ns:
            return None
        hash_data = entry.get("hash_result")
        if not isinstance(hash_data, dict):
            return None
        try:
            return HashResult(
                sha256=str(hash_data["sha256"]),
                md5=str(hash_data["md5"]),
                sha1=str(hash_data["sha1"]),
                file_size=int(hash_data["file_size"]),
                file_path=str(hash_data.get("file_path") or fingerprint.path),
            )
        except (KeyError, TypeError, ValueError):
            return None

    def put(self, fingerprint: FileFingerprint, hash_result: HashResult) -> None:
        data = self._load()
        data[fingerprint.path] = {
            "path": fingerprint.path,
            "size": fingerprint.size,
            "mtime_ns": fingerprint.mtime_ns,
            "hash_result": asdict(hash_result),
        }
        self._save(data)
