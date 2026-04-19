from __future__ import annotations

from pathlib import Path

from suscheck.modules.external.hash_engine import HashResult
from suscheck.services.fingerprint_service import Tier0FingerprintCache, build_file_fingerprint


def test_tier0_fingerprint_cache_reuses_hash_result(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("hello world\n", encoding="utf-8")

    cache_file = tmp_path / "tier0-cache.json"
    cache = Tier0FingerprintCache(cache_file)
    fingerprint = build_file_fingerprint(sample)
    hash_result = HashResult(
        sha256="a" * 64,
        md5="b" * 32,
        sha1="c" * 40,
        file_size=sample.stat().st_size,
        file_path=str(sample.resolve()),
    )

    assert cache.get(fingerprint) is None
    cache.put(fingerprint, hash_result)

    cached = cache.get(fingerprint)
    assert cached is not None
    assert cached.sha256 == hash_result.sha256
    assert cached.md5 == hash_result.md5
    assert cached.sha1 == hash_result.sha1
