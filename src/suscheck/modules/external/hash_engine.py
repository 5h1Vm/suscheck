"""Hash Engine — computes SHA-256, MD5, SHA-1 for files.

This is the foundation of Tier 0. Every file that enters the
pipeline gets hashed here before any other analysis.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Default max file size: 50 MB
DEFAULT_MAX_FILE_SIZE = 52_428_800

# Read files in 8 KB chunks for memory efficiency
CHUNK_SIZE = 8192


@dataclass
class HashResult:
    """Result of hashing a file."""

    sha256: str
    md5: str
    sha1: str
    file_size: int
    file_path: Optional[str] = None

    @property
    def vt_lookup_hash(self) -> str:
        """Return the preferred hash for VirusTotal lookups (SHA-256)."""
        return self.sha256


class HashEngine:
    """Computes SHA-256, MD5, and SHA-1 hashes for files.

    Supports both file paths and raw bytes. Uses chunked reading
    for memory efficiency on large files.
    """

    def __init__(self, max_file_size: int = DEFAULT_MAX_FILE_SIZE):
        self.max_file_size = max_file_size

    def hash_file(self, file_path: str) -> HashResult:
        """Hash a file on disk.

        Args:
            file_path: Path to the file to hash.

        Returns:
            HashResult with SHA-256, MD5, SHA-1 digests.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            IsADirectoryError: If the path is a directory.
            ValueError: If the file exceeds max_file_size.
            PermissionError: If the file can't be read.
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if path.is_dir():
            raise IsADirectoryError(f"Cannot hash a directory: {file_path}")

        file_size = path.stat().st_size

        if file_size > self.max_file_size:
            raise ValueError(
                f"File too large ({file_size:,} bytes). "
                f"Maximum is {self.max_file_size:,} bytes. "
                f"Override with max_file_size parameter."
            )

        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()

        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)

        return HashResult(
            sha256=sha256.hexdigest(),
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            file_size=file_size,
            file_path=str(path.resolve()),
        )

    def hash_bytes(self, data: bytes, label: str = "<bytes>") -> HashResult:
        """Hash raw bytes (e.g., downloaded package content).

        Args:
            data: Raw bytes to hash.
            label: Human-readable label for the data source.

        Returns:
            HashResult with SHA-256, MD5, SHA-1 digests.
        """
        return HashResult(
            sha256=hashlib.sha256(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            file_size=len(data),
            file_path=label,
        )
