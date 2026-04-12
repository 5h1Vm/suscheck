"""Tests for the Hash Engine (SHA-256, MD5, SHA-1 computation)."""

import hashlib
import os
import tempfile

import pytest

from suscheck.tier0.hash_engine import HashEngine, HashResult


SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples", "benign")


class TestHashResult:
    """Test the HashResult dataclass."""

    def test_vt_lookup_hash_returns_sha256(self):
        result = HashResult(
            sha256="abc123", md5="def456", sha1="ghi789", file_size=100
        )
        assert result.vt_lookup_hash == "abc123"

    def test_optional_file_path(self):
        result = HashResult(sha256="a", md5="b", sha1="c", file_size=0)
        assert result.file_path is None

    def test_file_path_set(self):
        result = HashResult(
            sha256="a", md5="b", sha1="c", file_size=0, file_path="/tmp/test"
        )
        assert result.file_path == "/tmp/test"


class TestHashEngine:
    """Test the HashEngine class."""

    def setup_method(self):
        self.engine = HashEngine()

    def test_hash_file_hello_py(self):
        """Test hashing the hello.py sample file."""
        hello_path = os.path.join(SAMPLES_DIR, "hello.py")
        result = self.engine.hash_file(hello_path)

        # Verify hashes match what Python's hashlib produces
        with open(hello_path, "rb") as f:
            content = f.read()

        assert result.sha256 == hashlib.sha256(content).hexdigest()
        assert result.md5 == hashlib.md5(content).hexdigest()
        assert result.sha1 == hashlib.sha1(content).hexdigest()
        assert result.file_size == len(content)
        assert result.file_path is not None

    def test_hash_file_not_found(self):
        """Test that FileNotFoundError is raised for missing files."""
        with pytest.raises(FileNotFoundError):
            self.engine.hash_file("/nonexistent/path/to/file.py")

    def test_hash_file_is_directory(self):
        """Test that IsADirectoryError is raised for directories."""
        with pytest.raises(IsADirectoryError):
            self.engine.hash_file(SAMPLES_DIR)

    def test_hash_file_too_large(self):
        """Test that ValueError is raised for files exceeding max size."""
        small_engine = HashEngine(max_file_size=10)  # 10 bytes max
        hello_path = os.path.join(SAMPLES_DIR, "hello.py")

        with pytest.raises(ValueError, match="File too large"):
            small_engine.hash_file(hello_path)

    def test_hash_bytes(self):
        """Test hashing raw bytes."""
        data = b"Hello, World!"
        result = self.engine.hash_bytes(data, label="test-data")

        assert result.sha256 == hashlib.sha256(data).hexdigest()
        assert result.md5 == hashlib.md5(data).hexdigest()
        assert result.sha1 == hashlib.sha1(data).hexdigest()
        assert result.file_size == len(data)
        assert result.file_path == "test-data"

    def test_hash_empty_bytes(self):
        """Test hashing empty bytes."""
        data = b""
        result = self.engine.hash_bytes(data)

        # SHA-256 of empty data is a known constant
        assert result.sha256 == hashlib.sha256(b"").hexdigest()
        assert result.file_size == 0

    def test_hash_file_produces_consistent_results(self):
        """Test that hashing the same file twice produces identical results."""
        hello_path = os.path.join(SAMPLES_DIR, "hello.py")

        result1 = self.engine.hash_file(hello_path)
        result2 = self.engine.hash_file(hello_path)

        assert result1.sha256 == result2.sha256
        assert result1.md5 == result2.md5
        assert result1.sha1 == result2.sha1

    def test_hash_bytes_matches_hash_file(self):
        """Test that hash_bytes and hash_file produce the same hashes."""
        hello_path = os.path.join(SAMPLES_DIR, "hello.py")

        with open(hello_path, "rb") as f:
            content = f.read()

        file_result = self.engine.hash_file(hello_path)
        bytes_result = self.engine.hash_bytes(content)

        assert file_result.sha256 == bytes_result.sha256
        assert file_result.md5 == bytes_result.md5
        assert file_result.sha1 == bytes_result.sha1

    def test_hash_large_file_chunked(self):
        """Test that large files are read in chunks without error."""
        # Create a temp file larger than chunk size (8KB)
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".bin",
            dir=os.path.join(os.path.dirname(__file__), ".."),
        ) as f:
            f.write(b"A" * 20000)  # 20 KB
            temp_path = f.name

        try:
            result = self.engine.hash_file(temp_path)
            assert result.sha256 == hashlib.sha256(b"A" * 20000).hexdigest()
            assert result.file_size == 20000
        finally:
            os.unlink(temp_path)

    def test_default_max_file_size(self):
        """Test that default max file size is 50MB."""
        engine = HashEngine()
        assert engine.max_file_size == 52_428_800

    def test_custom_max_file_size(self):
        """Test custom max file size."""
        engine = HashEngine(max_file_size=1024)
        assert engine.max_file_size == 1024
