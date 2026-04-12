"""Tests for the AutoDetector module."""

import os
from pathlib import Path

import pytest

from suscheck.core.auto_detector import AutoDetector, ArtifactType, Language


class TestAutoDetector:
    def setup_method(self):
        self.detector = AutoDetector()

    def test_detect_python_file_by_extension(self, tmp_path):
        f = tmp_path / "script.py"
        f.write_text("print('hello')")
        result = self.detector.detect(str(f))
        
        assert result.artifact_type == ArtifactType.CODE
        assert result.language == Language.PYTHON
        # Might be magic bytes if python-magic is installed and detects it, but typically extension or content
        assert result.language == Language.PYTHON

    def test_detect_bash_shebang_mismatch(self, tmp_path):
        """Test that a .py file with a bash shebang is flagged as a mismatch."""
        f = tmp_path / "script.py"
        f.write_text("#!/bin/bash\necho 'hello'")
        result = self.detector.detect(str(f))
        
        assert result.language == Language.BASH
        # It's a bash script, so artifact type should be CODE
        assert result.artifact_type == ArtifactType.CODE
        assert result.type_mismatch is True
        assert "Extension suggests" in str(result.mismatch_detail)

    def test_detect_dockerfile_by_name(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM alpine:latest\nRUN echo 'hello'")
        result = self.detector.detect(str(f))
        
        assert result.artifact_type == ArtifactType.CONFIG
        assert result.language == Language.DOCKERFILE
        assert result.detection_method == "filename_match"

    def test_detect_directory_as_repository(self, tmp_path):
        # Create a directory with a .git subfolder
        repo_dir = tmp_path / "my_repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()
        
        result = self.detector.detect(str(repo_dir))
        assert result.artifact_type == ArtifactType.REPOSITORY
        assert result.detection_method == "git_directory"

    def test_detect_repository_url(self):
        result = self.detector.detect("https://github.com/torvalds/linux")
        assert result.artifact_type == ArtifactType.REPOSITORY
        assert result.detection_method == "url_pattern"

    def test_detect_mcp_server_url(self):
        result = self.detector.detect("https://example.com/mcp_server")
        assert result.artifact_type == ArtifactType.MCP_SERVER
        assert result.detection_method == "url_pattern"

    def test_detect_mcp_manifest_by_filename(self, tmp_path):
        f = tmp_path / "mcp-config.json"
        f.write_text('{"mcpServers": {}}', encoding="utf-8")
        result = self.detector.detect(str(f))
        assert result.artifact_type == ArtifactType.MCP_SERVER
        assert result.language == Language.MCP_MANIFEST
        assert result.detection_method == "filename_match"

    def test_detect_mcp_manifest_by_content_marker(self, tmp_path):
        f = tmp_path / "cursor-style.json"
        f.write_text('{"mcpServers": {"x": {"command": "npx"}}}', encoding="utf-8")
        result = self.detector.detect(str(f))
        assert result.artifact_type == ArtifactType.MCP_SERVER
        assert result.language == Language.MCP_MANIFEST
        assert result.detection_method == "mcp_manifest_content"

    def test_detect_polyglot(self, tmp_path):
        """Test a file that could be multiple things."""
        f = tmp_path / "script.dat"
        # Has an unknown extension (no type mismatch triggered by extension), 
        # but has python shebang and php content.
        f.write_text("#!/usr/bin/env python\n<?php echo 'hello'; ?>")
        result = self.detector.detect(str(f))
        
        # Should be flagged as polyglot
        assert result.is_polyglot is True
