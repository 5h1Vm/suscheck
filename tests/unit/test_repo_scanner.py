"""Tests for the Repository Scanner module."""

import json
import os
import subprocess
import tempfile
from unittest.mock import patch

from suscheck.core.finding import FindingType, Severity
from suscheck.modules.repo_scanner import RepoScanner


def test_can_handle():
    scanner = RepoScanner()
    # Mocking files/directories
    with patch("pathlib.Path.is_dir") as mock_is_dir:
        mock_is_dir.return_value = True
        assert scanner.can_handle("repository", "/fake/dir") is True
        
        mock_is_dir.return_value = False
        assert scanner.can_handle("code", "/fake/file.py") is False


def test_gitleaks_detects_secret():
    scanner = RepoScanner()
    
    # We will mock the GitleaksRunner so we don't depend on the user's host
    # actually having the gitleaks binary installed during tests.
    with patch("suscheck.modules.repo.gitleaks_runner.subprocess.run") as mock_run:
        # Mocking the side_effect to physically write a JSON block into the report path
        # mimicking how subprocess.run("gitleaks detect --report-path <path>") works.
        def gitleaks_mock_effect(cmd, **kwargs):
            # Extract the report path from the command
            try:
                idx = cmd.index("--report-path")
                report_path = cmd[idx + 1]
            except ValueError:
                return subprocess.CompletedProcess(args=cmd, returncode=1)
                
            mock_data = [
                {
                    "Description": "AWS Access Key",
                    "StartLine": 10,
                    "EndLine": 10,
                    "StartColumn": 1,
                    "EndColumn": 20,
                    "Match": "AKIAIOSFODNN7EXAMPLE",
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                    "File": "config.json",
                    "Commit": "Uncommitted",
                    "Entropy": 5.0,
                    "Author": "Test Author",
                    "Email": "test@author.com",
                    "Date": "2023-01-01T00:00:00Z",
                    "Message": "Test",
                    "Tags": ["key", "AWS"],
                    "RuleID": "aws-access-token",
                    "Fingerprint": "config.json:aws-access-token:10"
                }
            ]
            with open(report_path, "w") as f:
                json.dump(mock_data, f)
                
            return subprocess.CompletedProcess(args=cmd, returncode=1)

        mock_run.side_effect = gitleaks_mock_effect

        with patch("suscheck.modules.repo.gitleaks_runner.shutil.which") as mock_which:
            mock_which.return_value = "/usr/bin/gitleaks"
            
            with tempfile.TemporaryDirectory() as temp_dir:
                res = scanner.scan(temp_dir)
                
                assert res.error is None
                assert len(res.findings) == 1
                
                finding = res.findings[0]
                assert finding.severity == Severity.CRITICAL
                assert finding.finding_type == FindingType.SECRET_EXPOSURE
                assert finding.finding_id == "LEAK-AWS-ACCESS-TOKEN"
                assert "AWS Access Key" in finding.title
