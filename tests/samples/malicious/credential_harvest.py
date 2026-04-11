#!/usr/bin/env python3
"""
MALICIOUS TEST SAMPLE — DO NOT RUN.
Contains hardcoded credentials for testing credential detection.
"""

# AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub PAT
github_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"

# Private key
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU4yTBpNb8FAKE_TEST_KEY_FOR_DETECTION_ONLY
-----END RSA PRIVATE KEY-----"""

# Hardcoded password
db_password = "SuperSecretP@ssw0rd123!"
password = "hunter2"

# API tokens
api_key = "a_very_secret_api_key_that_triggers_generic_detector"
slack_token = "xoxb-12345-67890-AbCdEfGhIjKlMnOpQrStUv"
google_key = "AIzaSyBDaBc1234567890ABCDEFGHIJKLMNOP"

# Database connection with embedded creds
DATABASE_URL = "postgresql://admin:secretpass@db.internal.com:5432/production"

# Auth token
auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIx"
