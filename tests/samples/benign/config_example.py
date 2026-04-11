#!/usr/bin/env python3
"""Configuration example — tests false positive filtering.

This file contains patterns that LOOK like credentials but are
actually placeholders, environment variable references, or
documentation. The scanner should NOT flag these.
"""

import os

# These are environment variable references, NOT real credentials
API_KEY = os.environ.get("API_KEY", "")
SECRET_KEY = os.getenv("SECRET_KEY")
DATABASE_URL = os.environ["DATABASE_URL"]

# Placeholder values — should NOT be flagged
password = ""
password = "your_password_here"
api_key = "REPLACE_ME"
secret = "<insert_secret>"
token = "changeme"
aws_key = "AKIAXXXXXXXXXXXXXXXX"  # Example format, not real

# Version numbers that look like IPs — should NOT be flagged
__version__ = "1.2.3.4"
version = "10.0.0.1"
release = "2.0.1.0"

# Hash values in comments — should NOT be flagged
# SHA-256: a3f2c8d1e5b9f4a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
# MD5: d41d8cd98f00b204e9800998ecf8427e

# UUIDs — should NOT be flagged
request_id = "550e8400-e29b-41d4-a716-446655440000"

# Import paths — should NOT be flagged
from datetime import datetime
from pathlib import Path

# This is a comment with the word password but no actual password
# Configuration docs: set the password field in config.toml

# Common safe URLs — should NOT be flagged
DOCS_URL = "https://docs.python.org/3/library/os.html"
PYPI_URL = "https://pypi.org/project/requests/"
