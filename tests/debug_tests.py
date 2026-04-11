"""Quick debug to understand test failures."""
import base64
from suscheck.modules.detectors.encoded_strings import detect_encoded_strings, BASE64_PATTERN, _is_common_base64_fp, _try_decode_base64
from suscheck.modules.detectors.network_indicators import detect_network_indicators, _is_version_number
from suscheck.modules.detectors.credentials import detect_credentials

# Test 1: Base64
payload = base64.b64encode(b"http://evil.com/shell").decode()
print(f"Base64 payload: {payload!r} (len={len(payload)})")
content = f'payload = "{payload}"'

import re
for m in BASE64_PATTERN.finditer(content):
    val = m.group(1) or m.group(2)
    print(f"  Match: {val!r} fp={_is_common_base64_fp(val)} decode={_try_decode_base64(val)!r}")

findings = detect_encoded_strings(content, "test.py")
print(f"  Findings: {len(findings)}")

# Test 2: Version number
content2 = 'version = "1.2.3.4"'
print(f"\nVersion test: {content2!r}")
print(f"  _is_version_number('1.2.3.4', content2) = {_is_version_number('1.2.3.4', content2)}")
findings2 = detect_network_indicators(content2, "test.py")
print(f"  Findings: {len(findings2)}")

# Test 3: AWS key
content3 = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'
findings3 = detect_credentials(content3, "test.py")
print(f"\nAWS key test: {len(findings3)} findings")
for f in findings3:
    print(f"  {f.title}")
