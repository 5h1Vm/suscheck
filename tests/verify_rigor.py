import subprocess
import json
import sys
import os

def run_suscheck(command_args):
    cmd = ["suscheck"] + command_args
    # Adjust path if not in env
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result
    except subprocess.TimeoutExpired:
        return None

def test_yanked_detection():
    print("Testing Yanked Package Detection (pypi:urllib3@2.0.0)...")
    # urllib3 2.0.0 is verified yanked
    res = subprocess.run(["suscheck", "trust", "pypi:urllib3@2.0.0"], capture_output=True, text=True)
    if "TRUST-YANKED" in res.stdout:
        print("✅ SUCCESS: Yanked version detected.")
    else:
        print("❌ FAILURE: Yanked version NOT detected.")
        print(res.stdout)

def test_obfuscation_peeling():
    print("\nTesting Recursive Obfuscation Peeling (obfuscated_stage2.py)...")
    res = subprocess.run(["suscheck", "scan", "tests/attack_lab/obfuscated_stage2.py"], capture_output=True, text=True)
    # The payload contains 'import os; os.system' after decoding
    if "exec() call" in res.stdout or "DANGEROUS_FUNCTION" in res.stdout:
        print("✅ SUCCESS: Obfuscated payload detected after recursive peeling.")
    else:
        print("❌ FAILURE: Obfuscated payload missed.")
        print(res.stdout)

def test_mcp_static_nightmare():
    print("\nTesting Static MCP Nightmare Manifest...")
    res = subprocess.run(["suscheck", "scan", "tests/samples/mcp_nightmare_static_001.json"], capture_output=True, text=True)
    if "shell_transport" in res.stdout or "restricted_tool_name" in res.stdout or "prompt_injection" in res.stdout:
        print("✅ SUCCESS: Static threats in MCP manifest detected.")
    else:
        print("❌ FAILURE: Static MCP threats missed.")
        print(res.stdout)

if __name__ == "__main__":
    # Ensure we are in the right directory
    os.chdir("/home/shivam/Minor02/suscheck")
    test_yanked_detection()
    test_obfuscation_peeling()
    test_mcp_static_nightmare()
