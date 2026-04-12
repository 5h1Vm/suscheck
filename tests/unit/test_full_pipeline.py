"""End-to-end regression tests for the SusCheck platform (Increment 18)."""

import subprocess
import os
import sys
from pathlib import Path
def run_suscheck(args: list[str]) -> subprocess.CompletedProcess:
    """Run suscheck CLI and return the result."""
    root = Path(__file__).parent.parent
    src_dir = root / "src"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(src_dir) + os.pathsep + env.get("PYTHONPATH", "")
    
    return subprocess.run(
        [sys.executable, "-m", "suscheck"] + args,
        capture_output=True,
        text=True,
        cwd=str(root),
        env=env
    )

def test_scan_malicious_python():
    """Verify that a known malicious Python file is flagged as ABORT/HOLD."""
    sample = "tests/samples/malicious/encoded_payload.py"
    result = run_suscheck(["scan", sample])
    
    if "ABORT" not in result.stdout and "HOLD" not in result.stdout:
        print(f"FAILED test_scan_malicious_python")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        assert False
    
    # PRI should be high for this sample
    assert result.returncode == 0
    assert "Platform Risk Index" in result.stdout

def test_explain_malicious_python():
    """Verify that the explain command works on a malicious file."""
    sample = "tests/samples/malicious/encoded_payload.py"
    # We use --no-ai might be needed if no API keys, but we want to test the orchestration
    result = run_suscheck(["explain", sample])
    
    assert result.returncode == 0
    assert "Behavioral Analysis" in result.stdout
    assert "encoded_payload.py" in result.stdout

def test_scan_benign_file():
    """Verify that a benign file is flagged as CLEAR."""
    sample = "README.md"
    result = run_suscheck(["scan", sample])
    
    assert result.returncode == 0
    assert "CLEAR" in result.stdout
    assert "0/100" in result.stdout or "5/100" in result.stdout

def test_report_generation():
    """Verify that HTML reports are generated correctly."""
    sample = "README.md"
    output_file = "test_report.html"
    if os.path.exists(output_file):
        os.remove(output_file)
        
    result = run_suscheck(["scan", sample, "--format", "html", "--output", output_file])
    
    assert result.returncode == 0
    assert os.path.exists(output_file)
    with open(output_file, "r") as f:
        html = f.read()
        assert "SusCheck Security Audit Report" in html
        assert "CLEAR" in html
        
    os.remove(output_file)

def test_trust_pypi():
    """Verify that the trust command handles PyPI targets."""
    # Use a package we know exists
    result = run_suscheck(["trust", "requests"])
    
    assert result.returncode == 0
    assert "requests" in result.stdout
    assert "Supply Chain Trust" in result.stdout

if __name__ == "__main__":
    print("Running manual regression suite...")
    test_scan_malicious_python()
    print("✅ test_scan_malicious_python passed")
    test_scan_benign_file()
    print("✅ test_scan_benign_file passed")
    test_report_generation()
    print("✅ test_report_generation passed")
    test_trust_pypi()
    print("✅ test_trust_pypi passed")
    print("\n[bold green]ALL REGRESSION TESTS PASSED.[/bold green]")
