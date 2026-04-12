"""Installer wrapper for suscheck.

Handles package installation safely after scanning.
"""

import subprocess
import sys
from typing import Optional

def install_package(ecosystem: str, package: str, force: bool = False) -> int:
    """Execute the actual install command."""
    installer = "pip" if ecosystem.lower() in ("pip", "pypi") else "npm"
    
    if installer == "pip":
        cmd = [sys.executable, "-m", "pip", "install", package]
    else:  # npm
        cmd = ["npm", "install", package]

    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except FileNotFoundError:
        return 127
