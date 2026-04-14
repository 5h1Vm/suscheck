"""Installer wrapper for suscheck.

Handles package installation safely after scanning.
"""

import logging
import subprocess
import sys

from suscheck.core.validators import validate_tool_available, ValidationError

logger = logging.getLogger(__name__)


def install_package(ecosystem: str, package: str, force: bool = False) -> int:
    """Execute the actual install command.
    
    Args:
        ecosystem: Package manager ecosystem (pypi, npm)
        package: Package name to install
        force: Whether to force install
        
    Returns:
        Exit code (0 = success, non-zero = failure)
    """
    installer = "pip" if ecosystem.lower() in ("pip", "pypi") else "npm"
    
    # ✅ FIX P0.4: Pre-validate tool exists before attempting to install
    try:
        if installer == "pip":
            # pip is special: we use Python's -m flag, so validate python first
            validate_tool_available("python", context="Running pip install")
            cmd = [sys.executable, "-m", "pip", "install", package]
            logger.info(f"Installing package via pip: {package}")
        else:  # npm
            validate_tool_available("npm", context="Running npm install")
            cmd = ["npm", "install", package]
            logger.info(f"Installing package via npm: {package}")
    except ValidationError as e:
        logger.error(f"Installation failed: {e}")
        return 127  # Tool not found
    
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except FileNotFoundError as e:
        logger.error(f"Failed to execute installer: {e}")
        return 127
    except Exception as e:
        logger.error(f"Installation failed with unexpected error: {e}", exc_info=True)
        return 1

